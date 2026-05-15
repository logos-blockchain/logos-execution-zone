use nssa_core::{
    Commitment, CommitmentSetDigest, DUMMY_COMMITMENT_HASH, EncryptionScheme, InputAccountIdentity,
    MembershipProof, Nullifier, NullifierPublicKey, NullifierSecretKey,
    PrivacyPreservingCircuitOutput, PrivateAccountKind, SharedSecretKey,
    account::{Account, AccountId, Nonce},
    compute_digest_for_path,
};

use crate::execution_state::ExecutionState;

pub fn compute_circuit_output(
    execution_state: ExecutionState,
    account_identities: &[InputAccountIdentity],
) -> PrivacyPreservingCircuitOutput {
    let (block_validity_window, timestamp_validity_window, pda_seed_by_position, states_iter) =
        execution_state.into_parts();
    let mut output = PrivacyPreservingCircuitOutput {
        public_pre_states: Vec::new(),
        public_post_states: Vec::new(),
        ciphertexts: Vec::new(),
        new_commitments: Vec::new(),
        new_nullifiers: Vec::new(),
        block_validity_window,
        timestamp_validity_window,
    };

    assert_eq!(
        account_identities.len(),
        states_iter.len(),
        "Invalid account_identities length"
    );

    let mut output_index = 0;
    for (pos, (account_identity, (pre_state, post_state))) in
        account_identities.iter().zip(states_iter).enumerate()
    {
        match account_identity {
            InputAccountIdentity::Public => {
                output.public_pre_states.push(pre_state);
                output.public_post_states.push(post_state);
            }
            InputAccountIdentity::PrivateAuthorizedInit {
                ssk,
                nsk,
                identifier,
            } => {
                let npk = NullifierPublicKey::from(nsk);
                let account_id = AccountId::for_regular_private_account(&npk, *identifier);

                assert_eq!(account_id, pre_state.account_id, "AccountId mismatch");
                assert!(
                    pre_state.is_authorized,
                    "Pre-state not authorized for authenticated private account"
                );
                assert_eq!(
                    pre_state.account,
                    Account::default(),
                    "Found new private account with non default values"
                );

                let new_nullifier = (
                    Nullifier::for_account_initialization(&account_id),
                    DUMMY_COMMITMENT_HASH,
                );
                let new_nonce = pre_state.account.nonce.private_account_nonce_increment(nsk);

                emit_private_output(
                    &mut output,
                    &mut output_index,
                    post_state,
                    &account_id,
                    &PrivateAccountKind::Regular(*identifier),
                    ssk,
                    new_nullifier,
                    new_nonce,
                );
            }
            InputAccountIdentity::PrivateAuthorizedUpdate {
                ssk,
                nsk,
                membership_proof,
                identifier,
            } => {
                let npk = NullifierPublicKey::from(nsk);
                let account_id = AccountId::for_regular_private_account(&npk, *identifier);

                assert_eq!(account_id, pre_state.account_id, "AccountId mismatch");
                assert!(
                    pre_state.is_authorized,
                    "Pre-state not authorized for authenticated private account"
                );

                let new_nullifier = compute_update_nullifier_and_set_digest(
                    membership_proof,
                    &pre_state.account,
                    &account_id,
                    nsk,
                );
                let new_nonce = pre_state.account.nonce.private_account_nonce_increment(nsk);

                emit_private_output(
                    &mut output,
                    &mut output_index,
                    post_state,
                    &account_id,
                    &PrivateAccountKind::Regular(*identifier),
                    ssk,
                    new_nullifier,
                    new_nonce,
                );
            }
            InputAccountIdentity::PrivateUnauthorized {
                npk,
                ssk,
                identifier,
            } => {
                let account_id = AccountId::for_regular_private_account(npk, *identifier);

                assert_eq!(account_id, pre_state.account_id, "AccountId mismatch");
                assert_eq!(
                    pre_state.account,
                    Account::default(),
                    "Found new private account with non default values",
                );
                assert!(
                    !pre_state.is_authorized,
                    "Found new private account marked as authorized."
                );

                let new_nullifier = (
                    Nullifier::for_account_initialization(&account_id),
                    DUMMY_COMMITMENT_HASH,
                );
                let new_nonce = Nonce::private_account_nonce_init(&account_id);

                emit_private_output(
                    &mut output,
                    &mut output_index,
                    post_state,
                    &account_id,
                    &PrivateAccountKind::Regular(*identifier),
                    ssk,
                    new_nullifier,
                    new_nonce,
                );
            }
            InputAccountIdentity::PrivatePdaInit {
                npk: _,
                ssk,
                identifier,
            } => {
                // The npk-to-account_id binding is established upstream in
                // `validate_and_sync_states` via `Claim::Pda(seed)` or a caller `pda_seeds`
                // match. Here we only enforce the init pre-conditions. The supplied npk on
                // the variant has been recorded into `private_pda_npk_by_position` and used
                // for the binding check; we use `pre_state.account_id` directly for nullifier
                // and commitment derivation.
                assert!(
                    !pre_state.is_authorized,
                    "PrivatePdaInit requires unauthorized pre_state"
                );
                assert_eq!(
                    pre_state.account,
                    Account::default(),
                    "New private PDA must be default"
                );

                let new_nullifier = (
                    Nullifier::for_account_initialization(&pre_state.account_id),
                    DUMMY_COMMITMENT_HASH,
                );
                let new_nonce = Nonce::private_account_nonce_init(&pre_state.account_id);

                let account_id = pre_state.account_id;
                let (pda_program_id, seed) = pda_seed_by_position
                    .get(&pos)
                    .expect("PrivatePdaInit position must be in pda_seed_by_position");
                emit_private_output(
                    &mut output,
                    &mut output_index,
                    post_state,
                    &account_id,
                    &PrivateAccountKind::Pda {
                        program_id: *pda_program_id,
                        seed: *seed,
                        identifier: *identifier,
                    },
                    ssk,
                    new_nullifier,
                    new_nonce,
                );
            }
            InputAccountIdentity::PrivatePdaUpdate {
                ssk,
                nsk,
                membership_proof,
                identifier,
            } => {
                // The npk binding is established upstream. Authorization must already be set;
                // an unauthorized PrivatePdaUpdate would mean the prover supplied an nsk for an
                // unbound PDA, which the upstream binding check would have rejected anyway,
                // but we assert here to fail fast and document the precondition.
                assert!(
                    pre_state.is_authorized,
                    "PrivatePdaUpdate requires authorized pre_state"
                );

                let new_nullifier = compute_update_nullifier_and_set_digest(
                    membership_proof,
                    &pre_state.account,
                    &pre_state.account_id,
                    nsk,
                );
                let new_nonce = pre_state.account.nonce.private_account_nonce_increment(nsk);

                let account_id = pre_state.account_id;
                let (pda_program_id, seed) = pda_seed_by_position
                    .get(&pos)
                    .expect("PrivatePdaUpdate position must be in pda_seed_by_position");
                emit_private_output(
                    &mut output,
                    &mut output_index,
                    post_state,
                    &account_id,
                    &PrivateAccountKind::Pda {
                        program_id: *pda_program_id,
                        seed: *seed,
                        identifier: *identifier,
                    },
                    ssk,
                    new_nullifier,
                    new_nonce,
                );
            }
        }
    }

    output
}

#[expect(
    clippy::too_many_arguments,
    reason = "All seven inputs are distinct concerns from the variant arms; bundling would be artificial"
)]
fn emit_private_output(
    output: &mut PrivacyPreservingCircuitOutput,
    output_index: &mut u32,
    post_state: Account,
    account_id: &AccountId,
    kind: &PrivateAccountKind,
    shared_secret: &SharedSecretKey,
    new_nullifier: (Nullifier, CommitmentSetDigest),
    new_nonce: Nonce,
) {
    output.new_nullifiers.push(new_nullifier);

    let mut post_with_updated_nonce = post_state;
    post_with_updated_nonce.nonce = new_nonce;

    let commitment_post = Commitment::new(account_id, &post_with_updated_nonce);
    let encrypted_account = EncryptionScheme::encrypt(
        &post_with_updated_nonce,
        kind,
        shared_secret,
        &commitment_post,
        *output_index,
    );

    output.new_commitments.push(commitment_post);
    output.ciphertexts.push(encrypted_account);
    *output_index = output_index
        .checked_add(1)
        .unwrap_or_else(|| panic!("Too many private accounts, output index overflow"));
}

fn compute_update_nullifier_and_set_digest(
    membership_proof: &MembershipProof,
    pre_account: &Account,
    account_id: &AccountId,
    nsk: &NullifierSecretKey,
) -> (Nullifier, CommitmentSetDigest) {
    let commitment_pre = Commitment::new(account_id, pre_account);
    let set_digest = compute_digest_for_path(&commitment_pre, membership_proof);
    let nullifier = Nullifier::for_account_update(&commitment_pre, nsk);
    (nullifier, set_digest)
}
