use lee_core::{
    Commitment, CommitmentSetDigest, DUMMY_COMMITMENT_HASH, EncryptedAccountData, EncryptionScheme,
    EphemeralPublicKey, InputAccountIdentity, MembershipProof, Nullifier, NullifierPublicKey,
    NullifierSecretKey, PrivacyPreservingCircuitOutput, PrivateAccountKind, SharedSecretKey,
    account::{Account, AccountId, Nonce},
    compute_digest_for_path,
};

use crate::execution_state::ExecutionState;

fn init_nullifier_and_nonce(account_id: &AccountId) -> ((Nullifier, CommitmentSetDigest), Nonce) {
    let nullifier = (
        Nullifier::for_account_initialization(account_id),
        DUMMY_COMMITMENT_HASH,
    );
    let nonce = Nonce::private_account_nonce_init(account_id);
    (nullifier, nonce)
}

fn derive_and_verify_account_id(
    npk: &NullifierPublicKey,
    identifier: u128,
    pre_state_account_id: AccountId,
) -> AccountId {
    let account_id = AccountId::for_regular_private_account(npk, identifier);
    assert_eq!(account_id, pre_state_account_id, "AccountId mismatch");
    account_id
}

#[expect(
    clippy::too_many_arguments,
    reason = "extracted match arm with many destructured fields"
)]
fn handle_private_authorized_init(
    output: &mut PrivacyPreservingCircuitOutput,
    output_index: &mut u32,
    pre_state: &lee_core::account::AccountWithMetadata,
    post_state: Account,
    epk: &EphemeralPublicKey,
    view_tag: u8,
    ssk: &SharedSecretKey,
    nsk: &NullifierSecretKey,
    identifier: u128,
) {
    let npk = NullifierPublicKey::from(nsk);
    let account_id = derive_and_verify_account_id(&npk, identifier, pre_state.account_id);

    assert!(
        pre_state.is_authorized,
        "Pre-state not authorized for authenticated private account"
    );
    assert_eq!(
        pre_state.account,
        Account::default(),
        "Found new private account with non default values"
    );

    let (new_nullifier, new_nonce) = init_nullifier_and_nonce(&account_id);

    emit_private_output(
        output,
        output_index,
        post_state,
        &account_id,
        &PrivateAccountKind::Regular(identifier),
        ssk,
        epk,
        view_tag,
        new_nullifier,
        new_nonce,
    );
}

#[expect(
    clippy::too_many_arguments,
    reason = "extracted match arm with many destructured fields"
)]
fn handle_private_authorized_update(
    output: &mut PrivacyPreservingCircuitOutput,
    output_index: &mut u32,
    pre_state: &lee_core::account::AccountWithMetadata,
    post_state: Account,
    epk: &EphemeralPublicKey,
    view_tag: u8,
    ssk: &SharedSecretKey,
    nsk: &NullifierSecretKey,
    membership_proof: &MembershipProof,
    identifier: u128,
) {
    let npk = NullifierPublicKey::from(nsk);
    let account_id = derive_and_verify_account_id(&npk, identifier, pre_state.account_id);

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
        output,
        output_index,
        post_state,
        &account_id,
        &PrivateAccountKind::Regular(identifier),
        ssk,
        epk,
        view_tag,
        new_nullifier,
        new_nonce,
    );
}

#[expect(
    clippy::too_many_arguments,
    reason = "extracted match arm with many destructured fields"
)]
fn handle_private_unauthorized(
    output: &mut PrivacyPreservingCircuitOutput,
    output_index: &mut u32,
    pre_state: &lee_core::account::AccountWithMetadata,
    post_state: Account,
    epk: &EphemeralPublicKey,
    view_tag: u8,
    npk: &NullifierPublicKey,
    ssk: &SharedSecretKey,
    identifier: u128,
) {
    let account_id = derive_and_verify_account_id(npk, identifier, pre_state.account_id);

    assert_eq!(
        pre_state.account,
        Account::default(),
        "Found new private account with non default values",
    );
    assert!(
        !pre_state.is_authorized,
        "Found new private account marked as authorized."
    );

    let (new_nullifier, new_nonce) = init_nullifier_and_nonce(&account_id);

    emit_private_output(
        output,
        output_index,
        post_state,
        &account_id,
        &PrivateAccountKind::Regular(identifier),
        ssk,
        epk,
        view_tag,
        new_nullifier,
        new_nonce,
    );
}

#[expect(
    clippy::too_many_arguments,
    reason = "PDA init has many distinct fields from the variant"
)]
fn handle_private_pda_init(
    output: &mut PrivacyPreservingCircuitOutput,
    output_index: &mut u32,
    pre_state: &lee_core::account::AccountWithMetadata,
    post_state: Account,
    epk: &EphemeralPublicKey,
    view_tag: u8,
    ssk: &SharedSecretKey,
    identifier: u128,
    pos: usize,
    pda_seed_by_position: &std::collections::HashMap<
        usize,
        (lee_core::program::ProgramId, lee_core::program::PdaSeed),
    >,
) {
    // The npk-to-account_id binding is established upstream in
    // `validate_and_sync_states` via `Claim::Pda(seed)` or a caller `pda_seeds`
    // match. Here we only enforce the init pre-conditions.
    assert!(
        !pre_state.is_authorized,
        "PrivatePdaInit requires unauthorized pre_state"
    );
    assert_eq!(
        pre_state.account,
        Account::default(),
        "New private PDA must be default"
    );

    let (new_nullifier, new_nonce) = init_nullifier_and_nonce(&pre_state.account_id);

    let account_id = pre_state.account_id;
    let (authority_program_id, seed) = pda_seed_by_position
        .get(&pos)
        .expect("PrivatePdaInit position must be in pda_seed_by_position");
    emit_private_output(
        output,
        output_index,
        post_state,
        &account_id,
        &PrivateAccountKind::Pda {
            program_id: *authority_program_id,
            seed: *seed,
            identifier,
        },
        ssk,
        epk,
        view_tag,
        new_nullifier,
        new_nonce,
    );
}

#[expect(
    clippy::too_many_arguments,
    reason = "PDA update has many distinct fields from the variant"
)]
fn handle_private_pda_update(
    output: &mut PrivacyPreservingCircuitOutput,
    output_index: &mut u32,
    pre_state: &lee_core::account::AccountWithMetadata,
    post_state: Account,
    epk: &EphemeralPublicKey,
    view_tag: u8,
    ssk: &SharedSecretKey,
    nsk: &NullifierSecretKey,
    membership_proof: &MembershipProof,
    identifier: u128,
    external_seed: Option<&(lee_core::program::PdaSeed, lee_core::program::ProgramId)>,
    pos: usize,
    pda_seed_by_position: &std::collections::HashMap<
        usize,
        (lee_core::program::ProgramId, lee_core::program::PdaSeed),
    >,
) {
    // With an external seed the binding comes from the circuit input and the
    // pre_state is intentionally unauthorized; without one the binding comes from
    // a Claim or caller pda_seeds, so the pre_state must already be authorized.
    assert!(
        pre_state.is_authorized ^ external_seed.is_some(),
        "PrivatePdaUpdate requires authorized pre_state or external seed"
    );

    let new_nullifier = compute_update_nullifier_and_set_digest(
        membership_proof,
        &pre_state.account,
        &pre_state.account_id,
        nsk,
    );
    let new_nonce = pre_state.account.nonce.private_account_nonce_increment(nsk);

    let account_id = pre_state.account_id;
    let (authority_program_id, seed) = pda_seed_by_position
        .get(&pos)
        .expect("PrivatePdaUpdate position must be in pda_seed_by_position");
    emit_private_output(
        output,
        output_index,
        post_state,
        &account_id,
        &PrivateAccountKind::Pda {
            program_id: *authority_program_id,
            seed: *seed,
            identifier,
        },
        ssk,
        epk,
        view_tag,
        new_nullifier,
        new_nonce,
    );
}

pub fn compute_circuit_output(
    execution_state: ExecutionState,
    account_identities: &[InputAccountIdentity],
) -> PrivacyPreservingCircuitOutput {
    let (block_validity_window, timestamp_validity_window, pda_seed_by_position, states_iter) =
        execution_state.into_parts();
    let mut output = PrivacyPreservingCircuitOutput {
        public_pre_states: Vec::new(),
        public_post_states: Vec::new(),
        encrypted_private_post_states: Vec::new(),
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
                epk,
                view_tag,
                ssk,
                nsk,
                identifier,
            } => handle_private_authorized_init(
                &mut output,
                &mut output_index,
                &pre_state,
                post_state,
                epk,
                *view_tag,
                ssk,
                nsk,
                *identifier,
            ),
            InputAccountIdentity::PrivateAuthorizedUpdate {
                epk,
                view_tag,
                ssk,
                nsk,
                membership_proof,
                identifier,
            } => handle_private_authorized_update(
                &mut output,
                &mut output_index,
                &pre_state,
                post_state,
                epk,
                *view_tag,
                ssk,
                nsk,
                membership_proof,
                *identifier,
            ),
            InputAccountIdentity::PrivateUnauthorized {
                epk,
                view_tag,
                npk,
                ssk,
                identifier,
            } => handle_private_unauthorized(
                &mut output,
                &mut output_index,
                &pre_state,
                post_state,
                epk,
                *view_tag,
                npk,
                ssk,
                *identifier,
            ),
            InputAccountIdentity::PrivatePdaInit {
                epk,
                view_tag,
                npk: _,
                ssk,
                identifier,
                seed: _,
            } => handle_private_pda_init(
                &mut output,
                &mut output_index,
                &pre_state,
                post_state,
                epk,
                *view_tag,
                ssk,
                *identifier,
                pos,
                &pda_seed_by_position,
            ),
            InputAccountIdentity::PrivatePdaUpdate {
                epk,
                view_tag,
                ssk,
                nsk,
                membership_proof,
                identifier,
                seed: external_seed,
            } => handle_private_pda_update(
                &mut output,
                &mut output_index,
                &pre_state,
                post_state,
                epk,
                *view_tag,
                ssk,
                nsk,
                membership_proof,
                *identifier,
                external_seed.as_ref(),
                pos,
                &pda_seed_by_position,
            ),
        }
    }

    output
}

#[expect(
    clippy::too_many_arguments,
    reason = "Inputs are distinct concerns from the variant arms; bundling would be artificial"
)]
fn emit_private_output(
    output: &mut PrivacyPreservingCircuitOutput,
    output_index: &mut u32,
    post_state: Account,
    account_id: &AccountId,
    kind: &PrivateAccountKind,
    shared_secret: &SharedSecretKey,
    epk: &EphemeralPublicKey,
    view_tag: u8,
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
    output
        .encrypted_private_post_states
        .push(EncryptedAccountData {
            ciphertext: encrypted_account,
            epk: epk.clone(),
            view_tag,
        });
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
