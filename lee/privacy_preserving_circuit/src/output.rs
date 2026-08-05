use lee_core::{
    Commitment, CommitmentSetDigest, DummyInput, EncryptedAccountData, EncryptionScheme,
    EphemeralSecretKey, InputAccountIdentity, MembershipProof, Nullifier, NullifierPublicKey,
    NullifierSecretKey, PrivacyPreservingCircuitOutput, PrivateAccountKind, SharedSecretKey,
    account::{Account, AccountId, Nonce},
    compute_digest_for_path,
    encryption::{ViewTag, ViewingPublicKey},
};

use crate::execution_state::ExecutionState;

pub fn compute_circuit_output(
    execution_state: ExecutionState,
    account_identities: &[InputAccountIdentity],
    dummy_inputs: Vec<DummyInput>,
) -> PrivacyPreservingCircuitOutput {
    let (
        block_validity_window,
        timestamp_validity_window,
        pda_seed_by_position,
        signer_account_ids,
        public_diffs,
        states_iter,
    ) = execution_state.into_parts();
    let mut output = PrivacyPreservingCircuitOutput {
        public_pre_states: Vec::new(),
        public_diffs,
        encrypted_private_post_states: Vec::new(),
        new_commitments: Vec::new(),
        new_nullifiers: Vec::new(),
        block_validity_window,
        timestamp_validity_window,
        signer_account_ids,
    };

    assert_eq!(
        account_identities.len(),
        states_iter.len(),
        "Invalid account_identities length"
    );

    for (pos, (account_identity, (pre_state, post_state))) in
        account_identities.iter().zip(states_iter).enumerate()
    {
        match account_identity {
            InputAccountIdentity::Public => {
                output.public_pre_states.push(pre_state);
            }
            InputAccountIdentity::PrivateAuthorizedInit {
                vpk,
                random_seed,
                nsk,
                identifier,
                commitment_root,
            } => {
                let npk = NullifierPublicKey::from(nsk);
                let account_id = AccountId::for_regular_private_account(&npk, vpk, *identifier);

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
                    *commitment_root,
                );
                let new_nonce = Nonce::private_account_nonce_init(&account_id);
                let view_tag = EncryptedAccountData::compute_view_tag(&npk, vpk);

                emit_private_output(
                    &mut output,
                    post_state,
                    &account_id,
                    &PrivateAccountKind::Regular(*identifier),
                    view_tag,
                    vpk,
                    random_seed,
                    new_nullifier,
                    new_nonce,
                );
            }
            InputAccountIdentity::PrivateAuthorizedUpdate {
                vpk,
                random_seed,
                view_tag,
                nsk,
                membership_proof,
                identifier,
            } => {
                let npk = NullifierPublicKey::from(nsk);
                let account_id = AccountId::for_regular_private_account(&npk, vpk, *identifier);

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
                    post_state,
                    &account_id,
                    &PrivateAccountKind::Regular(*identifier),
                    *view_tag,
                    vpk,
                    random_seed,
                    new_nullifier,
                    new_nonce,
                );
            }
            InputAccountIdentity::PrivateForeignInit {
                vpk,
                random_seed,
                npk,
                identifier,
                commitment_root,
            } => {
                let account_id = AccountId::for_regular_private_account(npk, vpk, *identifier);

                assert_eq!(account_id, pre_state.account_id, "AccountId mismatch");
                assert_eq!(
                    pre_state.account,
                    Account::default(),
                    "Found new private account with non default values",
                );
                assert!(
                    pre_state.is_authorized,
                    "Found new private account marked as unauthorized."
                );

                let new_nullifier = (
                    Nullifier::for_account_initialization(&account_id),
                    *commitment_root,
                );
                let new_nonce = Nonce::private_account_nonce_init(&account_id);
                let view_tag = EncryptedAccountData::compute_view_tag(npk, vpk);

                emit_private_output(
                    &mut output,
                    post_state,
                    &account_id,
                    &PrivateAccountKind::Regular(*identifier),
                    view_tag,
                    vpk,
                    random_seed,
                    new_nullifier,
                    new_nonce,
                );
            }
            InputAccountIdentity::PrivatePdaInit {
                vpk,
                random_seed,
                npk,
                identifier,
                commitment_root,
                seed: _,
            } => {
                // The npk-to-account_id binding is established upstream in
                // `validate_and_sync_states` via `Claim::Pda(seed)` or a caller `pda_seeds`
                // match. Here we only enforce the init pre-conditions. The supplied npk on
                // the variant has been recorded into `private_pda_by_position` and used
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
                    *commitment_root,
                );
                let new_nonce = Nonce::private_account_nonce_init(&pre_state.account_id);

                let account_id = pre_state.account_id;
                let (authority_program_id, seed) = pda_seed_by_position
                    .get(&pos)
                    .expect("PrivatePdaInit position must be in pda_seed_by_position");
                let view_tag = EncryptedAccountData::compute_view_tag(npk, vpk);
                emit_private_output(
                    &mut output,
                    post_state,
                    &account_id,
                    &PrivateAccountKind::Pda {
                        program_id: *authority_program_id,
                        seed: *seed,
                        identifier: *identifier,
                    },
                    view_tag,
                    vpk,
                    random_seed,
                    new_nullifier,
                    new_nonce,
                );
            }
            InputAccountIdentity::PrivatePdaUpdate {
                vpk,
                random_seed,
                view_tag,
                nsk,
                membership_proof,
                identifier,
                seed: external_seed,
            } => {
                // With an external seed the binding comes from the circuit input and the
                // pre_state is intentionally unauthorized; without one the binding comes from
                // a Claim or caller pda_seeds, so the pre_state must already be authorized.
                // When `external_seed` is `Some`, execution_state already asserted
                // `!pre_state.is_authorized`.
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
                    &mut output,
                    post_state,
                    &account_id,
                    &PrivateAccountKind::Pda {
                        program_id: *authority_program_id,
                        seed: *seed,
                        identifier: *identifier,
                    },
                    *view_tag,
                    vpk,
                    random_seed,
                    new_nullifier,
                    new_nonce,
                );
            }
        }
    }

    for dummy in dummy_inputs {
        emit_dummy_output(&mut output, dummy);
    }

    obfuscate_output_ordering(&mut output);

    output
}

fn obfuscate_output_ordering(output: &mut PrivacyPreservingCircuitOutput) {
    output
        .new_commitments
        .sort_unstable_by_key(Commitment::to_byte_array);

    let mut notes: Vec<_> = core::mem::take(&mut output.new_nullifiers)
        .into_iter()
        .zip(core::mem::take(&mut output.encrypted_private_post_states))
        .collect();
    notes.sort_unstable_by_key(|((nullifier, _), _)| nullifier.to_byte_array());
    (output.new_nullifiers, output.encrypted_private_post_states) = notes.into_iter().unzip();
}

fn emit_dummy_output(output: &mut PrivacyPreservingCircuitOutput, dummy: DummyInput) {
    // Note: the nullifiers and commitments are generated from seeds.
    // The prover is responsible for their randomness.
    let nullifier = Nullifier::for_dummy(&dummy.nullifier_seed);
    let commitment = Commitment::for_dummy(&nullifier, &dummy.commitment_seed);
    output
        .new_nullifiers
        .push((nullifier, dummy.commitment_root));
    output.new_commitments.push(commitment);
    // Note: the encrypted post states are pushed as fed into the circuit.
    // That means that the prover is responsible for managing the randomness
    // so as to not reveal the padding.
    //
    // In particular, it is recommended to generate the ML KEM ciphertext
    // explicitly as these are not uniformly random.
    output.encrypted_private_post_states.push(dummy.note);
}

#[expect(
    clippy::too_many_arguments,
    reason = "Inputs are distinct concerns from the variant arms; bundling would be artificial"
)]
fn emit_private_output(
    output: &mut PrivacyPreservingCircuitOutput,
    post_state: Account,
    account_id: &AccountId,
    kind: &PrivateAccountKind,
    view_tag: ViewTag,
    vpk: &ViewingPublicKey,
    random_seed: &[u8; 32],
    new_nullifier: (Nullifier, CommitmentSetDigest),
    new_nonce: Nonce,
) {
    let mut post_with_updated_nonce = post_state;
    post_with_updated_nonce.nonce = new_nonce;

    let commitment_post = Commitment::new(account_id, &post_with_updated_nonce);

    let esk = EphemeralSecretKey::new(account_id, random_seed, &new_nonce);
    let (shared_secret, epk) = SharedSecretKey::encapsulate_deterministic(vpk, &esk);

    let encrypted_account = EncryptionScheme::encrypt(
        &post_with_updated_nonce,
        kind,
        &shared_secret,
        &new_nullifier.0,
    );

    output.new_nullifiers.push(new_nullifier);
    output.new_commitments.push(commitment_post);
    output
        .encrypted_private_post_states
        .push(EncryptedAccountData {
            ciphertext: encrypted_account,
            epk,
            view_tag,
        });
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use lee_core::{DUMMY_COMMITMENT_HASH, EphemeralPublicKey};

    use super::*;

    fn note(tag: u8) -> (Nullifier, Commitment, EncryptedAccountData) {
        let nullifier = Nullifier::for_dummy(&[tag; 32]);
        let commitment = Commitment::for_dummy(&nullifier, &[tag; 32]);
        let ciphertext = EncryptionScheme::encrypt(
            &Account::default(),
            &PrivateAccountKind::Regular(0),
            &SharedSecretKey([0; 32]),
            &nullifier,
        );
        let encrypted = EncryptedAccountData {
            ciphertext,
            epk: EphemeralPublicKey(vec![tag]),
            view_tag: 0,
        };
        (nullifier, commitment, encrypted)
    }

    #[test]
    fn obfuscate_byte_sorts_commitments_and_nullifiers() {
        let mut output = PrivacyPreservingCircuitOutput::default();
        for tag in 0..3 {
            let (nullifier, commitment, encrypted) = note(tag);
            output
                .new_nullifiers
                .push((nullifier, DUMMY_COMMITMENT_HASH));
            output.new_commitments.push(commitment);
            output.encrypted_private_post_states.push(encrypted);
        }

        obfuscate_output_ordering(&mut output);

        assert!(
            output
                .new_commitments
                .is_sorted_by_key(Commitment::to_byte_array)
        );
        assert!(
            output
                .new_nullifiers
                .is_sorted_by_key(|(nullifier, _)| nullifier.to_byte_array())
        );
    }

    #[test]
    fn obfuscate_keeps_each_nullifier_with_its_ciphertext() {
        let mut output = PrivacyPreservingCircuitOutput::default();
        for tag in 0..3 {
            let (nullifier, _, encrypted) = note(tag);
            output
                .new_nullifiers
                .push((nullifier, DUMMY_COMMITMENT_HASH));
            output.encrypted_private_post_states.push(encrypted);
        }
        let paired: HashMap<[u8; 32], EphemeralPublicKey> = output
            .new_nullifiers
            .iter()
            .zip(&output.encrypted_private_post_states)
            .map(|((nullifier, _), note)| (nullifier.to_byte_array(), note.epk.clone()))
            .collect();

        obfuscate_output_ordering(&mut output);

        for ((nullifier, _), note) in output
            .new_nullifiers
            .iter()
            .zip(&output.encrypted_private_post_states)
        {
            assert_eq!(paired[&nullifier.to_byte_array()], note.epk);
        }
    }
}
