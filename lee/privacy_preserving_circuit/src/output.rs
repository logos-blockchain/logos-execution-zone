use lee_core::{
    Commitment, CommitmentSetDigest, DummyInput, EncryptedAccountData, EncryptionScheme,
    EphemeralSecretKey, MembershipProof, Nullifier, NullifierSecretKey, NullifierWitness,
    PrivacyPreservingCircuitOutput, PrivateAccountKind, PrivateAction, PrivateWitness,
    ProgramImageClaim, SharedSecretKey, WitnessKind,
    account::{Account, AccountId, Nonce},
    compute_digest_for_path,
    encryption::{ViewTag, ViewingPublicKey},
};

use crate::execution_state::ExecutionState;

pub fn compute_circuit_output(
    execution_state: ExecutionState,
    private_witnesses: &[PrivateWitness],
    dummy_inputs: Vec<DummyInput>,
    program_image_claims: Vec<ProgramImageClaim>,
) -> PrivacyPreservingCircuitOutput {
    let (block_validity_window, timestamp_validity_window, public_actions, mut private_final) =
        execution_state.into_parts();
    let mut output = PrivacyPreservingCircuitOutput {
        public_actions,
        private_actions: Vec::new(),
        block_validity_window,
        timestamp_validity_window,
        program_image_claims,
    };

    // Emit one action per private account, covering all its shards.
    for witness in private_witnesses {
        let PrivateWitness {
            account,
            vpk,
            random_seed,
            identifier,
            kind,
            nullifier,
        } = witness;
        let account_id = witness.account_id();
        let post_data = private_final.remove(&account_id).unwrap_or_else(|| {
            panic!("Every witness's account must be touched by the execution: {account_id}")
        });

        let (new_nullifier, new_nonce, view_tag) = match nullifier {
            NullifierWitness::Init {
                npk,
                commitment_root,
            } => {
                assert_eq!(
                    *account,
                    Account::default(),
                    "Private account init requires a default pre-state"
                );

                (
                    (
                        Nullifier::for_account_initialization(&account_id),
                        *commitment_root,
                    ),
                    Nonce::private_account_nonce_init(&account_id),
                    EncryptedAccountData::compute_view_tag(npk, vpk),
                )
            }
            NullifierWitness::Update {
                view_tag,
                nsk,
                membership_proof,
            } => (
                compute_update_nullifier_and_set_digest(
                    membership_proof,
                    account,
                    &account_id,
                    nsk,
                ),
                account.nonce.private_account_nonce_increment(nsk),
                *view_tag,
            ),
        };

        let account_kind = match kind {
            WitnessKind::Regular { .. } => PrivateAccountKind::Regular(*identifier),
            WitnessKind::Pda {
                binding: (program, seed),
            } => PrivateAccountKind::Pda {
                account_id: *program,
                seed: *seed,
                identifier: *identifier,
            },
        };

        emit_private_output(
            &mut output,
            &Account {
                nonce: new_nonce,
                data: post_data,
            },
            &account_id,
            &account_kind,
            view_tag,
            vpk,
            random_seed,
            new_nullifier,
        );
    }

    for dummy in dummy_inputs {
        emit_dummy_output(&mut output, dummy);
    }

    obfuscate_output_ordering(&mut output);

    output
}

fn obfuscate_output_ordering(output: &mut PrivacyPreservingCircuitOutput) {
    let mut commitments: Vec<_> = output
        .private_actions
        .iter()
        .map(|action| action.commitment)
        .collect();
    commitments.sort_unstable_by_key(Commitment::to_byte_array);

    output
        .private_actions
        .sort_unstable_by_key(|action| action.nullifier.to_byte_array());

    for (action, commitment) in output.private_actions.iter_mut().zip(commitments) {
        action.commitment = commitment;
    }
}

fn emit_dummy_output(output: &mut PrivacyPreservingCircuitOutput, dummy: DummyInput) {
    // Note: the nullifiers and commitments are generated from seeds.
    // The prover is responsible for their randomness.
    let nullifier = Nullifier::for_dummy(&dummy.nullifier_seed);
    let commitment = Commitment::for_dummy(&nullifier, &dummy.commitment_seed);
    // Note: the encrypted post states are pushed as fed into the circuit.
    // That means that the prover is responsible for managing the randomness
    // so as to not reveal the padding.
    //
    // In particular, it is recommended to generate the ML KEM ciphertext
    // explicitly as these are not uniformly random.
    output.private_actions.push(PrivateAction {
        nullifier,
        root: dummy.commitment_root,
        commitment,
        encrypted_post_state: dummy.note,
    });
}

#[expect(
    clippy::too_many_arguments,
    reason = "Inputs are distinct concerns from the variant arms; bundling would be artificial"
)]
fn emit_private_output(
    output: &mut PrivacyPreservingCircuitOutput,
    post_state: &Account,
    account_id: &AccountId,
    kind: &PrivateAccountKind,
    view_tag: ViewTag,
    vpk: &ViewingPublicKey,
    random_seed: &[u8; 32],
    new_nullifier: (Nullifier, CommitmentSetDigest),
) {
    let commitment_post = Commitment::new(account_id, post_state);

    let esk = EphemeralSecretKey::new(account_id, random_seed, &post_state.nonce);
    let (shared_secret, epk) = SharedSecretKey::encapsulate_deterministic(vpk, &esk);

    let encrypted_account =
        EncryptionScheme::encrypt(post_state, kind, &shared_secret, &new_nullifier.0);

    output.private_actions.push(PrivateAction {
        nullifier: new_nullifier.0,
        root: new_nullifier.1,
        commitment: commitment_post,
        encrypted_post_state: EncryptedAccountData {
            ciphertext: encrypted_account,
            epk,
            view_tag,
        },
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

    fn note(tag: u8) -> PrivateAction {
        let nullifier = Nullifier::for_dummy(&[tag; 32]);
        let commitment = Commitment::for_dummy(&nullifier, &[tag; 32]);
        let ciphertext = EncryptionScheme::encrypt(
            &Account::default(),
            &PrivateAccountKind::Regular(0),
            &SharedSecretKey([0; 32]),
            &nullifier,
        );
        PrivateAction {
            nullifier,
            root: DUMMY_COMMITMENT_HASH,
            commitment,
            encrypted_post_state: EncryptedAccountData {
                ciphertext,
                epk: EphemeralPublicKey(vec![tag]),
                view_tag: 0,
            },
        }
    }

    #[test]
    fn obfuscate_byte_sorts_commitments_and_nullifiers() {
        let mut output = PrivacyPreservingCircuitOutput::default();
        for tag in 0..3 {
            output.private_actions.push(note(tag));
        }

        obfuscate_output_ordering(&mut output);

        assert!(
            output
                .private_actions
                .is_sorted_by_key(|action| action.nullifier.to_byte_array())
        );
        assert!(
            output
                .private_actions
                .is_sorted_by_key(|action| action.commitment.to_byte_array())
        );
    }

    #[test]
    fn obfuscate_keeps_each_nullifier_with_its_ciphertext() {
        let mut output = PrivacyPreservingCircuitOutput::default();
        for tag in 0..3 {
            output.private_actions.push(note(tag));
        }
        let paired: HashMap<[u8; 32], EphemeralPublicKey> = output
            .private_actions
            .iter()
            .map(|action| {
                (
                    action.nullifier.to_byte_array(),
                    action.encrypted_post_state.epk.clone(),
                )
            })
            .collect();

        obfuscate_output_ordering(&mut output);

        for action in &output.private_actions {
            assert_eq!(
                paired[&action.nullifier.to_byte_array()],
                action.encrypted_post_state.epk
            );
        }
    }
}
