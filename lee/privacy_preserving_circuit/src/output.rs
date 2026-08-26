use lee_core::{
    Commitment, CommitmentSetDigest, DummyInput, EncryptedAccountData, EncryptionScheme,
    EphemeralSecretKey, InputAccountIdentity, MembershipProof, Nullifier, NullifierPublicKey,
    NullifierSecretKey, NullifierWitness, PrivacyPreservingCircuitOutput, PrivateAccountKind,
    PrivateAction, PrivateWitness, PublicAction, SharedSecretKey, WitnessKind,
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
    let (block_validity_window, timestamp_validity_window, states_iter) =
        execution_state.into_parts();
    let mut output = PrivacyPreservingCircuitOutput {
        public_actions: Vec::new(),
        private_actions: Vec::new(),
        block_validity_window,
        timestamp_validity_window,
    };

    assert_eq!(
        account_identities.len(),
        states_iter.len(),
        "Invalid account_identities length"
    );

    // A commitment covers a whole account, so an account gets exactly one nullifier-commitment
    // pair however many of its namespaces this transaction touches. Positions are checked one
    // by one; their writes are then coalesced per account before emission.
    let mut private_accounts: Vec<(AccountId, &PrivateWitness, Account)> = Vec::new();

    for (account_identity, (pre_state, post_state)) in account_identities.iter().zip(states_iter) {
        match account_identity {
            InputAccountIdentity::Public => {
                output.public_actions.push(PublicAction {
                    pre: pre_state,
                    post: post_state,
                });
            }
            InputAccountIdentity::Private(witness) => {
                let PrivateWitness {
                    account,
                    vpk,
                    identifier,
                    kind,
                    nullifier,
                    ..
                } = witness;

                let account_id = match kind {
                    WitnessKind::Regular { .. } => {
                        let derived = AccountId::for_regular_private_account(
                            &nullifier.npk(),
                            vpk,
                            *identifier,
                        );
                        assert_eq!(derived, pre_state.account_id, "AccountId mismatch");
                        derived
                    }
                    // The npk-to-account_id binding is proven upstream in
                    // `validate_and_sync_states`, at the account's first sight, against the
                    // witness. Here we only enforce the lifecycle pre-conditions and use
                    // `pre_state.account_id` directly for nullifier and commitment derivation.
                    WitnessKind::Pda { .. } => pre_state.account_id,
                };

                // The witness supplies the whole account because a commitment covers all of
                // it, while the program was handed one slot. Bind the two: without this the
                // commitment could be computed over an honest account while the program spent
                // a slot the prover invented, which mints balance from nothing.
                if let Some((program, slot)) = &pre_state.slot {
                    assert_eq!(
                        *slot,
                        account.slot_or_empty(*program),
                        "Witness account does not carry the slot the program executed on"
                    );
                }

                if let WitnessKind::Regular { ask } = kind {
                    if let Some(ask) = ask {
                        let derived = NullifierSecretKey::from(ask);
                        match nullifier {
                            // Check that the authorization key is actually bound to the
                            // account Id.
                            NullifierWitness::Update { nsk, .. } => assert_eq!(
                                derived, *nsk,
                                "Authorization secret key does not derive this account's nullifier secret key"
                            ),
                            NullifierWitness::Init { npk, .. } => assert_eq!(
                                NullifierPublicKey::from(&derived),
                                *npk,
                                "Authorization secret key does not derive this account's nullifier public key"
                            ),
                        }
                    }
                    assert_eq!(
                        pre_state.is_authorized,
                        ask.is_some(),
                        "Regular private account authorization must match the supplied credential"
                    );
                }

                let write = |post_account: &mut Account| {
                    if let (Some((program, _)), Some(post_slot)) = (&pre_state.slot, post_state) {
                        post_account.set_slot(*program, post_slot);
                    }
                };

                if let Some(index) = private_accounts
                    .iter()
                    .position(|(id, ..)| *id == account_id)
                {
                    let (_, first, post_account) = &mut private_accounts[index];
                    // One account, one witness. Without this a prover could describe the
                    // same account two ways and have the commitment take the flattering
                    // one while each position's slot was bound to the other.
                    assert_eq!(
                        borsh::to_vec(*first).expect("borsh serialization is infallible"),
                        borsh::to_vec(witness).expect("borsh serialization is infallible"),
                        "Positions of one private account carry disagreeing witnesses"
                    );
                    write(post_account);
                } else {
                    let mut post_account = account.clone();
                    write(&mut post_account);
                    private_accounts.push((account_id, witness, post_account));
                }
            }
        }
    }

    for (account_id, witness, post_account) in private_accounts {
        let PrivateWitness {
            account,
            vpk,
            random_seed,
            identifier,
            kind,
            nullifier,
        } = witness;

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
                binding: (program_id, seed),
            } => PrivateAccountKind::Pda {
                program_id: *program_id,
                seed: *seed,
                identifier: *identifier,
            },
        };

        emit_private_output(
            &mut output,
            post_account,
            &account_id,
            &account_kind,
            view_tag,
            vpk,
            random_seed,
            new_nullifier,
            new_nonce,
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
