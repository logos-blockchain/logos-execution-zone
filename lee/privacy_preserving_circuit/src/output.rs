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

    use lee_core::{
        AuthorizationSecretKey, DUMMY_COMMITMENT_HASH, EphemeralPublicKey, NullifierPublicKey,
        PublicAction,
        account::{AccountData, Data},
    };

    use super::*;

    const SHARD_A: AccountId = AccountId::new([10; 32]);
    const SHARD_B: AccountId = AccountId::new([11; 32]);
    const SHARD_C: AccountId = AccountId::new([12; 32]);

    struct Owner {
        ask: AuthorizationSecretKey,
        seed: [u8; 32],
        vpk: ViewingPublicKey,
    }

    impl Owner {
        fn new(tag: u8) -> Self {
            Self {
                ask: AuthorizationSecretKey([tag; 32]),
                seed: [tag; 32],
                vpk: ViewingPublicKey::from_seed(&[tag; 32], &[tag; 32]),
            }
        }

        fn nsk(&self) -> NullifierSecretKey {
            NullifierSecretKey::from(&self.ask)
        }

        fn account_id(&self) -> AccountId {
            AccountId::for_regular_private_account(
                &NullifierPublicKey::from(&self.nsk()),
                &self.vpk,
                0,
            )
        }

        fn update_witness(&self, account: Account) -> PrivateWitness {
            PrivateWitness {
                account,
                vpk: self.vpk.clone(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(self.ask),
                },
                nullifier: NullifierWitness::Update {
                    view_tag: 0,
                    nsk: self.nsk(),
                    membership_proof: (0, Vec::new()),
                },
            }
        }

        fn decrypt(&self, action: &PrivateAction) -> (PrivateAccountKind, Account) {
            let shared_secret = SharedSecretKey::decapsulate(
                &action.encrypted_post_state.epk,
                &self.seed,
                &self.seed,
            )
            .expect("the emitted epk is a well-formed ML-KEM ciphertext");
            EncryptionScheme::decrypt(
                &action.encrypted_post_state.ciphertext,
                &shared_secret,
                &action.nullifier,
            )
            .expect("the note decrypts under the recipient's viewing key")
        }
    }

    fn data(bytes: &[u8]) -> Data {
        bytes.to_vec().try_into().expect("test data is small")
    }

    fn emit(
        public: Vec<(AccountId, bool, AccountData, AccountData)>,
        private: Vec<(AccountId, AccountData)>,
        witnesses: &[PrivateWitness],
    ) -> PrivacyPreservingCircuitOutput {
        compute_circuit_output(
            ExecutionState::from_post_states(public, private),
            witnesses,
            Vec::new(),
            Vec::new(),
        )
    }

    #[test]
    fn one_note_per_private_account_carries_its_touched_shards() {
        let owner = Owner::new(3);
        let account = Account {
            nonce: Nonce(7),
            ..Account::funded(100)
                .with_shard(SHARD_A, data(b"a"))
                .with_shard(SHARD_B, data(b"b"))
        };
        let rewritten = AccountData {
            balance: 60,
            ..account.data.clone()
        }
        .with_shard(SHARD_B, data(b"b-rewritten"));

        let output = emit(
            Vec::new(),
            vec![(owner.account_id(), rewritten.clone())],
            &[owner.update_witness(account.clone())],
        );

        assert_eq!(output.private_actions.len(), 1, "one account, one note");
        let expected = Account {
            nonce: account.nonce.private_account_nonce_increment(&owner.nsk()),
            data: rewritten,
        };
        let action = &output.private_actions[0];
        assert_eq!(
            owner.decrypt(action),
            (PrivateAccountKind::Regular(0), expected.clone())
        );
        assert_eq!(
            action.commitment,
            Commitment::new(&owner.account_id(), &expected)
        );
    }

    #[test]
    fn public_action_post_is_projected_onto_the_touched_shards() {
        let account_id = AccountId::new([9; 32]);
        let pre = AccountData {
            balance: 10,
            shards: [(SHARD_A, data(b"a"))].into(),
        };
        let post_state = Account::funded(7)
            .with_shard(SHARD_A, data(b"a-rewritten"))
            .with_shard(SHARD_C, data(b"c"))
            .data;

        let output = emit(
            vec![(account_id, true, pre.clone(), post_state)],
            Vec::new(),
            &[],
        );

        assert_eq!(
            output.public_actions,
            vec![PublicAction {
                account_id,
                is_authorized: true,
                pre,
                post: AccountData {
                    balance: 7,
                    shards: [(SHARD_A, data(b"a-rewritten"))].into(),
                },
            }]
        );
    }

    #[test]
    #[should_panic(expected = "Every witness's account must be touched by the execution")]
    fn an_untouched_witness_is_rejected() {
        let owner = Owner::new(4);

        let output = emit(
            Vec::new(),
            Vec::new(),
            &[owner.update_witness(Account::default())],
        );

        unreachable!("an untouched witness must panic, got {output:?}");
    }

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
