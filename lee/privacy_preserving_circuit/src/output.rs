use lee_core::{
    Commitment, CommitmentSetDigest, DummyInput, DummyOutput, EncryptedNote, EncryptionScheme,
    EphemeralSecretKey, ML_KEM_768_CIPHERTEXT_LEN, Nullifier, PrivacyPreservingCircuitOutput,
    PrivateAction, PrivateWitness, ProgramImageClaim, ProvenExecution, RecipientEncryption,
    RootCall, SharedSecretKey,
    account::{Account, AccountData},
    execution_state::{PrivatePartOutcome, PublicExecutionContext},
};

#[expect(
    clippy::too_many_arguments,
    reason = "Each input is a distinct part of the journal; bundling would be artificial"
)]
pub fn compute_circuit_output(
    outcome: PrivatePartOutcome,
    context: PublicExecutionContext,
    public_root: Option<RootCall>,
    private_witnesses: &[PrivateWitness],
    message_spend: Option<((Nullifier, CommitmentSetDigest), DummyOutput)>,
    dummy_inputs: Vec<DummyInput>,
    ciphertext_padding: Option<u32>,
    program_image_claims: Vec<ProgramImageClaim>,
    recoveries: &[RecipientEncryption],
    cast_seals: Vec<RecipientEncryption>,
) -> PrivacyPreservingCircuitOutput {
    let PrivatePartOutcome {
        validity,
        mut private_accounts,
        boundary,
        casts,
    } = outcome;
    let casts = lee_core::seal_casts(&casts, cast_seals, ciphertext_padding)
        .unwrap_or_else(|e| panic!("{e}"));
    let mut output = ProvenExecution {
        boundary,
        casts,
        recovery_bindings: recoveries
            .iter()
            .map(RecipientEncryption::bind_recovery)
            .collect(),
        public_root,
        private_actions: Vec::new(),
        validity,
        program_image_claims,
    };

    // Emit one action per private account, covering all its actor states.
    for witness in private_witnesses {
        let post_data = private_accounts.remove(&witness.account_id()).expect(
            "every witness is declared as a private account and the private part emits each one",
        );
        output
            .private_actions
            .push(private_action(witness, post_data, ciphertext_padding));
    }

    let padding = dummy_inputs.into_iter().map(|dummy| {
        (
            (
                Nullifier::for_dummy(&dummy.nullifier_seed),
                dummy.commitment_root,
            ),
            dummy.output,
        )
    });
    for (spend, filler) in message_spend.into_iter().chain(padding) {
        emit_dummy_output(&mut output, spend, filler, ciphertext_padding);
    }

    obfuscate_output_ordering(&mut output);

    PrivacyPreservingCircuitOutput {
        context,
        execution: output,
    }
}

fn obfuscate_output_ordering(output: &mut ProvenExecution) {
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

fn emit_dummy_output(
    output: &mut ProvenExecution,
    (nullifier, root): (Nullifier, CommitmentSetDigest),
    filler: DummyOutput,
    ciphertext_padding: Option<u32>,
) {
    if let Some(padding) = ciphertext_padding {
        assert!(
            filler.note.ciphertext.as_bytes().len()
                >= usize::try_from(padding).expect("pad length fits in usize"),
            "Dummy note shorter than the requested ciphertext padding"
        );
    }
    assert_eq!(
        filler.note.epk.0.len(),
        ML_KEM_768_CIPHERTEXT_LEN,
        "Dummy note encapsulation is not ML-KEM-768 ciphertext length"
    );
    // Note: the commitments, and the nullifiers of padding, are generated from seeds.
    // The prover is responsible for their randomness.
    let commitment = Commitment::for_dummy(&nullifier, &filler.commitment_seed);
    // Note: the encrypted post states are pushed as fed into the circuit.
    // That means that the prover is responsible for managing the randomness
    // so as to not reveal the padding.
    //
    // In particular, it is recommended to generate the ML KEM ciphertext
    // explicitly as these are not uniformly random.
    output.private_actions.push(PrivateAction {
        nullifier,
        root,
        commitment,
        encrypted_post_state: filler.note,
    });
}

fn private_action(
    witness: &PrivateWitness,
    post_data: AccountData,
    ciphertext_padding: Option<u32>,
) -> PrivateAction {
    let PrivateWitness {
        vpk,
        random_seed,
        kind,
        nullifier: _,
        openings: _,
    } = witness;
    let account_id = witness.account_id();
    let (nullifier, root, nonce) = witness
        .transition()
        .expect("a private account's membership proof must fit its path");
    let post_state = Account {
        nonce,
        data: post_data,
    };
    let account_kind = kind.account_kind();

    let esk = EphemeralSecretKey::new(&account_id, random_seed, &post_state.nonce);
    let (shared_secret, epk) = SharedSecretKey::encapsulate_deterministic(vpk, &esk);

    let encrypted_account = EncryptionScheme::encrypt(
        &post_state,
        &account_kind,
        &shared_secret,
        &nullifier,
        ciphertext_padding,
    );

    PrivateAction {
        nullifier,
        root,
        commitment: Commitment::new(&account_id, &post_state),
        encrypted_post_state: EncryptedNote {
            ciphertext: encrypted_account,
            epk,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};

    use lee_core::{
        AuthorizationSecretKey, DUMMY_COMMITMENT_HASH, EphemeralPublicKey, NullifierPublicKey,
        NullifierSecretKey, NullifierWitness, PrivateAccountKind, RegularKey, WitnessKind,
        account::{AccountId, ActorState, Nonce},
        encryption::ViewingPublicKey,
        execution_state::Boundary,
        program::ValidityWindows,
    };

    use super::*;

    const ACTOR_STATE_A: AccountId = AccountId::new([10; 32]);
    const ACTOR_STATE_B: AccountId = AccountId::new([11; 32]);

    struct Owner {
        ask: AuthorizationSecretKey,
        d: [u8; 32],
        z: [u8; 32],
    }

    impl Owner {
        fn new(tag: u8) -> Self {
            Self {
                ask: AuthorizationSecretKey([tag; 32]),
                d: [tag; 32],
                z: [tag.wrapping_add(1); 32],
            }
        }

        fn nsk(&self) -> NullifierSecretKey {
            NullifierSecretKey::from(&self.ask)
        }

        fn vpk(&self) -> ViewingPublicKey {
            ViewingPublicKey::from_seed(&self.d, &self.z)
        }

        fn account_id(&self) -> AccountId {
            AccountId::for_regular_private_account(
                &NullifierPublicKey::from(&self.nsk()),
                &self.vpk(),
            )
        }

        fn update_witness(&self, account: Account) -> PrivateWitness {
            PrivateWitness {
                vpk: self.vpk(),
                random_seed: [0; 32],
                kind: WitnessKind::Regular(RegularKey::Authorized(self.ask)),
                nullifier: NullifierWitness::Update {
                    account,
                    membership_proof: (0, Vec::new()),
                },
                openings: BTreeSet::new(),
            }
        }

        fn decrypt(&self, action: &PrivateAction) -> (PrivateAccountKind, Account) {
            let shared =
                SharedSecretKey::decapsulate(&action.encrypted_post_state.epk, &self.d, &self.z)
                    .expect("the note's ephemeral key decapsulates");
            EncryptionScheme::decrypt(
                &action.encrypted_post_state.ciphertext,
                &shared,
                &action.nullifier,
            )
            .expect("the note decrypts")
        }
    }

    fn emit(
        private: Vec<(AccountId, AccountData)>,
        witnesses: &[PrivateWitness],
        message_spend: Option<((Nullifier, CommitmentSetDigest), DummyOutput)>,
        dummy_inputs: Vec<DummyInput>,
    ) -> PrivacyPreservingCircuitOutput {
        compute_circuit_output(
            PrivatePartOutcome {
                validity: ValidityWindows::new_unbounded(),
                private_accounts: private.into_iter().collect(),
                boundary: Boundary::default(),
                casts: Vec::new(),
            },
            PublicExecutionContext::default(),
            None,
            witnesses,
            message_spend,
            dummy_inputs,
            None,
            Vec::new(),
            &[],
            Vec::new(),
        )
    }

    fn data(bytes: &[u8]) -> ActorState {
        bytes.to_vec().into()
    }

    #[test]
    fn one_note_per_private_account_carries_its_touched_actor_states() {
        let owner = Owner::new(3);
        let account = Account {
            nonce: Nonce(7),
            ..Account::funded(100)
                .with_actor_state(ACTOR_STATE_A, data(b"a"))
                .with_actor_state(ACTOR_STATE_B, data(b"b"))
        };
        let rewritten = Account::funded(60)
            .data
            .with_actor_state(ACTOR_STATE_A, data(b"a"))
            .with_actor_state(ACTOR_STATE_B, data(b"b-rewritten"));

        let output = emit(
            vec![(owner.account_id(), rewritten.clone())],
            &[owner.update_witness(account.clone())],
            None,
            Vec::new(),
        );

        assert_eq!(
            output.execution.private_actions.len(),
            1,
            "one account, one note"
        );
        let expected = Account {
            nonce: account.nonce.private_account_nonce_increment(&owner.nsk()),
            data: rewritten,
        };
        let action = &output.execution.private_actions[0];
        assert_eq!(
            owner.decrypt(action),
            (PrivateAccountKind::Regular, expected.clone())
        );
        assert_eq!(
            action.commitment,
            Commitment::new(&owner.account_id(), &expected)
        );
    }

    #[test]
    fn a_received_message_is_spent_in_an_action_shaped_like_padding() {
        let owner = Owner::new(3);
        let account = Account::funded(100);
        let private = || vec![(owner.account_id(), account.data.clone())];
        let witnesses = [owner.update_witness(account.clone())];
        let padding = |count: u8| {
            (0..count)
                .map(|tag| DummyInput {
                    nullifier_seed: [tag; 32],
                    commitment_root: [4; 32],
                    output: DummyOutput {
                        commitment_seed: [tag; 32],
                        note: note(tag).encrypted_post_state,
                    },
                })
                .collect()
        };
        let spend = (Nullifier::from_byte_array([5; 32]), [6; 32]);
        let filler = DummyOutput {
            commitment_seed: [7; 32],
            note: note(7).encrypted_post_state,
        };

        let receipt = emit(
            private(),
            &witnesses,
            Some((spend, filler.clone())),
            padding(5),
        );
        let call = emit(private(), &witnesses, None, padding(6));

        assert_eq!(
            receipt.execution.private_actions.len(),
            call.execution.private_actions.len()
        );
        assert!(
            receipt
                .execution
                .private_actions
                .is_sorted_by_key(|action| action.nullifier.to_byte_array())
        );
        let action = receipt
            .execution
            .private_actions
            .iter()
            .find(|action| action.nullifier == spend.0)
            .expect("the message's nullifier is spent in one action");
        assert_eq!(
            (action.root, action.encrypted_post_state.clone()),
            (spend.1, filler.note)
        );
        assert!(
            receipt
                .execution
                .commitments()
                .contains(&Commitment::for_dummy(&spend.0, &filler.commitment_seed))
        );
    }

    #[test]
    #[should_panic(expected = "Dummy note encapsulation is not ML-KEM-768 ciphertext length")]
    fn a_dummy_note_whose_encapsulation_is_not_ml_kem_sized_is_refused() {
        let mut filler = DummyOutput {
            commitment_seed: [7; 32],
            note: note(7).encrypted_post_state,
        };
        filler.note.epk.0.pop();

        emit(
            Vec::new(),
            &[],
            Some(((Nullifier::from_byte_array([5; 32]), [6; 32]), filler)),
            Vec::new(),
        );
    }

    fn note(tag: u8) -> PrivateAction {
        let nullifier = Nullifier::for_dummy(&[tag; 32]);
        let commitment = Commitment::for_dummy(&nullifier, &[tag; 32]);
        let ciphertext = EncryptionScheme::encrypt(
            &Account::default(),
            &PrivateAccountKind::Regular,
            &SharedSecretKey([0; 32]),
            &nullifier,
            None,
        );
        PrivateAction {
            nullifier,
            root: DUMMY_COMMITMENT_HASH,
            commitment,
            encrypted_post_state: EncryptedNote {
                ciphertext,
                epk: EphemeralPublicKey(vec![tag; ML_KEM_768_CIPHERTEXT_LEN]),
            },
        }
    }

    #[test]
    fn obfuscate_byte_sorts_commitments_and_nullifiers() {
        let mut output = ProvenExecution::default();
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
        let mut output = ProvenExecution::default();
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
