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
    use std::collections::HashMap;

    use lee_core::{
        AuthorizationSecretKey, DUMMY_COMMITMENT_HASH, EphemeralPublicKey, Identifier,
        NullifierPublicKey, PublicAction,
        account::{AccountData, ShardData},
        program::{BlockValidityWindow, TimestampValidityWindow},
    };

    use super::*;

    const SHARD_A: AccountId = AccountId::new([10; 32]);
    const SHARD_B: AccountId = AccountId::new([11; 32]);

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
                Identifier::ZERO,
            )
        }

        fn update_witness(&self, account: Account) -> PrivateWitness {
            PrivateWitness {
                vpk: self.vpk(),
                random_seed: [0; 32],
                identifier: Identifier::ZERO,
                kind: WitnessKind::Regular {
                    ask: Some(self.ask),
                },
                nullifier: NullifierWitness::Update {
                    account,
                    view_tag: 0,
                    nsk: self.nsk(),
                    membership_proof: (0, Vec::new()),
                },
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
        public_actions: Vec<PublicAction>,
        private: Vec<(AccountId, AccountData)>,
        witnesses: &[PrivateWitness],
    ) -> PrivacyPreservingCircuitOutput {
        compute_circuit_output(
            ExecutionOutcome {
                block_validity_window: BlockValidityWindow::new_unbounded(),
                timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
                public: public_actions,
                private_accounts: private.into_iter().collect(),
            },
            witnesses,
            Vec::new(),
            None,
            Vec::new(),
        )
    }

    fn data(bytes: &[u8]) -> ShardData {
        bytes.to_vec().try_into().expect("test data is small")
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
        let rewritten = Account::funded(60)
            .data
            .with_shard(SHARD_A, data(b"a"))
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
            (
                PrivateAccountKind::Regular(Identifier::ZERO),
                expected.clone()
            )
        );
        assert_eq!(
            action.commitment,
            Commitment::new(&owner.account_id(), &expected)
        );
    }

    fn note(tag: u8) -> PrivateAction {
        let nullifier = Nullifier::for_dummy(&[tag; 32]);
        let commitment = Commitment::for_dummy(&nullifier, &[tag; 32]);
        let ciphertext = EncryptionScheme::encrypt(
            &Account::default(),
            &PrivateAccountKind::Regular(Identifier::ZERO),
            &SharedSecretKey([0; 32]),
            &nullifier,
            None,
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
