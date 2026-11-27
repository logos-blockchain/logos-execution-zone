use lee_core::{
    Commitment, CommitmentSetDigest, DummyInput, DummyOutput, EncryptedNote, EncryptionScheme,
    EphemeralSecretKey, FeeFallback, FeeTransfer, ML_KEM_768_CIPHERTEXT_LEN, Nullifier,
    PrivacyPreservingCircuitOutput, PrivateAction, PrivateWitness, ProgramImageClaim,
    ProvenExecution, ProvenFee, PublicationMode, RecipientEncryption, RootCall, SharedSecretKey,
    account::{Account, AccountData, Actor, Nonce},
    execution_state::{Boundary, BoundaryStep, PrivatePartOutcome, PublicExecutionContext},
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
};

/// A nullifier spent with no private action of its own, a received message's or a dummy
/// input's, and the dummy output standing in for its commitment.
pub struct MessageSpend {
    pub nullifier: Nullifier,
    pub root: CommitmentSetDigest,
    pub filler: DummyOutput,
}

/// The key a private account's note is encrypted under, and the nonce of the state it carries.
struct NoteKey {
    esk: EphemeralSecretKey,
    shared_secret: SharedSecretKey,
    nonce: Nonce,
}

#[expect(
    clippy::too_many_arguments,
    reason = "Each input is a distinct part of the journal; bundling would be artificial"
)]
pub fn compute_circuit_output(
    outcome: PrivatePartOutcome,
    public_context: PublicExecutionContext,
    public_root: Option<RootCall>,
    private_witnesses: &[PrivateWitness],
    message_spends: Vec<MessageSpend>,
    dummy_inputs: Vec<DummyInput>,
    ciphertext_padding: Option<u32>,
    program_image_claims: Vec<ProgramImageClaim>,
    recoveries: &[RecipientEncryption],
    publication_modes: Vec<PublicationMode>,
    fee: Option<FeeTransfer>,
) -> PrivacyPreservingCircuitOutput {
    let PrivatePartOutcome {
        validity,
        mut private_accounts,
        boundary,
        async_messages,
    } = outcome;
    let async_messages =
        lee_core::publish_messages(async_messages, publication_modes, ciphertext_padding)
            .unwrap_or_else(|e| panic!("{e}"));
    let mut output = ProvenExecution {
        boundary,
        async_messages,
        recovery_bindings: Vec::new(),
        public_root,
        private_actions: Vec::new(),
        validity,
        program_image_claims,
        proven_fee: None,
    };

    // Emit one action per private account, covering all its actor states.
    let mut fallback = None;
    let mut note_keys = Vec::with_capacity(private_witnesses.len());
    for witness in private_witnesses {
        let post_data = private_accounts.remove(&witness.account_id()).expect(
            "every witness is declared as a private account and the private part emits each one",
        );
        let (action, key) = private_action(witness, post_data, ciphertext_padding);
        if let Some(fee) = fee.as_ref().filter(|fee| fee.payer == witness.account_id()) {
            fallback = fee_fallback(
                fee,
                &output.boundary,
                witness,
                &action,
                &key,
                ciphertext_padding,
            );
        }
        output.private_actions.push(action);
        note_keys.push(key);
    }
    output.proven_fee = fee.map(|fee| ProvenFee {
        refund_to: fee.refund_to,
        tip: fee.tip,
        fallback,
    });
    // A recovery under a note's own ephemeral key shares that note's encapsulation.
    output.recovery_bindings = recoveries
        .iter()
        .map(|recovery| {
            private_witnesses
                .iter()
                .zip(&note_keys)
                .zip(&output.private_actions)
                .find(|((witness, key), _)| {
                    key.esk.0 == recovery.esk.0 && witness.vpk == recovery.recipient.vpk
                })
                .map_or_else(
                    || recovery.bind_recovery(),
                    |((_, key), action)| {
                        recovery.bind_recovery_under(
                            &key.shared_secret,
                            action.encrypted_post_state.epk.clone(),
                        )
                    },
                )
        })
        .collect();

    // Pad the output with dummy commitment/nullifier pairs.
    let padding = dummy_inputs.into_iter().map(|dummy| MessageSpend {
        nullifier: Nullifier::for_dummy(&dummy.nullifier_seed),
        root: dummy.commitment_root,
        filler: dummy.output,
    });

    // Each consumed message's nullifier is padded with a dummy commitment.
    for spend in message_spends.into_iter().chain(padding) {
        emit_dummy_output(&mut output, spend, ciphertext_padding);
    }

    obfuscate_output_ordering(&mut output);

    PrivacyPreservingCircuitOutput {
        public_context,
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
    MessageSpend {
        nullifier,
        root,
        filler,
    }: MessageSpend,
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

/// The payer's transition after the fee transfer alone, for settlement to apply when the public
/// part fails: `None` when its pre-state does not cover the transfer or nothing crosses with it.
///
/// This enables us to include reverted pptx'es, like how we do for public tx'es
/// so that we can charge the user for sending (potentially spamming) wrong tx'es.
///
/// `main` is the payer's action and `key` its note's key. Settlement applies one of the two, so
/// the fallback shares the main note's encapsulation, encrypted under a key apart from it.
fn fee_fallback(
    fee: &FeeTransfer,
    boundary: &Boundary,
    witness: &PrivateWitness,
    main: &PrivateAction,
    key: &NoteKey,
    ciphertext_padding: Option<u32>,
) -> Option<FeeFallback> {
    let pre = witness.predecessor();
    let balance = native_token::decode_balance(pre.data.actor_state(NATIVE_TOKEN_PROGRAM_ID))
        .ok()?
        .checked_sub(fee.amount)?;
    let post = pre.data.clone().with_actor_state(
        NATIVE_TOKEN_PROGRAM_ID,
        native_token::encode_balance(balance),
    );
    let credit = borsh::to_vec(&native_token::Message::Credit(fee.amount))
        .expect("a native message serializes");
    // The fee entry runs last, so searching from the end finds its own crossing; settlement
    // rejects a transaction crediting the inbox twice anyway.
    let crossing = boundary.iter().rev().find_map(|step| match step {
        BoundaryStep::PrivateToPublic(delivery)
            if delivery.envelope.to == Actor::native_balance(fee.recipient)
                && delivery.envelope.message == credit =>
        {
            Some(delivery.clone())
        }
        BoundaryStep::PrivateToPublic(_)
        | BoundaryStep::PublicToPrivate(_)
        | BoundaryStep::EndPrivateSubtree
        | BoundaryStep::EndPublicSubtree => None,
    })?;
    let post_state = Account {
        nonce: key.nonce,
        data: post,
    };
    let ciphertext = EncryptionScheme::encrypt_fee_fallback(
        &post_state,
        &witness.kind.account_kind(),
        &key.shared_secret,
        &main.nullifier,
        ciphertext_padding,
    );
    Some(FeeFallback {
        nullifier: main.nullifier,
        root: main.root,
        commitment: Commitment::new(&witness.account_id(), &post_state),
        ciphertext,
        boundary: vec![
            BoundaryStep::PrivateToPublic(crossing),
            BoundaryStep::EndPublicSubtree,
        ],
    })
}

/// Generate a private action given old and new account data, encrypted under the key the
/// successor's nonce derives. Also returns that key.
fn private_action(
    witness: &PrivateWitness,
    post_data: AccountData,
    ciphertext_padding: Option<u32>,
) -> (PrivateAction, NoteKey) {
    let PrivateWitness {
        vpk,
        random_seed,
        kind,
        nullifier: _,
        address_openings: _,
        signer_programs: _,
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

    let action = PrivateAction {
        nullifier,
        root,
        commitment: Commitment::new(&account_id, &post_state),
        encrypted_post_state: EncryptedNote {
            ciphertext: encrypted_account,
            epk,
        },
    };
    let key = NoteKey {
        esk,
        shared_secret,
        nonce: post_state.nonce,
    };
    (action, key)
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
                address_openings: BTreeSet::new(),
                signer_programs: BTreeSet::new(),
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

        fn decrypt_fallback(&self, action: &PrivateAction) -> (PrivateAccountKind, Account) {
            let shared =
                SharedSecretKey::decapsulate(&action.encrypted_post_state.epk, &self.d, &self.z)
                    .expect("the note's ephemeral key decapsulates");
            EncryptionScheme::decrypt_fee_fallback(
                &action.encrypted_post_state.ciphertext,
                &shared,
                &action.nullifier,
            )
            .expect("the fallback note decrypts")
        }
    }

    fn emit(
        private: Vec<(AccountId, AccountData)>,
        witnesses: &[PrivateWitness],
        message_spend: Option<MessageSpend>,
        dummy_inputs: Vec<DummyInput>,
    ) -> PrivacyPreservingCircuitOutput {
        compute_circuit_output(
            PrivatePartOutcome {
                validity: ValidityWindows::new_unbounded(),
                private_accounts: private.into_iter().collect(),
                boundary: Boundary::default(),
                async_messages: Vec::new(),
            },
            PublicExecutionContext::default(),
            None,
            witnesses,
            message_spend.into_iter().collect(),
            dummy_inputs,
            None,
            Vec::new(),
            &[],
            Vec::new(),
            None,
        )
    }

    fn data(bytes: &[u8]) -> ActorState {
        bytes.to_vec().into()
    }

    /// The fee's credit crossing into `inbox`.
    fn fee_crossing(inbox: AccountId, amount: u128) -> BoundaryStep {
        BoundaryStep::PrivateToPublic(lee_core::execution_state::Delivery {
            envelope: lee_core::program::MessageEnvelope {
                from: Actor::native_balance(AccountId::new([9; 32])),
                to: Actor::native_balance(inbox),
                message: borsh::to_vec(&native_token::Message::Credit(amount)).unwrap(),
            },
            grants: BTreeSet::new(),
            pda_seeds: BTreeSet::new(),
        })
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
        let (nullifier, root) = (Nullifier::from_byte_array([5; 32]), [6; 32]);
        let filler = DummyOutput {
            commitment_seed: [7; 32],
            note: note(7).encrypted_post_state,
        };

        let receipt = emit(
            private(),
            &witnesses,
            Some(MessageSpend {
                nullifier,
                root,
                filler: filler.clone(),
            }),
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
            .find(|action| action.nullifier == nullifier)
            .expect("the message's nullifier is spent in one action");
        assert_eq!(
            (action.root, action.encrypted_post_state.clone()),
            (root, filler.note)
        );
        assert!(
            receipt
                .execution
                .commitments()
                .contains(&Commitment::for_dummy(&nullifier, &filler.commitment_seed))
        );
    }

    #[test]
    fn the_fee_fallback_is_the_payers_state_after_the_transfer_alone() {
        let owner = Owner::new(3);
        let account = Account::funded(100);
        let witness = owner.update_witness(account.clone());
        let inbox = AccountId::new([8; 32]);
        let fee = FeeTransfer {
            payer: owner.account_id(),
            recipient: inbox,
            amount: 30,
            refund_to: None,
            tip: 0,
        };
        let boundary = vec![fee_crossing(inbox, 30), BoundaryStep::EndPublicSubtree];

        let (main, key) = private_action(&witness, Account::funded(70).data, None);
        let fallback = fee_fallback(&fee, &boundary, &witness, &main, &key, None)
            .expect("the pre-state covers the fee");
        let expected = Account {
            nonce: account.nonce.private_account_nonce_increment(&owner.nsk()),
            data: Account::funded(70).data,
        };
        assert_eq!(
            fallback.commitment,
            Commitment::new(&owner.account_id(), &expected)
        );
        // The fallback carries no ephemeral key: its note opens under the main action's.
        let action = fallback
            .action(std::slice::from_ref(&main))
            .expect("the fallback spends the main action's nullifier");
        assert_eq!(
            owner.decrypt_fallback(&action),
            (PrivateAccountKind::Regular, expected)
        );
        assert_eq!(
            fallback.boundary,
            vec![fee_crossing(inbox, 30), BoundaryStep::EndPublicSubtree]
        );
        // Under keys apart: the same state encrypts differently.
        assert_ne!(
            main.encrypted_post_state.ciphertext.as_bytes(),
            fallback.ciphertext.as_bytes()
        );

        // A fee the pre-state does not cover, or whose credit does not cross, has no fallback.
        let unaffordable = FeeTransfer { amount: 101, ..fee };
        assert!(fee_fallback(&unaffordable, &boundary, &witness, &main, &key, None).is_none());
        assert!(fee_fallback(&fee, &Vec::new(), &witness, &main, &key, None).is_none());
    }

    #[test]
    fn the_fee_fallback_and_recovery_follow_the_payers_action_through_the_output() {
        // The payer is neither the first nor the last witness, each of which could cover the
        // fee, and padding reorders the actions.
        let (other, payer, last) = (Owner::new(4), Owner::new(3), Owner::new(5));
        let account = Account::funded(100);
        let witnesses = [
            other.update_witness(Account::funded(50)),
            payer.update_witness(account.clone()),
            last.update_witness(Account::funded(50)),
        ];
        let inbox = AccountId::new([8; 32]);
        let (_, key) = private_action(&witnesses[1], Account::funded(40).data, None);
        let recovery = RecipientEncryption {
            recipient: lee_core::Recipient {
                npk: NullifierPublicKey::from(&payer.nsk()),
                vpk: payer.vpk(),
                kind: PrivateAccountKind::Regular,
                opening: Some([4; 32]),
            },
            esk: key.esk,
        };

        let output = compute_circuit_output(
            PrivatePartOutcome {
                validity: ValidityWindows::new_unbounded(),
                private_accounts: [
                    (other.account_id(), Account::funded(50).data),
                    (payer.account_id(), Account::funded(40).data),
                    (last.account_id(), Account::funded(50).data),
                ]
                .into(),
                boundary: vec![fee_crossing(inbox, 30), BoundaryStep::EndPublicSubtree],
                async_messages: Vec::new(),
            },
            PublicExecutionContext::default(),
            None,
            &witnesses,
            Vec::new(),
            (0..3)
                .map(|tag| DummyInput {
                    nullifier_seed: [tag; 32],
                    commitment_root: [4; 32],
                    output: DummyOutput {
                        commitment_seed: [tag; 32],
                        note: note(tag).encrypted_post_state,
                    },
                })
                .collect(),
            None,
            Vec::new(),
            std::slice::from_ref(&recovery),
            Vec::new(),
            Some(FeeTransfer {
                payer: payer.account_id(),
                recipient: inbox,
                amount: 30,
                refund_to: None,
                tip: 0,
            }),
        )
        .execution;

        let nonce = account.nonce.private_account_nonce_increment(&payer.nsk());
        let state = |balance| {
            let data = Account::funded(balance).data;
            (PrivateAccountKind::Regular, Account { nonce, data })
        };
        let fallback = output
            .proven_fee
            .and_then(|fee| fee.fallback)
            .expect("the payer's pre-state covers the fee");
        let main = output
            .private_actions
            .iter()
            .find(|action| action.nullifier == fallback.nullifier)
            .expect("the fallback spends the payer's nullifier");
        assert_eq!(payer.decrypt(main), state(40));
        let action = fallback
            .action(&output.private_actions)
            .expect("the fallback finds the payer's action");
        assert_eq!(payer.decrypt_fallback(&action), state(70));
        assert_eq!(
            output.recovery_bindings[0].note.epk,
            main.encrypted_post_state.epk
        );
    }

    #[test]
    fn a_recovery_under_a_notes_ephemeral_key_shares_its_encapsulation() {
        let owner = Owner::new(3);
        let witness = owner.update_witness(Account::funded(100));
        let (action, key) = private_action(&witness, Account::funded(100).data, None);
        let recovery = |vpk, esk| RecipientEncryption {
            recipient: lee_core::Recipient {
                npk: NullifierPublicKey::from(&owner.nsk()),
                vpk,
                kind: PrivateAccountKind::Regular,
                opening: Some([4; 32]),
            },
            esk,
        };
        let shared = recovery(owner.vpk(), key.esk);
        let apart = recovery(owner.vpk(), EphemeralSecretKey([5; 32]));
        // The note's ephemeral key, but another recipient: the note's secret is not theirs.
        let foreign = recovery(Owner::new(9).vpk(), key.esk);

        let output = compute_circuit_output(
            PrivatePartOutcome {
                validity: ValidityWindows::new_unbounded(),
                private_accounts: [(owner.account_id(), Account::funded(100).data)].into(),
                boundary: Boundary::default(),
                async_messages: Vec::new(),
            },
            PublicExecutionContext::default(),
            None,
            std::slice::from_ref(&witness),
            Vec::new(),
            Vec::new(),
            None,
            Vec::new(),
            &[shared.clone(), apart.clone(), foreign.clone()],
            Vec::new(),
            None,
        );

        let bindings = output.execution.recovery_bindings;
        assert_eq!(bindings[0].note.epk, action.encrypted_post_state.epk);
        assert_ne!(bindings[1].note.epk, action.encrypted_post_state.epk);
        // Sharing changes no binding: each is what its own encapsulation makes.
        assert_eq!(bindings[0], shared.bind_recovery());
        assert_eq!(bindings[1], apart.bind_recovery());
        assert_ne!(bindings[2].note.epk, action.encrypted_post_state.epk);
        assert_eq!(bindings[2], foreign.bind_recovery());
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
            Some(MessageSpend {
                nullifier: Nullifier::from_byte_array([5; 32]),
                root: [6; 32],
                filler,
            }),
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
