use lee_core::{
    Commitment, CommitmentSetDigest, DummyInput, DummyOutput, EncryptedNote, EncryptionScheme,
    EphemeralSecretKey, FeeFallback, FeeTransfer, ML_KEM_768_CIPHERTEXT_LEN, Nullifier,
    PrivacyPreservingCircuitOutput, PrivateAction, PrivateWitness, ProgramImageClaim,
    ProvenExecution, ProvenFee, RecipientEncryption, RootCall, SharedSecretKey,
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
    message_seals: Vec<RecipientEncryption>,
    fee: Option<FeeTransfer>,
) -> PrivacyPreservingCircuitOutput {
    let PrivatePartOutcome {
        validity,
        mut private_accounts,
        boundary,
        async_messages,
    } = outcome;
    let async_messages =
        lee_core::seal_messages(&async_messages, message_seals, ciphertext_padding)
            .unwrap_or_else(|e| panic!("{e}"));
    let fee = fee.map(|fee| ProvenFee {
        refund_to: fee.refund_to,
        fallback: fee_fallback(&fee, &boundary, private_witnesses, ciphertext_padding),
    });
    let mut output = ProvenExecution {
        boundary,
        async_messages,
        recovery_bindings: recoveries
            .iter()
            .map(RecipientEncryption::bind_recovery)
            .collect(),
        public_root,
        private_actions: Vec::new(),
        validity,
        program_image_claims,
        fee,
    };

    // Emit one action per private account, covering all its actor states.
    for witness in private_witnesses {
        let post_data = private_accounts.remove(&witness.account_id()).expect(
            "every witness is declared as a private account and the private part emits each one",
        );
        output
            .private_actions
            .push(private_action(witness, post_data, ciphertext_padding, None));
    }

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
fn fee_fallback(
    fee: &FeeTransfer,
    boundary: &Boundary,
    private_witnesses: &[PrivateWitness],
    ciphertext_padding: Option<u32>,
) -> Option<FeeFallback> {
    let witness = private_witnesses
        .iter()
        .find(|witness| witness.account_id() == fee.payer)?;
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
    // Its own key: the main note is encrypted under the successor's nonce.
    let esk_nonce = pre.nonce;
    Some(FeeFallback {
        action: private_action(witness, post, ciphertext_padding, Some(esk_nonce)),
        boundary: vec![
            BoundaryStep::PrivateToPublic(crossing),
            BoundaryStep::EndPublicSubtree,
        ],
    })
}

/// Generate a private action given old and new account data, encrypted under the key the
/// successor's nonce derives unless `esk_nonce` names another.
fn private_action(
    witness: &PrivateWitness,
    post_data: AccountData,
    ciphertext_padding: Option<u32>,
    esk_nonce: Option<Nonce>,
) -> PrivateAction {
    let PrivateWitness {
        vpk,
        random_seed,
        kind,
        nullifier: _,
        address_openings: _,
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

    let esk = EphemeralSecretKey::new(
        &account_id,
        random_seed,
        &esk_nonce.unwrap_or(post_state.nonce),
    );
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
                address_openings: BTreeSet::new(),
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
        };
        let crossing = |amount| {
            BoundaryStep::PrivateToPublic(lee_core::execution_state::Delivery {
                envelope: lee_core::program::MessageEnvelope {
                    from: Actor::native_balance(AccountId::new([9; 32])),
                    to: Actor::native_balance(inbox),
                    message: borsh::to_vec(&native_token::Message::Credit(amount)).unwrap(),
                },
                inherited_authorizations: BTreeSet::new(),
                inherits_entry_authorizations: true,
                pda_seeds: BTreeSet::new(),
            })
        };
        let boundary = vec![crossing(30), BoundaryStep::EndPublicSubtree];

        let fallback = fee_fallback(&fee, &boundary, std::slice::from_ref(&witness), None)
            .expect("the pre-state covers the fee");
        let expected = Account {
            nonce: account.nonce.private_account_nonce_increment(&owner.nsk()),
            data: Account::funded(70).data,
        };
        assert_eq!(
            fallback.action.commitment,
            Commitment::new(&owner.account_id(), &expected)
        );
        assert_eq!(
            owner.decrypt(&fallback.action),
            (PrivateAccountKind::Regular, expected)
        );
        assert_eq!(
            fallback.boundary,
            vec![crossing(30), BoundaryStep::EndPublicSubtree]
        );
        // Encrypted under its own key, apart from the main note's.
        let main = private_action(&witness, Account::funded(70).data, None, None);
        assert_ne!(
            main.encrypted_post_state.epk,
            fallback.action.encrypted_post_state.epk
        );

        // A fee the pre-state does not cover, or whose credit does not cross, has no fallback.
        let unaffordable = FeeTransfer { amount: 101, ..fee };
        assert!(
            fee_fallback(
                &unaffordable,
                &boundary,
                std::slice::from_ref(&witness),
                None
            )
            .is_none()
        );
        assert!(fee_fallback(&fee, &Vec::new(), &[witness], None).is_none());
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
