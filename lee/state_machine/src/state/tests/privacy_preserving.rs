use lee_core::execution_state::BoundaryStep;

use super::*;

// One funded private account, rooted at its scripted actor, whose native balance it may also
// address.
struct PrivateRoot {
    state: V03State,
    keys: TestPrivateKeys,
    account_id: AccountId,
    pre_account: Account,
}

impl PrivateRoot {
    fn new() -> Self {
        let keys = test_private_account_keys_1();
        let account_id =
            AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), Identifier::ZERO);
        let pre_account = Account::funded(100);
        let state = V03State::new()
            .with_test_programs()
            .with_private_account(&keys, &pre_account);
        Self {
            state,
            keys,
            account_id,
            pre_account,
        }
    }

    fn proving_input(&self, script: &Script, public_actors: Vec<Actor>) -> ProvingInput {
        let membership_proof = self
            .state
            .get_proof_for_commitment(&Commitment::new(&self.account_id, &self.pre_account))
            .expect("the account's commitment must be in state");
        ProvingInput {
            context: PublicExecutionContext::new(public_actors, []),
            private_witnesses: vec![update_witness(
                &self.keys,
                Identifier::ZERO,
                self.pre_account.clone(),
                membership_proof,
            )],
            ..proving_input(root(Actor::new(self.account_id, scripted_id()), script))
        }
    }

    fn prove(&self, script: &Script, public_actors: Vec<Actor>) -> PrivacyPreservingTransaction {
        let proven = execute_and_prove(
            self.proving_input(script, public_actors),
            &Simulation::default(),
            &synthetic_program(crate::test_methods::scripted()),
        )
        .unwrap();
        private_tx(proven, vec![], &[])
    }
}

// A shielded P → A → Q statement: the public root P sends into the private actor A, whose turn
// sends to the public actor Q. The proof always assumes P delivers `inner_turn` to A.
struct NestedBoundary {
    state: V03State,
    outer: Actor,
    inner: Actor,
    tx: PrivacyPreservingTransaction,
}

impl NestedBoundary {
    fn prove(outer_script: &Script) -> Self {
        let keys = test_private_account_keys_1();
        let (outer, inner) = nested_actors();
        let proven = execute_and_prove_assuming(
            ProvingInput {
                context: PublicExecutionContext::new(vec![outer, inner], []),
                private_witnesses: vec![init_witness(&keys, Identifier::ZERO)],
                ..proving_input(root(outer, outer_script))
            },
            vec![
                vec![Assumption {
                    envelope: MessageEnvelope {
                        source: outer,
                        to: nested_private(),
                        message: borsh::to_vec(&inner_turn()).unwrap(),
                    },
                    grants: Vec::new(),
                    pda_seeds: Vec::new(),
                }],
                Vec::new(),
            ],
            &synthetic_program(crate::test_methods::scripted()),
        )
        .unwrap();

        Self {
            state: V03State::new().with_programs([crate::test_methods::scripted()]),
            outer,
            inner,
            tx: private_tx(proven, vec![], &[]),
        }
    }
}

#[test]
fn transition_from_privacy_preserving_transaction_shielded() {
    let sender_keys = test_public_account_keys_1();
    let recipient_keys = test_private_account_keys_1();

    let mut state = V03State::new().with_public_account_balances([(sender_keys.account_id(), 200)]);

    let balance_to_move = 37;

    let tx =
        shielded_balance_transfer_for_tests(&sender_keys, &recipient_keys, balance_to_move, &state);

    let expected_sender_post = {
        let mut this = state.get_account_by_id(sender_keys.account_id());
        let post_balance = this.data.native_balance().unwrap() - balance_to_move;
        this.data
            .set_shard(NATIVE_TOKEN_PROGRAM_ID, encode_balance(post_balance));
        this.nonce.public_account_nonce_increment();
        this
    };

    let [expected_new_commitment] = tx.message().execution.commitments().try_into().unwrap();
    assert!(!state.private_state.0.contains(&expected_new_commitment));

    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .unwrap();

    let sender_post = state.get_account_by_id(sender_keys.account_id());
    assert_eq!(sender_post, expected_sender_post);
    assert!(state.private_state.0.contains(&expected_new_commitment));

    assert_eq!(
        state
            .get_account_by_id(sender_keys.account_id())
            .data
            .native_balance(),
        Ok(200 - balance_to_move)
    );
}

#[test]
fn privacy_preserving_witness_set_cannot_have_dulicate_signers() {
    let sender_keys = test_public_account_keys_1();
    let recipient_keys = test_private_account_keys_1();

    let mut state = V03State::new().with_public_account_balances([(sender_keys.account_id(), 200)]);

    let tx = shielded_balance_transfer_for_tests(&sender_keys, &recipient_keys, 37, &state);

    // Re-sign the same message with the sender twice; both nonces match the
    // current state, so only the repeat is at fault.
    let (_, proof) = tx.witness_set.into_raw_parts();
    let mut message = tx.message;
    let nonce = message.nonces[0];
    message.nonces = vec![nonce, nonce];
    let witness_set = WitnessSet::for_message(
        &message,
        proof,
        &[&sender_keys.signing_key, &sender_keys.signing_key],
    );
    let tx = PrivacyPreservingTransaction::new(message, witness_set);

    let result = state.transition_from_privacy_preserving_transaction(&tx, 1, 0);
    assert!(matches!(
        result,
        Err(LeeError::InvalidInput(msg)) if msg.contains("Duplicate signers")
    ));
}

#[test]
fn transition_from_privacy_preserving_transaction_private() {
    let sender_keys = test_private_account_keys_1();
    let sender_nonce = Nonce(0xdead_beef);

    let sender_private_account = Account {
        nonce: sender_nonce,
        ..Account::funded(100)
    };
    let recipient_keys = test_private_account_keys_2();

    let mut state = V03State::new().with_private_account(&sender_keys, &sender_private_account);

    let balance_to_move = 37;

    let tx = private_balance_transfer_for_tests(
        &sender_keys,
        &sender_private_account,
        &recipient_keys,
        balance_to_move,
        &state,
    );

    let sender_account_id = AccountId::for_regular_private_account(
        &sender_keys.npk(),
        &sender_keys.vpk(),
        Identifier::ZERO,
    );
    let recipient_account_id = AccountId::for_regular_private_account(
        &recipient_keys.npk(),
        &recipient_keys.vpk(),
        Identifier::ZERO,
    );
    let expected_new_commitment_1 = Commitment::new(
        &sender_account_id,
        &Account {
            nonce: sender_nonce.private_account_nonce_increment(&sender_keys.nsk()),
            ..Account::funded(
                sender_private_account.data.native_balance().unwrap() - balance_to_move,
            )
        },
    );

    let sender_pre_commitment = Commitment::new(&sender_account_id, &sender_private_account);
    let expected_new_nullifier =
        Nullifier::for_account_update(&sender_pre_commitment, &sender_keys.nsk());

    let expected_new_commitment_2 = Commitment::new(
        &recipient_account_id,
        &Account {
            nonce: Nonce::private_account_nonce_init(&recipient_account_id),
            ..Account::funded(balance_to_move)
        },
    );

    let previous_public_state = state.public_state.clone();
    assert!(state.private_state.0.contains(&sender_pre_commitment));
    assert!(!state.private_state.0.contains(&expected_new_commitment_1));
    assert!(!state.private_state.0.contains(&expected_new_commitment_2));
    assert!(!state.private_state.1.contains(&expected_new_nullifier));

    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .unwrap();

    assert_eq!(state.public_state, previous_public_state);
    assert!(state.private_state.0.contains(&sender_pre_commitment));
    assert!(state.private_state.0.contains(&expected_new_commitment_1));
    assert!(state.private_state.0.contains(&expected_new_commitment_2));
    assert!(state.private_state.1.contains(&expected_new_nullifier));
}

/// After a valid fully-private tx is proven, tampering with a note's epk should
/// make the shielding proof invalid.
#[test]
fn privacy_tampered_epk_is_rejected() {
    use crate::validated_state_diff::ValidatedStateDiff;

    let (state, mut tx) = valid_private_transfer_tx_and_state();

    // Baseline: the untampered tx verifies
    assert!(
        ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0).is_ok(),
        "the unmodified private transfer must verify"
    );

    // Flip a byte of the first note's epk
    tx.message.execution.private_actions[0]
        .encrypted_post_state
        .epk
        .0[0] ^= 0xFF;

    assert!(
        matches!(
            ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0),
            Err(LeeError::InvalidPrivacyPreservingProof)
        ),
        "a tampered epk must be rejected by proof verification"
    );
}

/// After a valid fully-private tx is proven, tampering with a note's view tag should
/// make the shielding proof invalid.
#[test]
fn privacy_tampered_view_tag_is_rejected() {
    use crate::validated_state_diff::ValidatedStateDiff;

    let (state, mut tx) = valid_private_transfer_tx_and_state();

    // Baseline: the untampered tx verifies.
    assert!(
        ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0).is_ok(),
        "the unmodified private transfer must verify"
    );

    // Flip the first note's view_tag
    tx.message.execution.private_actions[0]
        .encrypted_post_state
        .view_tag ^= 0xFF;

    assert!(
        matches!(
            ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0),
            Err(LeeError::InvalidPrivacyPreservingProof)
        ),
        "a tampered view_tag must be rejected by proof verification"
    );
}

#[test]
fn a_journal_claiming_an_unsigned_account_authorized_is_rejected() {
    use crate::validated_state_diff::ValidatedStateDiff;

    let sender_keys = test_public_account_keys_1();
    let recipient_keys = test_private_account_keys_1();
    let state = V03State::new().with_public_account_balances([(sender_keys.account_id(), 100)]);
    let signed = shielded_balance_transfer_for_tests(&sender_keys, &recipient_keys, 10, &state);
    assert!(
        ValidatedStateDiff::from_privacy_preserving_transaction(&signed, &state, 1, 0).is_ok(),
        "the signed transfer must verify"
    );

    // The same proof, which claims the sender authorized it, without the sender's signature.
    let PrivacyPreservingTransaction {
        mut message,
        witness_set,
    } = signed;
    message.nonces.clear();
    let unsigned = PrivacyPreservingTransaction::new(
        message.clone(),
        WitnessSet::for_message(&message, witness_set.proof.clone(), &[]),
    );

    assert!(matches!(
        ValidatedStateDiff::from_privacy_preserving_transaction(&unsigned, &state, 1, 0),
        Err(LeeError::InvalidInput(msg)) if msg == "Authorized accounts do not match the signers"
    ));

    // Dropping the claim to match the missing signature detaches the statement from its proof.
    message.execution.context.authorized_accounts.clear();
    let unclaimed = PrivacyPreservingTransaction::new(
        message.clone(),
        WitnessSet::for_message(&message, witness_set.proof, &[]),
    );

    assert!(matches!(
        ValidatedStateDiff::from_privacy_preserving_transaction(&unclaimed, &state, 1, 0),
        Err(LeeError::InvalidPrivacyPreservingProof)
    ));
}

#[test]
fn a_tampered_boundary_output_is_rejected() {
    use crate::validated_state_diff::ValidatedStateDiff;

    let sender_keys = test_private_account_keys_1();
    let sender_private_account = Account {
        nonce: Nonce(0xdead_beef),
        ..Account::funded(100)
    };
    let recipient_id = test_public_account_keys_1().account_id();
    let state = V03State::new()
        .with_public_account_balances([(recipient_id, 400)])
        .with_private_account(&sender_keys, &sender_private_account);
    let mut tx = deshielded_balance_transfer_for_tests(
        &sender_keys,
        &sender_private_account,
        &recipient_id,
        37,
        &state,
    );
    assert!(
        ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0).is_ok(),
        "the unmodified transfer must verify"
    );

    let BoundaryStep::CallPublic(delivery) = &mut tx.message.execution.boundary[0] else {
        panic!("the transfer's boundary opens with its public call");
    };
    delivery.envelope.message[0] ^= 0xFF;

    assert!(matches!(
        ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0),
        Err(LeeError::InvalidPrivacyPreservingProof)
    ));
}

#[test]
fn a_failing_public_turn_leaves_the_state_untouched() {
    let program_id = scripted_id();
    let sender_keys = test_public_account_keys_1();
    let sender_id = sender_keys.account_id();
    let sender = Actor::native_balance(sender_id);
    let own = Actor::new(AccountId::new([7; 32]), program_id);
    let recipient_keys = test_private_account_keys_1();
    let recipient_id = AccountId::for_regular_private_account(
        &recipient_keys.npk(),
        &recipient_keys.vpk(),
        Identifier::ZERO,
    );
    let mut state = V03State::new()
        .with_programs([crate::test_methods::scripted()])
        .with_public_account_balances([(sender_id, 10)]);
    let overdraft: u128 = 11;

    // The builder's snapshot funds the overdraft, so it proves and only fails once settled.
    let script = Script::write(vec![1]).call(sender, &transfer(recipient_id, overdraft));
    let proven = execute_and_prove(
        ProvingInput {
            context: PublicExecutionContext::new(vec![own, sender], [sender_id]),
            private_witnesses: vec![init_witness(&recipient_keys, Identifier::ZERO)],
            ..proving_input(root(own, &script))
        },
        &Simulation {
            public_shards: [(sender, encode_balance(overdraft))].into(),
            ..Simulation::default()
        },
        &synthetic_program(crate::test_methods::scripted()),
    )
    .unwrap();
    let tx = private_tx(
        proven,
        vec![state.get_account_by_id(sender_id).nonce],
        &[&sender_keys.signing_key],
    );
    let public_state = state.public_state.clone();

    let result = state.transition_from_privacy_preserving_transaction(&tx, 1, 0);

    assert!(
        matches!(
            result,
            Err(LeeError::InvalidProgramBehavior(
                InvalidProgramBehaviorError::NativeTransferFailed(
                    TransferError::InsufficientBalance { account_id }
                )
            )) if account_id == sender_id
        ),
        "expected the debit to fail at settlement, got {result:?}"
    );
    assert_eq!(state.public_state, public_state);
    assert!(
        !state
            .private_state
            .1
            .contains(&Nullifier::for_account_initialization(&recipient_id))
    );
}

#[test]
fn transition_from_privacy_preserving_transaction_deshielded() {
    let sender_keys = test_private_account_keys_1();
    let sender_nonce = Nonce(0xdead_beef);

    let sender_private_account = Account {
        nonce: sender_nonce,
        ..Account::funded(100)
    };
    let recipient_keys = test_public_account_keys_1();
    let recipient_initial_balance = 400;
    let mut state = V03State::new()
        .with_public_account_balances([(recipient_keys.account_id(), recipient_initial_balance)])
        .with_private_account(&sender_keys, &sender_private_account);

    let balance_to_move = 37;

    let expected_recipient_post = {
        let mut this = state.get_account_by_id(recipient_keys.account_id());
        let post_balance = this.data.native_balance().unwrap() + balance_to_move;
        this.data
            .set_shard(NATIVE_TOKEN_PROGRAM_ID, encode_balance(post_balance));
        this
    };

    let tx = deshielded_balance_transfer_for_tests(
        &sender_keys,
        &sender_private_account,
        &recipient_keys.account_id(),
        balance_to_move,
        &state,
    );

    let sender_account_id = AccountId::for_regular_private_account(
        &sender_keys.npk(),
        &sender_keys.vpk(),
        Identifier::ZERO,
    );
    let expected_new_commitment = Commitment::new(
        &sender_account_id,
        &Account {
            nonce: sender_nonce.private_account_nonce_increment(&sender_keys.nsk()),
            ..Account::funded(
                sender_private_account.data.native_balance().unwrap() - balance_to_move,
            )
        },
    );

    let sender_pre_commitment = Commitment::new(&sender_account_id, &sender_private_account);
    let expected_new_nullifier =
        Nullifier::for_account_update(&sender_pre_commitment, &sender_keys.nsk());

    assert!(state.private_state.0.contains(&sender_pre_commitment));
    assert!(!state.private_state.0.contains(&expected_new_commitment));
    assert!(!state.private_state.1.contains(&expected_new_nullifier));

    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .unwrap();

    let recipient_post = state.get_account_by_id(recipient_keys.account_id());
    assert_eq!(recipient_post, expected_recipient_post);
    assert!(state.private_state.0.contains(&sender_pre_commitment));
    assert!(state.private_state.0.contains(&expected_new_commitment));
    assert!(state.private_state.1.contains(&expected_new_nullifier));
    assert_eq!(
        state
            .get_account_by_id(recipient_keys.account_id())
            .data
            .native_balance(),
        Ok(recipient_initial_balance + balance_to_move)
    );
}

#[test]
fn an_unauthorized_public_debit_proves_but_is_refused_at_settlement() {
    let sender_id = test_public_account_keys_1().account_id();
    let sender = Actor::native_balance(sender_id);
    let recipient_keys = test_private_account_keys_1();
    let recipient_id = AccountId::for_regular_private_account(
        &recipient_keys.npk(),
        &recipient_keys.vpk(),
        Identifier::ZERO,
    );
    let mut state = V03State::new().with_public_account_balances([(sender_id, 100)]);

    // An honest prover would refuse the debit; this one assumes its credit without running it.
    let proven = execute_and_prove_assuming(
        ProvingInput {
            context: PublicExecutionContext::new(vec![sender], []),
            private_witnesses: vec![init_witness(&recipient_keys, Identifier::ZERO)],
            ..proving_input(root(sender, &transfer(recipient_id, 10)))
        },
        vec![vec![credit(
            sender,
            Actor::native_balance(recipient_id),
            10,
        )]],
        &ProgramCatalog::default(),
    )
    .expect("the proof does not cover the public debit");
    let tx = private_tx(proven, vec![], &[]);

    let result = state.transition_from_privacy_preserving_transaction(&tx, 1, 0);

    assert!(
        matches!(
            result,
            Err(LeeError::InvalidProgramBehavior(
                InvalidProgramBehaviorError::NativeTransferFailed(
                    TransferError::UnauthorizedSender { account_id }
                )
            )) if account_id == sender_id
        ),
        "expected an unauthorized sender rejection, got {result:?}"
    );
}

#[test]
fn two_deshielded_transfers_to_one_recipient_compose_at_settlement() {
    let recipient_id = test_public_account_keys_1().account_id();
    let senders = [
        (test_private_account_keys_1(), 37_u128),
        (test_private_account_keys_2(), 11),
    ];
    let sender_account = Account {
        nonce: Nonce(0xdead_beef),
        ..Account::funded(100)
    };

    let mut state = V03State::new().with_public_account_balances([(recipient_id, 400)]);
    for (keys, _) in &senders {
        state = state.with_private_account(keys, &sender_account);
    }

    let transactions: Vec<_> = senders
        .iter()
        .map(|(keys, amount)| {
            deshielded_balance_transfer_for_tests(
                keys,
                &sender_account,
                &recipient_id,
                *amount,
                &state,
            )
        })
        .collect();

    let mut expected = 400;
    for (tx, (_, amount)) in transactions.iter().zip(&senders) {
        state
            .transition_from_privacy_preserving_transaction(tx, 1, 0)
            .unwrap();
        expected += amount;
        assert_eq!(
            state.get_account_by_id(recipient_id).data.native_balance(),
            Ok(expected)
        );
    }
}

#[test]
fn a_private_roots_public_outputs_settle_against_live_state() {
    let mut root = PrivateRoot::new();
    let written_to = Actor::new(AccountId::new([77; 32]), scripted_id());
    let recipient = Actor::native_balance(AccountId::new([88; 32]));
    let amount: u128 = 30;

    let tx = root.prove(
        &Script::default()
            .call(written_to, &Script::write(vec![5; 4]))
            .call(
                Actor::native_balance(root.account_id),
                &transfer(recipient.account_id, amount),
            ),
        vec![written_to, recipient],
    );

    root.state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .expect("the public outputs settle");

    // The scripted actor's own shard was written by its live turn at settlement.
    assert_eq!(
        root.state
            .get_account_by_id(written_to.account_id)
            .data
            .shard(scripted_id())
            .as_ref(),
        &[5_u8; 4]
    );
    // The native leg of the same transaction settled alongside it.
    assert_eq!(
        root.state
            .get_account_by_id(recipient.account_id)
            .data
            .native_balance(),
        Ok(amount)
    );
}

fn assert_forged_field_is_refused(forge_field: ForgeField) {
    let mut root = PrivateRoot::new();
    let program_id = AccountId::from_builtin_program(crate::test_methods::forges_echo().id());
    let forger = Actor::new(AccountId::new([77; 32]), program_id);

    // The prover assumes the forger delivers nothing back, without running it.
    let proven = execute_and_prove_assuming(
        root.proving_input(&Script::default().call(forger, &forge_field), vec![forger]),
        vec![Vec::new()],
        &synthetic_program(crate::test_methods::scripted()),
    )
    .unwrap();
    let tx = private_tx(proven, vec![], &[]);

    let result = root
        .state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0);

    assert!(
        matches!(
            &result,
            Err(LeeError::InvalidProgramBehavior(
                InvalidProgramBehaviorError::Execution(ExecutionError::ExecutionValidation {
                    program_account_id,
                    source: ExecutionValidationError::TransitionInputMismatch { .. },
                })
            )) if *program_account_id == program_id
        ),
        "expected the echo binding to refuse the forged transition, got {result:?}"
    );
    assert_eq!(
        root.state.get_account_by_id(forger.account_id),
        Account::default()
    );
}

#[test]
fn a_public_turn_forging_its_receiver_is_refused() {
    assert_forged_field_is_refused(ForgeField::Receiver);
}

#[test]
fn a_public_turn_forging_the_pre_state_it_was_given_is_refused() {
    assert_forged_field_is_refused(ForgeField::PreState);
}

#[test]
fn a_public_turn_forging_the_message_it_was_sent_is_refused() {
    assert_forged_field_is_refused(ForgeField::Message);
}

fn nested_actors() -> (Actor, Actor) {
    (
        Actor::new(AccountId::new([1; 32]), scripted_id()),
        Actor::new(AccountId::new([2; 32]), scripted_id()),
    )
}

fn inner_turn() -> Script {
    Script::default().call(nested_actors().1, &Script::write(vec![2; 4]))
}

fn nested_private() -> Actor {
    let keys = test_private_account_keys_1();
    Actor::new(
        AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), Identifier::ZERO),
        scripted_id(),
    )
}

fn outer_turn(delivered: &Script) -> Script {
    Script::write(vec![1; 4]).call(nested_private(), delivered)
}

#[test]
fn a_nested_boundary_settles_both_public_writes() {
    let mut nested = NestedBoundary::prove(&outer_turn(&inner_turn()));

    assert!(matches!(
        nested.tx.message.execution.boundary.as_slice(),
        [
            BoundaryStep::CallPublic(_),
            BoundaryStep::EnterPrivate(_),
            BoundaryStep::CallPublic(_),
            BoundaryStep::ReturnPublic,
            BoundaryStep::LeavePrivate,
            BoundaryStep::ReturnPublic,
        ]
    ));

    nested
        .state
        .transition_from_privacy_preserving_transaction(&nested.tx, 1, 0)
        .expect("the live public turns reproduce the proven boundary");

    for (actor, written) in [(nested.outer, [1; 4]), (nested.inner, [2; 4])] {
        assert_eq!(
            nested
                .state
                .get_account_by_id(actor.account_id)
                .data
                .shard(scripted_id())
                .as_ref(),
            written
        );
    }
}

#[test]
fn a_tampered_assumption_is_rejected() {
    use crate::validated_state_diff::ValidatedStateDiff;

    let mut nested = NestedBoundary::prove(&outer_turn(&inner_turn()));
    assert!(
        ValidatedStateDiff::from_privacy_preserving_transaction(&nested.tx, &nested.state, 1, 0)
            .is_ok(),
        "the unmodified statement must verify"
    );

    let BoundaryStep::EnterPrivate(assumption) = &mut nested.tx.message.execution.boundary[1]
    else {
        panic!("the nested boundary enters the private turn second");
    };
    assumption.envelope.message[0] ^= 0xFF;

    assert!(matches!(
        ValidatedStateDiff::from_privacy_preserving_transaction(&nested.tx, &nested.state, 1, 0),
        Err(LeeError::InvalidPrivacyPreservingProof)
    ));
}

#[test]
fn a_public_turn_departing_from_its_assumed_delivery_is_rejected_and_applies_nothing() {
    // The outer turn's live script delivers something other than the assumed message.
    let mut nested = NestedBoundary::prove(
        &outer_turn(&Script::default()).cast(nested_actors().1, &Script::default()),
    );
    let public_state = nested.state.public_state.clone();

    let result = nested
        .state
        .transition_from_privacy_preserving_transaction(&nested.tx, 1, 0);

    assert!(
        matches!(
            execution_error(result),
            ExecutionError::AssumptionMismatch { index: 1 }
        ),
        "the live delivery must be checked against the assumed one"
    );
    assert_eq!(nested.state.public_state, public_state);
    assert!(
        nested
            .state
            .get_proof_for_commitment(&nested.tx.message.execution.commitments()[0])
            .is_none()
    );
    assert!(nested.state.pending_messages_from(0).next().is_none());
}
