use lee_core::program::{MessageBody, MessageRef, StoredMessage};

use super::*;
use crate::{PublicIdentity, ValidatedStateDiff};

fn sender() -> Actor {
    Actor::new(AccountId::new([1; 32]), scripted_id())
}

fn receiver_pk() -> PublicKey {
    PublicKey::new_from_private_key(&PrivateKey::try_new([7; 32]).unwrap())
}

fn receiver() -> Actor {
    Actor::new(AccountId::from(&receiver_pk()), scripted_id())
}

fn received() -> Script {
    Script::write(b"received".to_vec()).from(scripted_id())
}

fn replying() -> Script {
    received().cast(sender(), &received())
}

fn cast(state: &mut V03State, to: Actor) -> StoredMessage {
    cast_script(state, to, &received())
}

fn cast_script(state: &mut V03State, to: Actor, script: &Script) -> StoredMessage {
    let tx = public_tx(
        sender(),
        vec![sender()],
        vec![],
        Script::default().cast(to, script),
        &[],
    );
    state.transition_from_public_transaction(&tx, 1, 0).unwrap();
    state
        .pending_messages_from(0)
        .max_by_key(|record| record.sequence)
        .cloned()
        .unwrap()
}

fn receipt(reference: MessageRef, to: Actor, identities: Vec<PublicIdentity>) -> PublicTransaction {
    let message = public_transaction::Message::new(
        TransactionEntry::Cast(reference),
        vec![to],
        vec![],
        None,
        identities,
    );
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    PublicTransaction::new(message, witness_set)
}

#[test]
fn a_cast_publishes_a_pending_record_that_a_later_transaction_receives() {
    let mut state = V03State::new().with_test_programs();

    let record = cast(&mut state, receiver());

    assert_eq!(
        state.pending_messages_from(0).cloned().collect::<Vec<_>>(),
        vec![StoredMessage {
            sequence: 0,
            body: MessageBody {
                source: scripted_id(),
                to: receiver(),
                message: borsh::to_vec(&received()).unwrap(),
            },
        }]
    );
    assert!(state.get_account_by_id_ref(receiver().account_id).is_none());

    state
        .transition_from_public_transaction(
            &receipt(
                record.reference(),
                receiver(),
                vec![PublicIdentity::Key(receiver_pk())],
            ),
            2,
            0,
        )
        .unwrap();

    assert_eq!(
        state
            .get_account_by_id(receiver().account_id)
            .data
            .shard(scripted_id()),
        &ActorState::from(b"received".to_vec())
    );
    assert!(state.pending_messages_from(0).next().is_none());
}

#[test]
fn pending_records_are_numbered_in_publication_order_across_transactions() {
    let mut state = V03State::new().with_test_programs();
    let cast_twice = public_tx(
        sender(),
        vec![sender()],
        vec![],
        Script::default()
            .cast(receiver(), &received())
            .cast(receiver(), &received()),
        &[],
    );
    let body = MessageBody {
        source: scripted_id(),
        to: receiver(),
        message: borsh::to_vec(&received()).unwrap(),
    };

    state
        .transition_from_public_transaction(&cast_twice, 1, 0)
        .unwrap();

    let mut records: Vec<StoredMessage> = state.pending_messages_from(0).cloned().collect();
    records.sort_by_key(|record| record.sequence);
    let [first, second] = <[_; 2]>::try_from(records).unwrap();
    assert_eq!(
        first,
        StoredMessage {
            sequence: 0,
            body: body.clone(),
        }
    );
    assert_eq!(
        second,
        StoredMessage {
            sequence: 1,
            body: body.clone(),
        }
    );
    assert_ne!(first.digest(), second.digest());
    assert_eq!(
        cast(&mut state, receiver()),
        StoredMessage { sequence: 2, body }
    );
}

#[test]
fn a_public_receipt_settles_only_where_its_record_is_pending() {
    let mut holding = V03State::new().with_test_programs();
    let mut replaced = holding.clone();
    let record = cast(&mut holding, receiver());
    let other = cast_script(&mut replaced, receiver(), &replying());
    assert_eq!(record.sequence, other.sequence);
    let tx = receipt(
        record.reference(),
        receiver(),
        vec![PublicIdentity::Key(receiver_pk())],
    );

    holding
        .transition_from_public_transaction(&tx, 2, 0)
        .unwrap();

    for mut mailbox in [holding, replaced] {
        let before = mailbox.clone();
        assert!(matches!(
            mailbox.transition_from_public_transaction(&tx, 3, 0),
            Err(LeeError::InvalidInput(message)) if message == "A consumed message is not pending"
        ));
        assert_eq!(mailbox, before);
    }
}

#[test]
fn a_public_receipt_needs_identity_evidence_for_an_unauthorized_receiver() {
    let mut state = V03State::new().with_test_programs();
    let record = cast(&mut state, receiver());

    let result = state.transition_from_public_transaction(
        &receipt(record.reference(), receiver(), vec![]),
        2,
        0,
    );

    assert!(matches!(
        result,
        Err(LeeError::UnprovenPublicIdentity { actor }) if actor == receiver()
    ));
    assert_eq!(state.pending_message(record.reference()), Some(&record));
    state
        .transition_from_public_transaction(
            &receipt(
                record.reference(),
                receiver(),
                vec![PublicIdentity::Key(receiver_pk())],
            ),
            2,
            0,
        )
        .expect("the receiver's key must prove its identity");
}

#[test]
fn a_cast_to_a_private_account_cannot_be_received_publicly() {
    let private_receiver = private_actor();
    let mut state = V03State::new().with_test_programs();
    let record = cast(&mut state, private_receiver);

    let result = state.transition_from_public_transaction(
        &receipt(
            record.reference(),
            private_receiver,
            vec![PublicIdentity::Key(receiver_pk())],
        ),
        2,
        0,
    );

    assert!(matches!(
        result,
        Err(LeeError::UnprovenPublicIdentity { actor }) if actor == private_receiver
    ));
    assert_eq!(state.pending_message(record.reference()), Some(&record));
}

#[test]
fn a_public_pda_proves_its_identity_by_its_seed() {
    let seed = PdaSeed::new([42; 32]);
    let pda = Actor::new(
        AccountId::for_public_pda(&scripted_id(), &seed),
        scripted_id(),
    );
    let mut state = V03State::new().with_test_programs();
    let record = cast(&mut state, pda);

    state
        .transition_from_public_transaction(
            &receipt(
                record.reference(),
                pda,
                vec![PublicIdentity::Pda {
                    program: scripted_id(),
                    seed,
                }],
            ),
            2,
            0,
        )
        .expect("the PDA's seed must prove its identity");
}

#[test]
fn a_designated_public_account_receives_without_identity_evidence() {
    let designated = Actor::new(AccountId::new([9; 32]), scripted_id());
    let mut state = V03State::new()
        .with_test_programs()
        .with_designated_public_accounts([designated.account_id]);
    let record = cast(&mut state, designated);

    state
        .transition_from_public_transaction(&receipt(record.reference(), designated, vec![]), 2, 0)
        .expect("a designated account must need no identity evidence");
}

#[test]
fn a_proven_receipt_settles_only_where_its_record_is_pending() {
    let keys = test_private_account_keys_1();
    let private_receiver = private_actor();
    let empty = V03State::new().with_test_programs();
    let (mut holding, mut replaced) = (empty.clone(), empty.clone());
    let record = cast(&mut holding, private_receiver);
    let other = cast_script(&mut replaced, private_receiver, &replying());
    assert_eq!(record.sequence, other.sequence);
    let reference = record.reference();
    let proven = execute_and_prove(
        ProvingInput {
            private_witnesses: vec![init_witness(&keys, Identifier::ZERO)],
            ..proving_input(TransactionEntry::Cast(record))
        },
        &Simulation::default(),
        &scripted_programs(),
    )
    .unwrap();
    let tx = private_tx(proven, vec![], &[]);

    for mut mailbox in [empty, replaced] {
        let before = mailbox.clone();
        assert!(matches!(
            mailbox.transition_from_privacy_preserving_transaction(&tx, 2, 0),
            Err(LeeError::InvalidInput(message)) if message == "A consumed message is not pending"
        ));
        assert_eq!(mailbox, before);
    }
    holding
        .transition_from_privacy_preserving_transaction(&tx, 2, 0)
        .unwrap();

    assert_eq!(
        tx.message.instance.entry,
        Some(TransactionEntry::Cast(reference))
    );
    assert!(holding.pending_message(reference).is_none());
}

#[test]
fn a_cast_from_a_private_root_is_published_at_settlement() {
    let tx = proven_casting(
        &Script::default().cast(receiver(), &received()),
        PublicExecutionContext::default(),
    );
    let mut state = V03State::new().with_test_programs();

    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .unwrap();

    assert_eq!(
        state.pending_messages_from(0).cloned().collect::<Vec<_>>(),
        vec![StoredMessage {
            sequence: 0,
            body: cast_body(&received()),
        }]
    );
}

#[test]
fn a_private_pda_with_a_nonzero_identifier_receives_a_cast_without_a_grant() {
    let keys = test_private_account_keys_1();
    let seed = PdaSeed::new([42; 32]);
    let identifier = Identifier::new([3; 32]);
    let pda = Actor::new(
        AccountId::for_private_pda(&scripted_id(), &seed, &keys.npk(), &keys.vpk(), identifier),
        scripted_id(),
    );
    let mut state = V03State::new().with_test_programs();
    let record = cast(&mut state, pda);
    let reference = record.reference();
    let proven = execute_and_prove(
        ProvingInput {
            private_witnesses: vec![init_pda_witness(&keys, identifier, (scripted_id(), seed))],
            ..proving_input(TransactionEntry::Cast(record))
        },
        &Simulation::default(),
        &scripted_programs(),
    )
    .unwrap();

    state
        .transition_from_privacy_preserving_transaction(&private_tx(proven, vec![], &[]), 2, 0)
        .expect("a private PDA must receive a cast by proof alone");

    assert!(state.pending_message(reference).is_none());
}

#[test]
fn a_pending_record_survives_a_borsh_round_trip_and_enters_the_genesis_fingerprint() {
    let mut state = V03State::new().with_test_programs();
    let fingerprint = state.genesis_fingerprint();

    cast(&mut state, receiver());

    assert_eq!(
        borsh::from_slice::<V03State>(&borsh::to_vec(&state).unwrap()).unwrap(),
        state
    );
    assert_ne!(state.genesis_fingerprint(), fingerprint);
}

#[test]
fn a_diff_consuming_a_record_no_longer_pending_is_refused_at_apply() {
    let mut state = V03State::new().with_test_programs();
    let mut fork = state.clone();
    let record = cast_script(&mut state, receiver(), &replying());
    let other = cast(&mut fork, receiver());
    assert_eq!(record.sequence, other.sequence);
    let tx = receipt(
        record.reference(),
        receiver(),
        vec![PublicIdentity::Key(receiver_pk())],
    );
    let validate = || ValidatedStateDiff::from_public_transaction(&tx, &state, 2, 0).unwrap();
    let (first, second, stale) = (validate(), validate(), validate());

    state.apply_state_diff(first).unwrap();

    assert_eq!(
        state.pending_messages_from(0).cloned().collect::<Vec<_>>(),
        vec![StoredMessage {
            sequence: 1,
            body: MessageBody {
                source: scripted_id(),
                to: sender(),
                message: borsh::to_vec(&received()).unwrap(),
            },
        }]
    );
    for (mut target, diff) in [(state, second), (fork, stale)] {
        let before = target.clone();
        assert!(matches!(
            target.apply_state_diff(diff),
            Err(LeeError::InvalidInput(message)) if message == "A consumed message is no longer pending"
        ));
        assert_eq!(target, before);
    }
}

#[test]
fn pending_records_are_listed_in_sequence_order_from_any_sequence() {
    let mut state = V03State::new().with_test_programs();
    let records: Vec<StoredMessage> = std::iter::repeat_with(|| cast(&mut state, receiver()))
        .take(5)
        .collect();

    for from_sequence in 0..=6 {
        assert_eq!(
            state
                .pending_messages_from(from_sequence)
                .cloned()
                .collect::<Vec<_>>(),
            records
                .iter()
                .filter(|record| record.sequence >= from_sequence)
                .cloned()
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn a_receipt_that_fails_after_casting_keeps_its_record_pending_and_publishes_nothing() {
    let mut state = V03State::new().with_test_programs();
    let record = cast_script(
        &mut state,
        receiver(),
        &replying().call(receiver(), &Script::default().authorized()),
    );

    let result = state.transition_from_public_transaction(
        &receipt(
            record.reference(),
            receiver(),
            vec![PublicIdentity::Key(receiver_pk())],
        ),
        2,
        0,
    );

    assert!(matches!(result, Err(LeeError::ProgramExecutionFailed(_))));
    assert_eq!(
        state.pending_messages_from(0).cloned().collect::<Vec<_>>(),
        vec![record]
    );
}

#[test]
fn a_receipt_root_naming_an_unknown_program_is_rejected_not_charged() {
    let unknown = Actor::new(receiver().account_id, AccountId::new([0xEE; 32]));
    let mut state = V03State::new().with_test_programs();
    let record = cast(&mut state, unknown);

    let (_, result) = ValidatedStateDiff::from_public_transaction_metered(
        &receipt(
            record.reference(),
            unknown,
            vec![PublicIdentity::Key(receiver_pk())],
        ),
        &state,
        2,
        0,
        crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET,
    );

    let Err(error) = result else {
        panic!("a receipt root naming an unknown program must reject the block");
    };
    assert!(
        matches!(error, LeeError::UnknownProgram { at_root: true }),
        "expected the unknown root program to be named top-level, got {error:?}"
    );
    assert!(!error.is_chargeable());
}

#[test]
fn a_proven_receipt_at_a_public_root_needs_identity_evidence_at_settlement() {
    let keys = test_private_account_keys_1();
    let mut state = V03State::new().with_test_programs();
    let record = cast(&mut state, receiver());
    let reference = record.reference();
    let (output, proof) = execute_and_prove_with_cross_messages(
        ProvingInput {
            context: PublicExecutionContext::new(vec![receiver()], []),
            private_witnesses: vec![init_witness(&keys, Identifier::ZERO)],
            ..proving_input(TransactionEntry::Cast(record.clone()))
        },
        vec![Vec::new()],
        &scripted_programs(),
    )
    .unwrap();
    let submit = |state: &mut V03State, identities: Vec<PublicIdentity>| {
        let message = Message {
            identities,
            ..Message::from_circuit_output(vec![], output.clone())
        };
        let witness_set = WitnessSet::for_message(&message, proof.clone(), &[]);
        state.transition_from_privacy_preserving_transaction(
            &PrivacyPreservingTransaction::new(message, witness_set),
            2,
            0,
        )
    };

    assert!(matches!(
        submit(&mut state, Vec::new()),
        Err(LeeError::UnprovenPublicIdentity { actor }) if actor == receiver()
    ));
    assert_eq!(state.pending_message(reference), Some(&record));
    submit(&mut state, vec![PublicIdentity::Key(receiver_pk())])
        .expect("the receiver's key must prove its identity at settlement");
    assert!(state.pending_message(reference).is_none());
}

#[test]
fn a_private_receipt_root_that_calls_a_public_actor_needs_no_identity_evidence() {
    let keys = test_private_account_keys_1();
    let private_receiver = private_actor();
    let mut state = V03State::new().with_test_programs();
    let record = cast_script(
        &mut state,
        private_receiver,
        &received().call(receiver(), &Script::write(b"called".to_vec())),
    );
    let reference = record.reference();
    let proven = execute_and_prove(
        ProvingInput {
            context: PublicExecutionContext::new(vec![receiver()], []),
            private_witnesses: vec![init_witness(&keys, Identifier::ZERO)],
            ..proving_input(TransactionEntry::Cast(record))
        },
        &Simulation::default(),
        &scripted_programs(),
    )
    .unwrap();

    state
        .transition_from_privacy_preserving_transaction(&private_tx(proven, vec![], &[]), 2, 0)
        .expect("a private receipt root must need no public identity evidence");

    assert!(state.pending_message(reference).is_none());
    assert_eq!(
        state
            .get_account_by_id(receiver().account_id)
            .data
            .shard(scripted_id()),
        &ActorState::from(b"called".to_vec())
    );
}

#[test]
fn a_signing_public_receiver_needs_no_identity_evidence() {
    let mut state = V03State::new().with_test_programs();
    let record = cast(&mut state, receiver());
    let message = public_transaction::Message::new(
        TransactionEntry::Cast(record.reference()),
        vec![receiver()],
        vec![Nonce(0)],
        None,
        Vec::new(),
    );
    let witness_set = public_transaction::WitnessSet::for_message(
        &message,
        &[&PrivateKey::try_new([7; 32]).unwrap()],
    );

    state
        .transition_from_public_transaction(&PublicTransaction::new(message, witness_set), 2, 0)
        .expect("the receiver's signature must prove its identity");

    assert!(state.pending_message(record.reference()).is_none());
}

#[test]
fn a_public_receipt_without_identity_evidence_is_rejected_not_charged() {
    let mut state = V03State::new().with_test_programs();
    let record = cast(&mut state, receiver());

    let (_, result) = ValidatedStateDiff::from_public_transaction_metered(
        &receipt(record.reference(), receiver(), Vec::new()),
        &state,
        2,
        0,
        crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET,
    );

    let Err(error) = result else {
        panic!("a public receipt without identity evidence must reject the block");
    };
    assert!(
        matches!(error, LeeError::UnprovenPublicIdentity { actor } if actor == receiver()),
        "expected the receiver's identity to be unproven, got {error:?}"
    );
    assert!(!error.is_chargeable());
}

fn private_actor() -> Actor {
    let keys = test_private_account_keys_1();
    Actor::new(
        AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), Identifier::ZERO),
        scripted_id(),
    )
}

fn proven_casting(
    root_script: &Script,
    context: PublicExecutionContext,
) -> PrivacyPreservingTransaction {
    let proven = execute_and_prove(
        ProvingInput {
            context,
            private_witnesses: vec![init_witness(
                &test_private_account_keys_1(),
                Identifier::ZERO,
            )],
            ..proving_input(root(private_actor(), root_script))
        },
        &Simulation::default(),
        &scripted_programs(),
    )
    .unwrap();
    private_tx(proven, vec![], &[])
}

fn cast_body(script: &Script) -> MessageBody {
    MessageBody {
        source: scripted_id(),
        to: receiver(),
        message: borsh::to_vec(script).unwrap(),
    }
}

#[test]
fn identical_casts_are_received_independently_and_out_of_order() {
    let mut state = V03State::new().with_test_programs();
    let cast_twice = public_tx(
        sender(),
        vec![sender()],
        vec![],
        Script::default()
            .cast(receiver(), &received())
            .cast(receiver(), &received()),
        &[],
    );
    state
        .transition_from_public_transaction(&cast_twice, 1, 0)
        .unwrap();
    let [first, second] =
        <[_; 2]>::try_from(state.pending_messages_from(0).cloned().collect::<Vec<_>>()).unwrap();

    state
        .transition_from_public_transaction(
            &receipt(
                second.reference(),
                receiver(),
                vec![PublicIdentity::Key(receiver_pk())],
            ),
            2,
            0,
        )
        .unwrap();

    assert_eq!(
        state.pending_messages_from(0).cloned().collect::<Vec<_>>(),
        vec![first]
    );
}

#[test]
fn a_mixed_transaction_publishes_its_live_casts_before_its_proven_casts() {
    let live = Script::default().cast(receiver(), &replying());
    let tx = proven_casting(
        &Script::default()
            .cast(receiver(), &received())
            .call(sender(), &live),
        PublicExecutionContext::new(vec![sender()], []),
    );
    let mut state = V03State::new().with_test_programs();

    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .unwrap();

    assert_eq!(
        state.pending_messages_from(0).cloned().collect::<Vec<_>>(),
        vec![
            StoredMessage {
                sequence: 0,
                body: cast_body(&replying()),
            },
            StoredMessage {
                sequence: 1,
                body: cast_body(&received()),
            },
        ]
    );
}

#[test]
fn a_tampered_proven_cast_is_rejected() {
    let mut tx = proven_casting(
        &Script::default().cast(receiver(), &received()),
        PublicExecutionContext::default(),
    );
    let state = V03State::new().with_test_programs();
    assert!(
        ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0).is_ok(),
        "the unmodified statement must verify"
    );

    tx.message.instance.casts[0].message[0] ^= 0xFF;

    assert!(matches!(
        ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0),
        Err(LeeError::InvalidPrivacyPreservingProof)
    ));
}
