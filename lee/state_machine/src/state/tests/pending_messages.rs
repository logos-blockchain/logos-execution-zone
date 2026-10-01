use lee_core::program::{Cast, MessageBody, MessageId, StoredMessage};

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
    Script::write(b"received".to_vec()).from(Origin::Program(scripted_id()))
}

fn replying() -> Script {
    received().send(Cast::new(sender(), &received()))
}

fn cast(state: &mut V03State, to: Actor) -> StoredMessage {
    cast_script(state, to, &received())
}

fn cast_script(state: &mut V03State, to: Actor, script: &Script) -> StoredMessage {
    let tx = public_tx(
        sender(),
        vec![sender()],
        vec![],
        Script::default().send(Cast::new(to, script)),
        &[],
    );
    state.transition_from_public_transaction(&tx, 1, 0).unwrap();
    state
        .pending_messages_from(0)
        .max_by_key(|record| record.sequence)
        .cloned()
        .unwrap()
}

fn receipt(id: MessageId, to: Actor, identities: Vec<PublicIdentity>) -> PublicTransaction {
    let message = public_transaction::Message::new(
        TransactionEntry::Receive(id),
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
                origin_program: scripted_id(),
                to: receiver(),
                message: borsh::to_vec(&received()).unwrap(),
            },
        }]
    );
    assert!(state.get_account_by_id_ref(receiver().account_id).is_none());

    state
        .transition_from_public_transaction(
            &receipt(
                record.id(),
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
        &ShardData::try_from(b"received".to_vec()).unwrap()
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
            .send(Cast::new(receiver(), &received()))
            .send(Cast::new(receiver(), &received())),
        &[],
    );
    let body = MessageBody {
        origin_program: scripted_id(),
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
    assert_ne!(first.id(), second.id());
    assert_eq!(
        cast(&mut state, receiver()),
        StoredMessage { sequence: 2, body }
    );
}

#[test]
fn a_replayed_receipt_is_rejected_and_leaves_the_state_unchanged() {
    let mut state = V03State::new().with_test_programs();
    let record = cast(&mut state, receiver());
    let tx = receipt(
        record.id(),
        receiver(),
        vec![PublicIdentity::Key(receiver_pk())],
    );
    state.transition_from_public_transaction(&tx, 2, 0).unwrap();
    let settled = state.clone();

    let result = state.transition_from_public_transaction(&tx, 3, 0);

    assert!(matches!(
        result,
        Err(LeeError::InvalidInput(message)) if message == "Root message is not pending"
    ));
    assert_eq!(state, settled);
}

#[test]
fn a_public_receipt_needs_identity_evidence_for_an_unauthorized_receiver() {
    let mut state = V03State::new().with_test_programs();
    let record = cast(&mut state, receiver());

    let result =
        state.transition_from_public_transaction(&receipt(record.id(), receiver(), vec![]), 2, 0);

    assert!(matches!(
        result,
        Err(LeeError::UnprovenPublicIdentity { actor }) if actor == receiver()
    ));
    assert_eq!(state.pending_message(record.id()), Some(&record));
    state
        .transition_from_public_transaction(
            &receipt(
                record.id(),
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
    let keys = test_private_account_keys_1();
    let private_receiver = Actor::new(
        AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), Identifier::ZERO),
        scripted_id(),
    );
    let mut state = V03State::new().with_test_programs();
    let record = cast(&mut state, private_receiver);

    let result = state.transition_from_public_transaction(
        &receipt(
            record.id(),
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
    assert_eq!(state.pending_message(record.id()), Some(&record));
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
                record.id(),
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
        .transition_from_public_transaction(&receipt(record.id(), designated, vec![]), 2, 0)
        .expect("a designated account must need no identity evidence");
}

#[test]
fn a_private_account_receives_a_cast_by_proof() {
    let keys = test_private_account_keys_1();
    let private_receiver = Actor::new(
        AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), Identifier::ZERO),
        scripted_id(),
    );
    let mut state = V03State::new().with_test_programs();
    let record = cast(&mut state, private_receiver);
    let id = record.id();
    let proven = execute_and_prove(
        ProvingInput {
            private_witnesses: vec![init_witness(&keys, Identifier::ZERO)],
            ..proving_input(TransactionEntry::Receive(record))
        },
        &scripted_programs(),
    )
    .unwrap();
    let tx = private_tx(proven, vec![], &[]);

    state
        .transition_from_privacy_preserving_transaction(&tx, 2, 0)
        .unwrap();

    assert_eq!(tx.message.consumed_message, Some(id));
    assert!(state.pending_message(id).is_none());
}

#[test]
fn a_proven_receipt_of_an_unpublished_record_is_rejected_at_settlement() {
    let keys = test_private_account_keys_1();
    let record = StoredMessage {
        sequence: 0,
        body: MessageBody {
            origin_program: scripted_id(),
            to: Actor::new(
                AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), Identifier::ZERO),
                scripted_id(),
            ),
            message: borsh::to_vec(&received()).unwrap(),
        },
    };
    let proven = execute_and_prove(
        ProvingInput {
            private_witnesses: vec![init_witness(&keys, Identifier::ZERO)],
            ..proving_input(TransactionEntry::Receive(record))
        },
        &scripted_programs(),
    )
    .unwrap();

    let result = V03State::new()
        .with_test_programs()
        .transition_from_privacy_preserving_transaction(&private_tx(proven, vec![], &[]), 1, 0);

    assert!(matches!(
        result,
        Err(LeeError::InvalidInput(message)) if message == "A consumed message is not pending"
    ));
}

#[test]
fn a_cast_from_a_private_root_is_published_at_settlement() {
    let keys = test_private_account_keys_1();
    let private_root = Actor::new(
        AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), Identifier::ZERO),
        scripted_id(),
    );
    let proven = execute_and_prove(
        ProvingInput {
            private_witnesses: vec![init_witness(&keys, Identifier::ZERO)],
            ..proving_input(root(
                private_root,
                &Script::default().send(Cast::new(receiver(), &received())),
            ))
        },
        &scripted_programs(),
    )
    .unwrap();
    let mut state = V03State::new().with_test_programs();

    state
        .transition_from_privacy_preserving_transaction(&private_tx(proven, vec![], &[]), 1, 0)
        .unwrap();

    assert_eq!(
        state.pending_messages_from(0).cloned().collect::<Vec<_>>(),
        vec![StoredMessage {
            sequence: 0,
            body: MessageBody {
                origin_program: scripted_id(),
                to: receiver(),
                message: borsh::to_vec(&received()).unwrap(),
            },
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
    let id = record.id();
    let proven = execute_and_prove(
        ProvingInput {
            private_witnesses: vec![init_pda_witness(&keys, identifier, (scripted_id(), seed))],
            ..proving_input(TransactionEntry::Receive(record))
        },
        &scripted_programs(),
    )
    .unwrap();

    state
        .transition_from_privacy_preserving_transaction(&private_tx(proven, vec![], &[]), 2, 0)
        .expect("a private PDA must receive a cast by proof alone");

    assert!(state.pending_message(id).is_none());
}

#[test]
fn a_prepared_receipt_to_an_unproven_public_receiver_fails_before_proving() {
    let keys = test_private_account_keys_1();
    let mut state = V03State::new().with_test_programs();
    let record = cast(&mut state, receiver());
    let id = record.id();
    let prove = |identities: HashSet<AccountId>| {
        execute_and_prove(
            ProvingInput {
                public_actors: vec![receiver()],
                identities,
                private_witnesses: vec![init_witness(&keys, Identifier::ZERO)],
                ..proving_input(TransactionEntry::Receive(record.clone()))
            },
            &scripted_programs(),
        )
    };

    assert!(matches!(
        prove(HashSet::new()),
        Err(LeeError::UnprovenPublicIdentity { actor }) if actor == receiver()
    ));
    let (output, proof) = prove([receiver().account_id].into()).unwrap();
    let message = Message {
        identities: vec![PublicIdentity::Key(receiver_pk())],
        ..Message::from_circuit_output(vec![], output)
    };
    let witness_set = WitnessSet::for_message(&message, proof, &[]);

    state
        .transition_from_privacy_preserving_transaction(
            &PrivacyPreservingTransaction::new(message, witness_set),
            2,
            0,
        )
        .expect("the receiver's key must prove its identity at settlement");

    assert!(state.pending_message(id).is_none());
    assert_eq!(
        state
            .get_account_by_id(receiver().account_id)
            .data
            .shard(scripted_id()),
        &ShardData::try_from(b"received".to_vec()).unwrap()
    );
}

#[test]
fn a_pending_record_survives_a_borsh_round_trip_and_enters_the_genesis_fingerprint() {
    // The seeded sender makes the cast's public diff a no-op, so only the record differs.
    let mut state = V03State::new()
        .with_test_programs()
        .with_public_accounts([(sender().account_id, Account::default())]);
    let fingerprint = state.genesis_fingerprint();

    cast(&mut state, receiver());

    assert_eq!(
        borsh::from_slice::<V03State>(&borsh::to_vec(&state).unwrap()).unwrap(),
        state
    );
    assert_ne!(state.genesis_fingerprint(), fingerprint);
}

#[test]
fn a_second_diff_receiving_an_already_received_record_is_refused_at_apply() {
    let mut state = V03State::new().with_test_programs();
    let record = cast_script(&mut state, receiver(), &replying());
    let tx = receipt(
        record.id(),
        receiver(),
        vec![PublicIdentity::Key(receiver_pk())],
    );
    let first = ValidatedStateDiff::from_public_transaction(&tx, &state, 2, 0).unwrap();
    let second = ValidatedStateDiff::from_public_transaction(&tx, &state, 2, 0).unwrap();

    state.apply_state_diff(first).unwrap();
    let settled = state.clone();
    let result = state.apply_state_diff(second);

    assert_eq!(
        settled
            .pending_messages_from(0)
            .cloned()
            .collect::<Vec<_>>(),
        vec![StoredMessage {
            sequence: 1,
            body: MessageBody {
                origin_program: scripted_id(),
                to: sender(),
                message: borsh::to_vec(&received()).unwrap(),
            },
        }]
    );
    assert!(matches!(
        result,
        Err(LeeError::InvalidInput(message)) if message == "A consumed message is no longer pending"
    ));
    assert_eq!(state, settled);
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
        &replying().send(Call::new(receiver(), &Script::default().authorized())),
    );

    let result = state.transition_from_public_transaction(
        &receipt(
            record.id(),
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
            record.id(),
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
        matches!(error, LeeError::UnknownProgram { chained: false }),
        "expected the unknown root program to be named top-level, got {error:?}"
    );
    assert!(!error.is_chargeable());
}
