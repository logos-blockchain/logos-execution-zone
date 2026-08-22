use super::*;

fn program_transaction<T: serde::Serialize>(
    program_id: ProgramId,
    account_id: AccountId,
    instruction: T,
) -> PublicTransaction {
    let message =
        public_transaction::Message::try_new(program_id, vec![account_id], vec![], instruction)
            .expect("test instruction must serialize");
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    PublicTransaction::new(message, witness_set)
}

fn payloads(events: &[lee_core::program::Event]) -> Vec<Vec<u8>> {
    events.iter().map(|event| event.data.clone()).collect()
}

#[test]
fn emitted_events_are_returned_in_order_and_attributed_to_the_emitter() {
    let account_id = AccountId::new([1; 32]);
    let mut state = V03State::new().with_test_programs();
    let emitter_id = crate::test_methods::event_emitter().id();

    let tx = program_transaction(
        emitter_id,
        account_id,
        EmitterInstruction {
            events: vec![vec![0; 4], vec![1; 4]],
            chain: vec![],
        },
    );

    let events = state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    assert_eq!(payloads(&events), vec![vec![0; 4], vec![1; 4]]);
    assert!(events.iter().all(|event| event.program_id == emitter_id));
}

#[test]
fn parent_events_precede_chained_callee_events() {
    let account_id = AccountId::new([1; 32]);
    let mut state = V03State::new().with_test_programs();
    let emitter_id = crate::test_methods::event_emitter().id();

    let callee_instruction_data = Program::serialize_instruction(EmitterInstruction {
        events: vec![vec![1; 4], vec![2; 4]],
        chain: vec![],
    })
    .unwrap();

    let tx = program_transaction(
        emitter_id,
        account_id,
        EmitterInstruction {
            events: vec![vec![0; 4]],
            chain: vec![(emitter_id, callee_instruction_data)],
        },
    );

    let events = state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    assert_eq!(
        payloads(&events),
        vec![vec![0; 4], vec![1; 4], vec![2; 4]],
        "a parent's events must all precede its callee's"
    );
}

#[test]
fn chained_events_follow_depth_first_pre_order() {
    let account_id = AccountId::new([1; 32]);
    let mut state = V03State::new().with_test_programs();
    let emitter_id = crate::test_methods::event_emitter().id();

    let grandchild = Program::serialize_instruction(EmitterInstruction {
        events: vec![vec![2; 4]],
        chain: vec![],
    })
    .unwrap();
    let first_callee = Program::serialize_instruction(EmitterInstruction {
        events: vec![vec![1; 4]],
        chain: vec![(emitter_id, grandchild)],
    })
    .unwrap();
    let second_callee = Program::serialize_instruction(EmitterInstruction {
        events: vec![vec![3; 4]],
        chain: vec![],
    })
    .unwrap();

    let tx = program_transaction(
        emitter_id,
        account_id,
        EmitterInstruction {
            events: vec![vec![0; 4]],
            chain: vec![(emitter_id, first_callee), (emitter_id, second_callee)],
        },
    );

    let events = state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    assert_eq!(
        payloads(&events),
        vec![vec![0; 4], vec![1; 4], vec![2; 4], vec![3; 4]],
        "depth-first pre-order: the first callee's subtree must complete before the second \
         callee runs (breadth-first would yield 0, 1, 3, 2)"
    );
}

#[test]
fn chained_callee_events_are_attributed_to_the_callee_not_the_caller() {
    let initiator = crate::test_methods::flash_swap_initiator();
    let emitter = crate::test_methods::event_emitter();
    let token = crate::test_methods::simple_balance_transfer();

    let vault_id = AccountId::for_public_pda(&initiator.id(), &PdaSeed::new([0; 32]));
    let receiver_id = AccountId::for_public_pda(&emitter.id(), &PdaSeed::new([1; 32]));

    let mut state = V03State::new().with_test_programs();
    state.force_insert_account(
        vault_id,
        Account {
            program_owner: token.id().into(),
            balance: 1000,
            ..Account::default()
        },
    );
    state.force_insert_account(
        receiver_id,
        Account {
            program_owner: token.id().into(),
            balance: 0,
            ..Account::default()
        },
    );

    // Zero-amount flash swap: the emitter runs as the callback, the second of the initiator's
    // three sibling chained calls, so the only emitting program is neither the top-level
    // program nor its caller.
    let callback_instruction_data = Program::serialize_instruction(EmitterInstruction {
        events: vec![vec![0; 4]],
        chain: vec![],
    })
    .unwrap();
    let instruction = FlashSwapInstruction::Initiate {
        token_program_id: token.id(),
        callback_program_id: emitter.id(),
        amount_out: 0,
        callback_instruction_data,
    };

    let tx = build_flash_swap_tx(&initiator, vault_id, receiver_id, instruction);
    let events = state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    assert_eq!(payloads(&events), vec![vec![0; 4]]);
    assert_eq!(events[0].program_id, emitter.id());
    assert_ne!(events[0].program_id, initiator.id());
    assert_ne!(events[0].program_id, token.id());
}

#[test]
fn program_that_emits_nothing_yields_no_events() {
    let account_id = AccountId::new([1; 32]);
    let mut state = V03State::new().with_test_programs();

    let tx = program_transaction(crate::test_methods::noop().id(), account_id, ());

    let events = state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    assert!(events.is_empty());
}
