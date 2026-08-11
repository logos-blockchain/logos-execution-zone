use super::*;

// Reference for the selector VALUE convention: selector = first 8 bytes of
// sha256("<program>::<EventName>"), pinned as a literal so the guest never hashes.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Debug, PartialEq, Eq)]
struct ExampleEvent {
    account: AccountId,
    amount: Balance,
}

impl ExampleEvent {
    const SELECTOR_NAME: &'static str = "lee_test::ExampleEvent";
    const SELECTOR: [u8; 8] = [0x92, 0x8d, 0x12, 0x8c, 0x88, 0x2f, 0x1c, 0x5d];

    fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).unwrap()
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        borsh::from_slice(bytes).unwrap()
    }
}

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

fn payloads(events: &[TransactionEvent]) -> Vec<Vec<u8>> {
    events
        .iter()
        .map(|event| event.event.data.clone())
        .collect()
}

fn emitted(n: u8) -> ProgramEvent {
    ProgramEvent {
        selector: [n; 8],
        data: vec![n; 4],
    }
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
            events: vec![emitted(0), emitted(1)],
            chain: vec![],
        },
    );

    let events = state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    assert_eq!(payloads(&events), vec![vec![0; 4], vec![1; 4]]);
    assert_eq!(
        events
            .iter()
            .map(|event| event.event.selector)
            .collect::<Vec<_>>(),
        vec![[0; 8], [1; 8]]
    );
    assert!(events.iter().all(|event| event.program_id == emitter_id));
}

#[test]
fn parent_events_precede_chained_callee_events() {
    let account_id = AccountId::new([1; 32]);
    let mut state = V03State::new().with_test_programs();
    let emitter_id = crate::test_methods::event_emitter().id();

    let callee_instruction_data = Program::serialize_instruction(EmitterInstruction {
        events: vec![emitted(1), emitted(2)],
        chain: vec![],
    })
    .unwrap();

    let tx = program_transaction(
        emitter_id,
        account_id,
        EmitterInstruction {
            events: vec![emitted(0)],
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
        events: vec![emitted(2)],
        chain: vec![],
    })
    .unwrap();
    let first_callee = Program::serialize_instruction(EmitterInstruction {
        events: vec![emitted(1)],
        chain: vec![(emitter_id, grandchild)],
    })
    .unwrap();
    let second_callee = Program::serialize_instruction(EmitterInstruction {
        events: vec![emitted(3)],
        chain: vec![],
    })
    .unwrap();

    let tx = program_transaction(
        emitter_id,
        account_id,
        EmitterInstruction {
            events: vec![emitted(0)],
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
        events: vec![emitted(0)],
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

#[test]
fn example_event_selector_matches_its_derivation() {
    use sha2::Digest as _;

    let digest = sha2::Sha256::digest(ExampleEvent::SELECTOR_NAME.as_bytes());

    assert_eq!(&ExampleEvent::SELECTOR[..], &digest[..8]);
}

#[test]
fn events_are_filterable_by_selector_and_decodable() {
    let account_id = AccountId::new([1; 32]);
    let mut state = V03State::new().with_test_programs();
    let emitter_id = crate::test_methods::event_emitter().id();

    let example = ExampleEvent {
        account: AccountId::new([7; 32]),
        amount: 42,
    };
    let tx = program_transaction(
        emitter_id,
        account_id,
        EmitterInstruction {
            events: vec![
                emitted(0),
                ProgramEvent {
                    selector: ExampleEvent::SELECTOR,
                    data: example.to_bytes(),
                },
                emitted(1),
            ],
            chain: vec![],
        },
    );

    let events = state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    let matched: Vec<_> = events
        .iter()
        .filter(|event| event.event.selector == ExampleEvent::SELECTOR)
        .collect();
    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0].program_id, emitter_id);
    assert_eq!(ExampleEvent::from_bytes(&matched[0].event.data), example);

    let unmatched = events
        .iter()
        .filter(|event| event.event.selector == [0xff; 8])
        .count();
    assert_eq!(unmatched, 0);
}

#[test]
fn event_emitting_program_proves_and_validates_on_the_private_path() {
    let keys = test_private_account_keys_1();
    let emitter = crate::test_methods::event_emitter();

    let pre = AccountWithMetadata::new(Account::default(), true, (&keys.npk(), &keys.vpk(), 0));

    let (output, proof) = crate::privacy_preserving_transaction::circuit::execute_and_prove(
        vec![pre],
        Program::serialize_instruction(EmitterInstruction {
            events: vec![emitted(0), emitted(1)],
            chain: vec![],
        })
        .unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: WitnessKind::Regular {
                ask: Some(keys.ask),
            },
            nullifier: NullifierWitness::Init {
                npk: keys.npk(),
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        })],
        &emitter.into(),
    )
    .expect("emitting guest must prove on the private path");

    assert_eq!(output.private_actions.len(), 1);

    let message = Message::from_circuit_output(vec![], output);
    let witness_set = WitnessSet::for_message(&message, proof, &[]);
    let tx = PrivacyPreservingTransaction::new(message, witness_set);

    let mut state = V03State::new();

    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .unwrap();
}
