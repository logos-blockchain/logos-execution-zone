use lee_core::program::Response;

use super::*;

// Reference for the selector VALUE convention: selector = first 8 bytes of
// sha256("<program>::<EventName>"), pinned as a literal so the guest never hashes.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Debug, PartialEq, Eq)]
struct ExampleEvent {
    account: AccountId,
    amount: Balance,
}

impl ExampleEvent {
    const SELECTOR: [u8; 8] = [0x92, 0x8d, 0x12, 0x8c, 0x88, 0x2f, 0x1c, 0x5d];
    const SELECTOR_NAME: &'static str = "lee_test::ExampleEvent";

    fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).unwrap()
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        borsh::from_slice(bytes).unwrap()
    }
}

fn emitter() -> Actor {
    Actor::new(AccountId::new([1; 32]), scripted_id())
}

fn emitting(events: Vec<ProgramEvent>) -> Script {
    Script {
        response: Response {
            events,
            ..Response::keep_state()
        },
        ..Script::default()
    }
}

fn emitter_transaction(script: Script) -> PublicTransaction {
    public_tx(emitter(), vec![emitter()], vec![], script, &[])
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
    let mut state = V03State::new().with_programs([crate::test_methods::scripted()]);
    let emitter_id = scripted_id();

    let tx = emitter_transaction(emitting(vec![emitted(0), emitted(1)]));

    let events = state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    assert_eq!(payloads(&events), vec![vec![0; 4], vec![1; 4]]);
    assert_eq!(
        events
            .iter()
            .map(|event| event.event.selector)
            .collect::<Vec<_>>(),
        vec![[0; 8], [1; 8]]
    );
    assert!(events.iter().all(|event| event.account_id == emitter_id));
}

#[test]
fn events_of_sent_turns_follow_depth_first_pre_order() {
    let mut state = V03State::new().with_programs([crate::test_methods::scripted()]);
    let to_emitter = emitter();

    let grandchild = emitting(vec![emitted(2)]);
    let first_callee = emitting(vec![emitted(1)]).call(to_emitter, &grandchild);
    let second_callee = emitting(vec![emitted(3)]);

    let tx = emitter_transaction(
        emitting(vec![emitted(0)])
            .call(to_emitter, &first_callee)
            .call(to_emitter, &second_callee),
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
fn a_sent_turns_events_are_attributed_to_its_program_not_its_sender() {
    let initiator = crate::test_methods::flash_swap_initiator();

    let vault_id = AccountId::for_public_pda(
        &AccountId::from_builtin_program(initiator.id()),
        &PdaSeed::new([0; 32]),
    );
    let receiver_id = AccountId::new([2; 32]);
    let callback = Actor::new(receiver_id, scripted_id());

    let mut state = V03State::new().with_programs([
        crate::test_methods::scripted(),
        crate::test_methods::flash_swap_initiator(),
    ]);
    state.force_insert_account(vault_id, Account::funded(1000));

    // Zero-amount flash swap: the emitter runs as the callback, the second of the initiator's
    // three sends, so the only emitting program is neither the root program nor its sender.
    let message = FlashSwapMessage::Initiate {
        vault: vault_id,
        receiver: receiver_id,
        callback,
        amount_out: 0,
        vault_balance: 1000,
        callback_message: borsh::to_vec(&emitting(vec![emitted(0)])).unwrap(),
    };

    let tx = flash_swap_tx(vault_id, receiver_id, callback, &message);
    let events = state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    assert_eq!(payloads(&events), vec![vec![0; 4]]);
    assert_eq!(events[0].account_id, scripted_id());
    assert_ne!(
        events[0].account_id,
        AccountId::from_builtin_program(initiator.id())
    );
    assert_ne!(events[0].account_id, NATIVE_TOKEN_PROGRAM_ID);
}

#[test]
fn program_that_emits_nothing_yields_no_events() {
    let mut state = V03State::new().with_programs([crate::test_methods::scripted()]);

    let tx = emitter_transaction(Script::default());

    let events = state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    assert!(events.is_empty());
}

#[test]
fn emitted_events_leave_state_untouched() {
    let run = |events: Vec<ProgramEvent>| {
        let mut state = V03State::new().with_programs([crate::test_methods::scripted()]);
        let tx = emitter_transaction(emitting(events));
        state.transition_from_public_transaction(&tx, 1, 0).unwrap();
        state
    };

    let silent = run(vec![]);
    let emitting = run(vec![emitted(0), emitted(1)]);

    assert_eq!(
        borsh::to_vec(&silent).unwrap(),
        borsh::to_vec(&emitting).unwrap(),
        "event emission must not perturb state"
    );
}

#[test]
fn example_event_selector_matches_its_derivation() {
    use sha2::Digest as _;

    let digest = sha2::Sha256::digest(ExampleEvent::SELECTOR_NAME.as_bytes());

    assert_eq!(&ExampleEvent::SELECTOR[..], &digest[..8]);
}

#[test]
fn events_are_filterable_by_selector_and_decodable() {
    let mut state = V03State::new().with_programs([crate::test_methods::scripted()]);
    let emitter_id = scripted_id();

    let example = ExampleEvent {
        account: AccountId::new([7; 32]),
        amount: 42,
    };
    let tx = emitter_transaction(emitting(vec![
        emitted(0),
        ProgramEvent {
            selector: ExampleEvent::SELECTOR,
            data: example.to_bytes(),
        },
        emitted(1),
    ]));

    let events = state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    let matched: Vec<_> = events
        .iter()
        .filter(|event| event.event.selector == ExampleEvent::SELECTOR)
        .collect();
    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0].account_id, emitter_id);
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
    let emitter = crate::test_methods::scripted();
    let account_id =
        AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), Identifier::ZERO);

    let (output, proof) = execute_and_prove(
        ProvingInput {
            private_witnesses: vec![init_witness(&keys, Identifier::ZERO)],
            ..proving_input(root(
                Actor::new(account_id, scripted_id()),
                &emitting(vec![emitted(0), emitted(1)]),
            ))
        },
        &Simulation::default(),
        &synthetic_program(emitter.clone()),
    )
    .expect("emitting guest must prove on the private path");

    assert_eq!(output.private_actions.len(), 1);

    let tx = private_tx((output, proof), vec![], &[]);

    let mut state = V03State::new();
    state.insert_program(&emitter, true);

    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .unwrap();
}
