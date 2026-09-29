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
        events,
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
