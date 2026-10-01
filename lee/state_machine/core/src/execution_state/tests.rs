use super::{
    ScheduleOp::{CallPublic, EnterPrivate, LeavePrivate, Publish, ReturnPublic},
    *,
};
use crate::{
    AuthorizationSecretKey, Identifier,
    encryption::ViewingPublicKey,
    native_token,
    program::{Call, Cast, Response},
};

const ENTRY: Actor = Actor::new(AccountId::new([1; 32]), AccountId::new([9; 32]));
const CALLEE: Actor = Actor::new(AccountId::new([2; 32]), AccountId::new([9; 32]));
const BYSTANDER: Actor = Actor::new(AccountId::new([3; 32]), AccountId::new([9; 32]));
const ENTER: &[u8] = b"enter";

type Handler = Box<dyn FnMut(&ReceiveInput) -> Transition>;
type Settled = (
    Vec<(AccountId, AccountData)>,
    Vec<(Actor, ProgramEvent)>,
    Vec<MessageBody>,
);

struct Keys {
    ask: AuthorizationSecretKey,
    vpk: ViewingPublicKey,
}

impl Keys {
    fn new(tag: u8) -> Self {
        Self {
            ask: AuthorizationSecretKey([tag; 32]),
            vpk: ViewingPublicKey::from_seed(&[tag; 32], &[tag; 32]),
        }
    }

    fn nsk(&self) -> NullifierSecretKey {
        NullifierSecretKey::from(&self.ask)
    }

    fn npk(&self) -> NullifierPublicKey {
        NullifierPublicKey::from(&self.nsk())
    }

    fn regular_id(&self) -> AccountId {
        AccountId::for_regular_private_account(&self.npk(), &self.vpk, Identifier::ZERO)
    }

    fn pda_id(&self, program: AccountId, seed: PdaSeed) -> AccountId {
        AccountId::for_private_pda(&program, &seed, &self.npk(), &self.vpk, Identifier::ZERO)
    }

    fn witness(&self, kind: WitnessKind) -> PrivateWitness {
        PrivateWitness {
            vpk: self.vpk.clone(),
            random_seed: [0; 32],
            identifier: Identifier::ZERO,
            kind,
            nullifier: NullifierWitness::Init {
                npk: self.npk(),
                commitment_root: [8; 32],
            },
        }
    }

    fn regular(&self, ask: bool) -> PrivateWitness {
        self.witness(WitnessKind::Regular {
            ask: ask.then_some(self.ask),
        })
    }

    fn pda(&self, program: AccountId, seed: PdaSeed) -> PrivateWitness {
        self.witness(WitnessKind::Pda {
            binding: (program, seed),
        })
    }
}

#[derive(Default)]
struct Script {
    handlers: HashMap<Actor, Handler>,
    shards: HashMap<Actor, ShardData>,
    log: Vec<ReceiveInput>,
}

impl Script {
    fn on(
        mut self,
        receiver: Actor,
        handler: impl FnMut(&ReceiveInput) -> Transition + 'static,
    ) -> Self {
        self.shards.entry(receiver).or_insert_with(ShardData::empty);
        self.handlers.insert(receiver, Box::new(handler));
        self
    }

    fn shard(mut self, receiver: Actor, bytes: &[u8]) -> Self {
        self.shards.insert(receiver, data(bytes));
        self
    }
}

impl Backend for Script {
    type Error = ExecutionError;

    fn receive(
        &mut self,
        input: &ReceiveInput,
        _execution: &ExecutionState<'_>,
    ) -> Result<Transition, ExecutionError> {
        self.log.push(input.clone());
        let handler = self
            .handlers
            .get_mut(&input.receiver)
            .unwrap_or_else(|| panic!("no handler for {:?}", input.receiver));
        Ok(handler(input))
    }

    fn public_shard(&mut self, actor: Actor) -> Result<ShardData, ExecutionError> {
        self.shards
            .get(&actor)
            .cloned()
            .ok_or(ExecutionError::PublicShardUnavailable { actor })
    }
}

fn id(tag: u8) -> AccountId {
    AccountId::new([tag; 32])
}

fn actor(account: u8, program: u8) -> Actor {
    Actor::new(id(account), id(program))
}

fn holder(keys: &Keys) -> Actor {
    Actor::new(keys.regular_id(), id(8))
}

fn data(bytes: &[u8]) -> ShardData {
    bytes.to_vec().try_into().unwrap()
}

fn send_to(receiver: Actor) -> Call {
    Call {
        to: receiver,
        message: Vec::new(),
        pda_seeds: Vec::new(),
    }
}

// The private holder of `Keys::new(1)`, entered from a public turn.
fn enter(message: &[u8]) -> Call {
    Call {
        to: holder(&Keys::new(1)),
        message: message.to_vec(),
        pda_seeds: Vec::new(),
    }
}

fn output(to: Actor, origin: Origin) -> Output {
    Output {
        to,
        message: Vec::new(),
        origin,
        issuer: match origin {
            Origin::Root => None,
            Origin::Program(program) => Some(program),
        },
        grants: Vec::new(),
        pda_seeds: Vec::new(),
    }
}

fn echo(input: &ReceiveInput, response: Response) -> Transition {
    response.into_transition(input.clone())
}

fn sending(calls: Vec<Call>) -> impl Fn(&ReceiveInput) -> Transition {
    move |input| {
        echo(
            input,
            calls.iter().cloned().fold(Response::keep(), Response::send),
        )
    }
}

fn sending_when(origin: Origin, calls: Vec<Call>) -> impl Fn(&ReceiveInput) -> Transition {
    let send = sending(calls);
    move |input| {
        if input.origin == origin {
            send(input)
        } else {
            echo(input, Response::keep())
        }
    }
}

fn root(to: Actor) -> TransactionEntry<StoredMessage> {
    TransactionEntry::Call {
        to,
        message: Vec::new(),
    }
}

fn live(to: Actor) -> Mode {
    Mode::Live(root(to))
}

fn declared(public_actors: Vec<Actor>) -> Declared {
    Declared {
        public_actors,
        authorized_accounts: Vec::new(),
    }
}

fn run(
    declared_actors: Declared,
    witnesses: &[PrivateWitness],
    mode: Mode,
    script: &mut Script,
) -> Result<ExecutionOutcome, ExecutionError> {
    ExecutionState::initialize(declared_actors, witnesses, mode)?.run(script)
}

fn order(script: &Script) -> Vec<(Actor, Origin)> {
    script
        .log
        .iter()
        .map(|input| (input.receiver, input.origin))
        .collect()
}

fn authorized(script: &Script) -> Vec<(Actor, bool)> {
    script
        .log
        .iter()
        .map(|input| (input.receiver, input.is_authorized))
        .collect()
}

fn seeded_to(to: Actor, seed: PdaSeed) -> Call {
    Call {
        pda_seeds: vec![seed],
        ..send_to(to)
    }
}

fn public_pda(program: AccountId, seed: PdaSeed) -> Actor {
    Actor::new(AccountId::for_public_pda(&program, &seed), program)
}

fn stored(origin_program: AccountId, to: Actor, message: &[u8]) -> StoredMessage {
    StoredMessage {
        sequence: 0,
        body: MessageBody {
            origin_program,
            to,
            message: message.to_vec(),
        },
    }
}

// A statement whose only public call is the root delivery to `ENTRY`.
fn root_statement() -> Boundary {
    Boundary {
        outputs: vec![output(ENTRY, Origin::Root)],
        schedule: vec![CallPublic, ReturnPublic],
        ..Boundary::default()
    }
}

// `ENTRY` enters the private holder, whose turn calls `CALLEE`.
fn nested_assumed() -> Vec<Vec<Assumption>> {
    vec![
        vec![Assumption {
            from: ENTRY,
            to: holder(&Keys::new(1)),
            message: ENTER.to_vec(),
            grants: Vec::new(),
            pda_seeds: Vec::new(),
        }],
        Vec::new(),
    ]
}

fn nested_private() -> Script {
    Script::default().on(holder(&Keys::new(1)), sending(vec![send_to(CALLEE)]))
}

fn nested_public(script: Script, entry_sends: Vec<Call>) -> Script {
    script
        .on(ENTRY, sending(entry_sends))
        .on(CALLEE, sending(Vec::new()))
        .on(BYSTANDER, sending(Vec::new()))
}

fn recorded_boundary(outcome: ExecutionOutcome) -> Boundary {
    let ExecutionResult::Recorded { boundary, .. } = outcome.result else {
        panic!("expected a recorded execution")
    };
    boundary
}

fn settled(outcome: ExecutionOutcome) -> Settled {
    let ExecutionResult::Settled {
        public,
        events,
        casts,
    } = outcome.result
    else {
        panic!("expected a settled execution")
    };
    (public, events, casts)
}

fn record_nested(assumed: Vec<Vec<Assumption>>) -> (Boundary, Script) {
    let mut script = nested_private();
    let outcome = run(
        declared(vec![ENTRY, CALLEE, BYSTANDER]),
        &[Keys::new(1).regular(false)],
        Mode::Record {
            root: root(ENTRY),
            assumed,
        },
        &mut script,
    )
    .unwrap();
    (recorded_boundary(outcome), script)
}

fn check_nested(
    boundary: Boundary,
    entry_sends: Vec<Call>,
) -> (Result<ExecutionOutcome, ExecutionError>, Script) {
    let mut script = nested_public(Script::default(), entry_sends);
    let result = run(
        declared(vec![ENTRY, CALLEE, BYSTANDER]),
        &[],
        Mode::Check(boundary),
        &mut script,
    );
    (result, script)
}

#[test]
fn a_root_delivery_stages_its_write_and_reports_its_events() {
    let receiver = actor(1, 9);
    let event = ProgramEvent {
        selector: [7; 8],
        data: vec![1],
    };
    let emitted = event.clone();
    let mut script = Script::default()
        .shard(receiver, b"old")
        .on(receiver, move |input| {
            echo(
                input,
                Response::write(b"new".to_vec()).event(emitted.clone()),
            )
        });

    let (public, events, _) =
        settled(run(declared(vec![receiver]), &[], live(receiver), &mut script).unwrap());

    assert_eq!(
        public,
        vec![(
            receiver.account_id,
            AccountData::default().with_shard(receiver.program_account_id, data(b"new"))
        )]
    );
    assert_eq!(events, vec![(receiver, event)]);
}

#[test]
fn sends_run_depth_first_with_each_senders_program_as_origin() {
    let (parent, first, second, nested) = (actor(1, 9), actor(2, 7), actor(3, 9), actor(4, 9));
    let mut script = Script::default()
        .on(parent, sending(vec![send_to(first), send_to(second)]))
        .on(first, sending(vec![send_to(nested)]))
        .on(second, sending(Vec::new()))
        .on(nested, sending(Vec::new()));

    run(
        declared(vec![parent, first, second, nested]),
        &[],
        live(parent),
        &mut script,
    )
    .unwrap();

    assert_eq!(
        order(&script),
        vec![
            (parent, Origin::Root),
            (first, Origin::Program(id(9))),
            (nested, Origin::Program(id(7))),
            (second, Origin::Program(id(9))),
        ]
    );
}

#[test]
fn a_send_to_an_undeclared_actor_is_rejected() {
    let (parent, stranger, sibling) = (actor(1, 9), actor(2, 9), actor(3, 9));
    let mut script = Script::default()
        .on(parent, sending(vec![send_to(stranger), send_to(sibling)]))
        .on(sibling, sending(Vec::new()));

    let result = run(
        declared(vec![parent, sibling]),
        &[],
        live(parent),
        &mut script,
    );

    assert!(matches!(
        result,
        Err(ExecutionError::UndeclaredActor { actor: rejected }) if rejected == stranger
    ));
    assert_eq!(order(&script), vec![(parent, Origin::Root)]);
}

#[test]
fn a_transition_that_forges_its_input_is_rejected() {
    let receiver = actor(1, 9);
    let mut script = Script::default().on(receiver, |input| {
        Response::keep().into_transition(ReceiveInput {
            message: b"forged".to_vec(),
            ..input.clone()
        })
    });

    assert!(matches!(
        run(declared(vec![receiver]), &[], live(receiver), &mut script),
        Err(ExecutionError::ExecutionValidation {
            source: ExecutionValidationError::TransitionInputMismatch { .. },
            ..
        })
    ));
}

#[test]
fn a_revisited_actor_sees_its_staged_write() {
    let looping = actor(1, 9);
    let mut script = Script::default().on(looping, move |input| {
        if input.pre_data.is_empty() {
            echo(input, Response::write(b"x".to_vec()).send(send_to(looping)))
        } else {
            echo(input, Response::keep())
        }
    });

    run(declared(vec![looping]), &[], live(looping), &mut script).unwrap();

    let seen: Vec<_> = script
        .log
        .iter()
        .map(|input| (input.pre_data.clone(), input.receiver))
        .collect();
    assert_eq!(
        seen,
        vec![(ShardData::empty(), looping), (data(b"x"), looping)]
    );
}

#[test]
fn a_seed_grants_its_pda_and_the_grant_is_inherited_downstream() {
    let (owner, forwarder, relay) = (actor(1, 9), actor(2, 7), actor(3, 8));
    let seed = PdaSeed::new([5; 32]);
    let vault = Actor::new(
        AccountId::for_public_pda(&owner.program_account_id, &seed),
        owner.program_account_id,
    );
    let seeded = Call {
        pda_seeds: vec![seed],
        ..send_to(vault)
    };
    let mut script = Script::default()
        .on(owner, sending(vec![seeded, send_to(forwarder)]))
        .on(
            vault,
            sending_when(Origin::Program(id(9)), vec![send_to(relay)]),
        )
        .on(relay, sending(vec![send_to(vault)]))
        .on(forwarder, sending(vec![send_to(vault)]));

    run(
        declared(vec![owner, forwarder, relay, vault]),
        &[],
        live(owner),
        &mut script,
    )
    .unwrap();

    assert_eq!(
        authorized(&script),
        vec![
            (owner, false),
            (vault, true),
            (relay, false),
            (vault, true),
            (forwarder, false),
            (vault, false),
        ]
    );
}

#[test]
fn a_root_authorized_public_account_is_authorized_from_any_origin() {
    let (signer, peer) = (actor(1, 9), actor(2, 9));
    let mut script = Script::default()
        .on(signer, sending_when(Origin::Root, vec![send_to(peer)]))
        .on(peer, sending(vec![send_to(signer)]));

    run(
        Declared {
            public_actors: vec![signer, peer],
            authorized_accounts: vec![signer.account_id],
        },
        &[],
        live(signer),
        &mut script,
    )
    .unwrap();

    assert_eq!(
        authorized(&script),
        vec![(signer, true), (peer, false), (signer, true)]
    );
}

#[test]
fn turn_windows_intersect_and_disjoint_ones_are_rejected() {
    let (outer, inner) = (actor(1, 9), actor(2, 9));
    let windowed = |inner_window: std::ops::Range<u64>| {
        Script::default()
            .on(outer, move |input| {
                echo(
                    input,
                    Response::keep()
                        .try_block_window(1_u64..10)
                        .unwrap()
                        .send(send_to(inner)),
                )
            })
            .on(inner, move |input| {
                echo(
                    input,
                    Response::keep()
                        .try_block_window(inner_window.clone())
                        .unwrap(),
                )
            })
    };
    let execute = |script: &mut Script| run(declared(vec![outer, inner]), &[], live(outer), script);

    let outcome = execute(&mut windowed(5..20)).unwrap();

    assert_eq!(
        outcome.block_validity_window,
        BlockValidityWindow::try_from(5..10).unwrap()
    );
    assert!(matches!(
        execute(&mut windowed(10..20)),
        Err(ExecutionError::EmptyBlockWindowIntersection)
    ));
}

#[test]
fn a_long_self_send_chain_completes() {
    let revisited = actor(1, 9);
    let mut remaining = 128_u32;
    let mut script = Script::default().on(revisited, move |input| {
        let response = if remaining == 0 {
            Response::keep()
        } else {
            remaining = remaining.saturating_sub(1);
            Response::keep().send(send_to(revisited))
        };
        echo(input, response)
    });

    run(declared(vec![revisited]), &[], live(revisited), &mut script).unwrap();
    assert_eq!(script.log.len(), 129);
}

#[test]
fn a_public_shard_is_fetched_once_and_a_cleared_shard_is_reported_empty() {
    let clearing = actor(1, 9);
    let mut script = Script::default()
        .shard(clearing, b"orig")
        .on(clearing, move |input| {
            if input.pre_data.is_empty() {
                echo(input, Response::keep())
            } else {
                echo(input, Response::write(Vec::new()).send(send_to(clearing)))
            }
        });

    let (public, _, _) =
        settled(run(declared(vec![clearing]), &[], live(clearing), &mut script).unwrap());

    let seen: Vec<_> = script
        .log
        .iter()
        .map(|input| input.pre_data.clone())
        .collect();
    assert_eq!(seen, vec![data(b"orig"), ShardData::empty()]);
    assert_eq!(script.shards[&clearing], data(b"orig"));
    assert_eq!(
        public,
        vec![(
            clearing.account_id,
            AccountData {
                shards: [(clearing.program_account_id, ShardData::empty())].into(),
            }
        )]
    );
}

#[test]
fn a_live_execution_runs_nothing_privately() {
    let keys = Keys::new(1);
    assert!(matches!(
        run(
            Declared::default(),
            &[keys.regular(true)],
            live(holder(&keys)),
            &mut Script::default()
        ),
        Err(ExecutionError::UndeclaredActor { actor }) if actor == holder(&keys)
    ));
}

#[test]
fn a_private_root_records_its_public_call_and_the_assumed_reply() {
    let keys = Keys::new(1);
    let owner = holder(&keys);
    let vault = actor(2, 9);
    let credit = Call {
        to: vault,
        message: b"credit".to_vec(),
        pda_seeds: Vec::new(),
    };
    let reply = Assumption {
        from: vault,
        to: owner,
        message: b"credit".to_vec(),
        grants: Vec::new(),
        pda_seeds: Vec::new(),
    };
    let event = ProgramEvent {
        selector: [7; 8],
        data: Vec::new(),
    };
    let mut script = Script::default().on(owner, move |input| {
        if input.origin == Origin::Root {
            echo(
                input,
                Response::write(b"first".to_vec()).send(credit.clone()),
            )
        } else {
            echo(
                input,
                Response::write(b"second".to_vec()).event(event.clone()),
            )
        }
    });

    let ExecutionResult::Recorded {
        private_accounts,
        boundary,
    } = run(
        declared(vec![vault]),
        &[keys.regular(true)],
        Mode::Record {
            root: root(owner),
            assumed: vec![vec![reply.clone()]],
        },
        &mut script,
    )
    .unwrap()
    .result
    else {
        panic!("expected a recorded execution")
    };

    assert_eq!(
        order(&script),
        vec![(owner, Origin::Root), (owner, Origin::Program(id(9)))]
    );
    assert_eq!(
        boundary,
        Boundary {
            outputs: vec![Output {
                message: b"credit".to_vec(),
                ..output(vault, Origin::Program(id(8)))
            }],
            assumptions: vec![reply],
            publications: Vec::new(),
            schedule: vec![CallPublic, EnterPrivate, LeavePrivate, ReturnPublic],
        }
    );
    assert_eq!(
        private_accounts[&owner.account_id],
        AccountData::default().with_shard(owner.program_account_id, data(b"second"))
    );
}

#[test]
fn a_public_call_made_inside_an_assumed_delivery_is_bracketed_within_it() {
    let (boundary, script) = record_nested(nested_assumed());

    assert_eq!(
        boundary.schedule,
        vec![
            CallPublic,
            EnterPrivate,
            CallPublic,
            ReturnPublic,
            LeavePrivate,
            ReturnPublic,
        ]
    );
    assert_eq!(
        boundary.outputs,
        vec![
            output(ENTRY, Origin::Root),
            output(CALLEE, Origin::Program(id(8))),
        ]
    );
    assert_eq!(
        order(&script),
        vec![(holder(&Keys::new(1)), Origin::Program(id(9)))]
    );
}

#[test]
fn assumed_deliveries_must_match_the_recorded_outputs() {
    let keys = Keys::new(1);
    let vault = actor(2, 9);
    let stranger = actor(5, 9);
    let record = |assumed: Vec<Vec<Assumption>>| {
        let mut script = Script::default().on(holder(&keys), sending(vec![send_to(vault)]));
        run(
            declared(vec![vault]),
            &[keys.regular(false)],
            Mode::Record {
                root: root(holder(&keys)),
                assumed,
            },
            &mut script,
        )
    };
    let reply = Assumption {
        from: stranger,
        to: holder(&keys),
        message: Vec::new(),
        grants: Vec::new(),
        pda_seeds: Vec::new(),
    };

    assert!(matches!(
        record(Vec::new()),
        Err(ExecutionError::MissingAssumedDeliveries { output: 0 })
    ));
    assert!(matches!(
        record(vec![Vec::new(), Vec::new()]),
        Err(ExecutionError::UnusedAssumedDeliveries)
    ));
    assert!(matches!(
        record(vec![vec![reply]]),
        Err(ExecutionError::UndeclaredAssumedSender { actor: sender }) if sender == stranger
    ));
}

#[test]
fn a_private_credential_holds_from_any_origin_beside_a_seed_grant() {
    let keys = Keys::new(1);
    let owner = holder(&keys);
    let vault = actor(2, 9);
    let seed = PdaSeed::new([5; 32]);
    let custody = Actor::new(keys.pda_id(vault.program_account_id, seed), id(8));
    let mut script = Script::default()
        .on(owner, sending_when(Origin::Root, vec![send_to(vault)]))
        .on(custody, sending(Vec::new()));
    let assumed = vec![vec![
        Assumption {
            from: vault,
            to: owner,
            message: Vec::new(),
            grants: Vec::new(),
            pda_seeds: Vec::new(),
        },
        Assumption {
            from: vault,
            to: custody,
            message: Vec::new(),
            grants: Vec::new(),
            pda_seeds: vec![seed],
        },
    ]];

    run(
        declared(vec![vault]),
        &[keys.regular(true), keys.pda(vault.program_account_id, seed)],
        Mode::Record {
            root: root(owner),
            assumed,
        },
        &mut script,
    )
    .unwrap();

    assert_eq!(
        authorized(&script),
        vec![(owner, true), (owner, true), (custody, true)]
    );
}

#[test]
fn a_check_replays_the_public_side_of_a_recorded_statement() {
    let (boundary, _) = record_nested(nested_assumed());

    let (result, script) = check_nested(boundary, vec![enter(ENTER), send_to(BYSTANDER)]);

    assert!(result.is_ok());
    assert_eq!(
        order(&script),
        vec![
            (ENTRY, Origin::Root),
            (CALLEE, Origin::Program(id(8))),
            (BYSTANDER, Origin::Program(id(9))),
        ]
    );
}

#[test]
fn a_check_rejects_public_behaviour_that_departs_from_the_statement() {
    let boundary = record_nested(nested_assumed()).0;
    let checked = |sends: Vec<Call>| check_nested(boundary.clone(), sends).0;
    let truncated = Boundary {
        schedule: vec![CallPublic],
        ..boundary.clone()
    };

    assert!(matches!(
        checked(vec![send_to(BYSTANDER)]),
        Err(ExecutionError::ScheduleMismatch {
            index: 1,
            expected: ReturnPublic
        })
    ));
    assert!(matches!(
        checked(vec![enter(b"other")]),
        Err(ExecutionError::AssumptionMismatch { index: 0 })
    ));
    assert!(matches!(
        checked(vec![enter(ENTER), enter(ENTER)]),
        Err(ExecutionError::ScheduleMismatch {
            index: 5,
            expected: EnterPrivate
        })
    ));
    assert!(matches!(
        check_nested(truncated, vec![enter(ENTER), send_to(BYSTANDER)]).0,
        Err(ExecutionError::ScheduleMismatch {
            index: 1,
            expected: EnterPrivate
        })
    ));
}

#[test]
fn a_check_runs_a_privately_originated_call_with_its_private_origin() {
    let origin = Origin::Program(id(8));
    let boundary = Boundary {
        outputs: vec![output(ENTRY, origin)],
        schedule: vec![CallPublic, ReturnPublic],
        ..Boundary::default()
    };

    let (result, script) = check_nested(boundary, Vec::new());

    assert!(result.is_ok());
    assert_eq!(order(&script), vec![(ENTRY, origin)]);
}

#[test]
fn initialization_rejects_inconsistent_declarations() {
    let keys = Keys::new(1);
    let owned = holder(&keys);
    let public_actor = actor(2, 9);
    let private_witnesses = [keys.regular(false)];
    let init = |public_actors: Vec<Actor>, witnesses: &[PrivateWitness]| {
        ExecutionState::initialize(declared(public_actors), witnesses, live(public_actor)).err()
    };

    assert!(matches!(
        init(vec![Actor::new(owned.account_id, id(9))], &private_witnesses),
        Some(ExecutionError::PublicAndPrivate { account_id }) if account_id == owned.account_id
    ));
    assert!(matches!(
        init(vec![public_actor, public_actor], &[]),
        Some(ExecutionError::DuplicatePublicActor { actor: repeated }) if repeated == public_actor
    ));
}

#[test]
fn a_check_whose_live_subtree_reaches_the_loader_fails() {
    let loader = Actor::new(id(4), PROGRAM_LOADER_ACCOUNT_ID);
    let mut script = Script::default()
        .on(ENTRY, sending(vec![send_to(loader)]))
        .on(loader, sending(Vec::new()));

    let result = run(
        declared(vec![ENTRY, loader]),
        &[],
        Mode::Check(root_statement()),
        &mut script,
    );

    assert!(matches!(
        result,
        Err(ExecutionError::LoaderOutsideLiveExecution { actor }) if actor == loader
    ));
    assert_eq!(order(&script), vec![(ENTRY, Origin::Root)]);
}

#[test]
fn a_record_refuses_an_explicit_delivery_to_the_loader() {
    let keys = Keys::new(1);
    let loader = Actor::new(id(4), PROGRAM_LOADER_ACCOUNT_ID);
    let mut script = Script::default().on(holder(&keys), sending(vec![send_to(loader)]));

    let result = run(
        declared(vec![loader]),
        &[keys.regular(false)],
        Mode::Record {
            root: root(holder(&keys)),
            assumed: vec![Vec::new()],
        },
        &mut script,
    );

    assert!(matches!(
        result,
        Err(ExecutionError::LoaderOutsideLiveExecution { actor }) if actor == loader
    ));
    assert_eq!(order(&script), vec![(holder(&keys), Origin::Root)]);
}

// The public owner seeds two PDAs; the first enters the private relay, whose call back to it
// carries its grant. `assumed_grants` is what the proof claims the relay received.
fn relayed_grant(
    assumed_grants: Vec<AccountId>,
) -> (Result<ExecutionOutcome, ExecutionError>, Script) {
    let keys = Keys::new(1);
    let relay = holder(&keys);
    let owner = ENTRY;
    let (seed, sibling_seed) = (PdaSeed::new([5; 32]), PdaSeed::new([6; 32]));
    let vault = public_pda(owner.program_account_id, seed);
    let sibling = public_pda(owner.program_account_id, sibling_seed);
    let actors = vec![owner, sibling, vault];

    let mut recording = Script::default().on(relay, sending(vec![send_to(vault)]));
    let recorded = run(
        declared(actors.clone()),
        &[keys.regular(false)],
        Mode::Record {
            root: root(owner),
            assumed: vec![
                vec![Assumption {
                    from: vault,
                    to: relay,
                    message: ENTER.to_vec(),
                    grants: assumed_grants,
                    pda_seeds: Vec::new(),
                }],
                Vec::new(),
            ],
        },
        &mut recording,
    )
    .unwrap();

    let mut checking = Script::default()
        .on(
            owner,
            sending(vec![
                seeded_to(vault, seed),
                seeded_to(sibling, sibling_seed),
            ]),
        )
        .on(sibling, sending(Vec::new()))
        .on(
            vault,
            sending_when(Origin::Program(id(9)), vec![enter(ENTER)]),
        );
    let result = run(
        declared(actors),
        &[],
        Mode::Check(recorded_boundary(recorded)),
        &mut checking,
    );
    (result, checking)
}

#[test]
fn a_public_grant_crosses_a_private_relay_and_authorizes_the_reply() {
    let vault = public_pda(ENTRY.program_account_id, PdaSeed::new([5; 32]));
    let sibling = public_pda(ENTRY.program_account_id, PdaSeed::new([6; 32]));

    let (result, script) = relayed_grant(vec![vault.account_id]);

    assert!(result.is_ok());
    assert_eq!(
        authorized(&script),
        vec![
            (ENTRY, false),
            (vault, true),
            (vault, true),
            (sibling, true)
        ]
    );
}

#[test]
fn an_assumption_must_claim_exactly_the_delivered_grants() {
    let sibling = public_pda(ENTRY.program_account_id, PdaSeed::new([6; 32]));

    for claimed in [vec![sibling.account_id], Vec::new()] {
        assert!(matches!(
            relayed_grant(claimed).0,
            Err(ExecutionError::AssumptionMismatch { index: 0 })
        ));
    }
}

#[test]
fn a_private_grant_crosses_a_public_actor_and_authorizes_the_return() {
    let (keys, pda_keys) = (Keys::new(1), Keys::new(2));
    let owner = holder(&keys);
    let seed = PdaSeed::new([5; 32]);
    let custody = Actor::new(pda_keys.pda_id(owner.program_account_id, seed), id(8));
    let peer = actor(3, 9);
    let peer_vault = public_pda(peer.program_account_id, seed);
    let mut recording = Script::default()
        .on(owner, sending(vec![seeded_to(custody, seed)]))
        .on(
            custody,
            sending_when(Origin::Program(id(8)), vec![send_to(peer)]),
        );

    let recorded = run(
        declared(vec![peer, peer_vault]),
        &[
            keys.regular(false),
            pda_keys.pda(owner.program_account_id, seed),
        ],
        Mode::Record {
            root: root(owner),
            assumed: vec![vec![Assumption {
                from: peer,
                to: custody,
                message: Vec::new(),
                grants: vec![custody.account_id],
                pda_seeds: Vec::new(),
            }]],
        },
        &mut recording,
    )
    .unwrap();

    assert_eq!(
        authorized(&recording),
        vec![(owner, false), (custody, true), (custody, true)]
    );
    let boundary = recorded_boundary(recorded);
    assert_eq!(boundary.outputs[0].grants, vec![custody.account_id]);

    let mut checking = Script::default()
        .on(
            peer,
            sending(vec![send_to(custody), seeded_to(peer_vault, seed)]),
        )
        .on(peer_vault, sending(Vec::new()));
    assert!(
        run(
            declared(vec![peer, peer_vault]),
            &[],
            Mode::Check(boundary),
            &mut checking,
        )
        .is_ok()
    );
    assert_eq!(
        authorized(&checking),
        vec![(peer, false), (peer_vault, true)]
    );
}

#[test]
fn a_private_pda_family_cannot_declare_its_public_member() {
    let keys = Keys::new(1);
    let (program, seed) = (id(8), PdaSeed::new([5; 32]));
    let custody = Actor::new(keys.pda_id(program, seed), program);
    let public_member = Actor::new(AccountId::for_public_pda(&program, &seed), id(9));
    let witnesses = [keys.pda(program, seed)];

    let result = ExecutionState::initialize(
        declared(vec![public_member]),
        &witnesses,
        Mode::Record {
            root: root(custody),
            assumed: Vec::new(),
        },
    );

    assert!(matches!(
        result.err(),
        Some(ExecutionError::PublicFamilyMemberDeclared { account_id })
            if account_id == public_member.account_id
    ));
}

#[test]
fn a_check_publishes_live_events() {
    let event = ProgramEvent {
        selector: [7; 8],
        data: Vec::new(),
    };
    let emitted = event.clone();
    let mut checking = Script::default().on(ENTRY, move |input| {
        echo(input, Response::keep().event(emitted.clone()))
    });

    let (_, events, _) = settled(
        run(
            declared(vec![ENTRY]),
            &[],
            Mode::Check(root_statement()),
            &mut checking,
        )
        .unwrap(),
    );

    assert_eq!(events, vec![(ENTRY, event)]);
}

// A public turn asks a private account's native balance to pay: the private turn runs under the
// account's own credential, and without it the debit is refused.
#[test]
fn a_public_turn_requests_a_private_debit_that_the_private_credential_authorizes() {
    let keys = Keys::new(1);
    let (requester, payee) = (actor(2, 9), Actor::native_balance(id(3)));
    let payer = Actor::native_balance(keys.regular_id());
    let record = |credential: bool| {
        let mut script = Script::default().on(payer, |input| {
            native_token::receive(input).unwrap_or_else(|error| panic!("{error}"))
        });
        run(
            declared(vec![requester, payee]),
            &[keys.regular(credential)],
            Mode::Record {
                root: root(requester),
                assumed: vec![
                    vec![Assumption {
                        from: requester,
                        to: payer,
                        message: borsh::to_vec(&native_token::Message::Transfer {
                            to: payee.account_id,
                            amount: 0,
                            expect_balance: None,
                        })
                        .unwrap(),
                        grants: Vec::new(),
                        pda_seeds: Vec::new(),
                    }],
                    Vec::new(),
                ],
            },
            &mut script,
        )
    };

    assert_eq!(
        recorded_boundary(record(true).unwrap()).outputs[1],
        Output {
            message: borsh::to_vec(&native_token::Message::Credit(0)).unwrap(),
            ..output(
                payee,
                Origin::Program(native_token::NATIVE_TOKEN_PROGRAM_ID)
            )
        }
    );
    let Err(refused) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| record(false)))
    else {
        panic!("a debit without the payer's credential must not prove");
    };
    assert!(
        refused
            .downcast_ref::<String>()
            .is_some_and(|message| message.contains("is not authorized"))
    );
}

#[test]
fn an_undeclared_actor_of_a_declared_public_account_is_refused() {
    let keys = Keys::new(1);
    let owner = holder(&keys);
    let stray = Actor::new(ENTRY.account_id, id(7));

    let mut recording = Script::default().on(owner, sending(vec![send_to(stray)]));
    let recorded = run(
        declared(vec![ENTRY]),
        &[keys.regular(false)],
        Mode::Record {
            root: root(owner),
            assumed: Vec::new(),
        },
        &mut recording,
    );
    let mut checking = Script::default().on(ENTRY, sending(vec![send_to(stray)]));
    let checked = run(
        declared(vec![ENTRY]),
        &[],
        Mode::Check(root_statement()),
        &mut checking,
    );

    for result in [recorded, checked] {
        assert!(matches!(
            result,
            Err(ExecutionError::UndeclaredActor { actor }) if actor == stray
        ));
    }
}

#[test]
fn a_check_whose_live_subtree_makes_more_than_64_deliveries_succeeds() {
    let mut remaining = 100_u32;
    let mut script = Script::default().on(ENTRY, move |input| {
        let response = if remaining == 0 {
            Response::keep()
        } else {
            remaining = remaining.saturating_sub(1);
            Response::keep().send(send_to(ENTRY))
        };
        echo(input, response)
    });

    run(
        declared(vec![ENTRY]),
        &[],
        Mode::Check(root_statement()),
        &mut script,
    )
    .unwrap();
    assert_eq!(script.log.len(), 101);
}

#[test]
fn a_derived_statement_records_and_checks_a_nested_mixed_graph() {
    let entry_sends = vec![enter(ENTER), send_to(BYSTANDER)];
    let mut deriving = nested_public(nested_private(), entry_sends.clone());

    let ExecutionResult::Derived { assumed } = run(
        declared(vec![ENTRY, CALLEE, BYSTANDER]),
        &[Keys::new(1).regular(false)],
        Mode::Derive(root(ENTRY)),
        &mut deriving,
    )
    .unwrap()
    .result
    else {
        panic!("expected a derived execution")
    };

    assert_eq!(assumed, nested_assumed());
    let (boundary, _) = record_nested(assumed);
    assert!(check_nested(boundary, entry_sends).0.is_ok());
}

#[test]
fn an_output_from_a_private_sender_carries_only_its_programs_provenance() {
    let keys = Keys::new(1);
    let mut script = Script::default().on(holder(&keys), sending(vec![send_to(ENTRY)]));

    let recorded = run(
        declared(vec![ENTRY]),
        &[keys.regular(false)],
        Mode::Record {
            root: root(holder(&keys)),
            assumed: vec![Vec::new()],
        },
        &mut script,
    )
    .unwrap();

    assert_eq!(
        recorded_boundary(recorded).outputs,
        vec![output(
            ENTRY,
            Origin::Program(holder(&keys).program_account_id)
        )]
    );
}

#[test]
fn a_live_delivery_from_another_actor_of_the_same_program_does_not_satisfy_an_assumption() {
    let (boundary, _) = record_nested(nested_assumed());
    let mut script = nested_public(Script::default(), vec![send_to(BYSTANDER)])
        .on(BYSTANDER, sending(vec![enter(ENTER)]));
    assert_eq!(BYSTANDER.program_account_id, ENTRY.program_account_id);

    let result = run(
        declared(vec![ENTRY, CALLEE, BYSTANDER]),
        &[],
        Mode::Check(boundary),
        &mut script,
    );

    assert!(matches!(
        result,
        Err(ExecutionError::AssumptionMismatch { index: 0 })
    ));
}

#[test]
fn a_cast_is_published_after_the_subtree_of_the_call_before_it() {
    let (outer_target, inner_target) = (actor(6, 7), actor(7, 7));
    let mut script = Script::default()
        .on(ENTRY, move |input| {
            echo(
                input,
                Response::keep()
                    .send(send_to(CALLEE))
                    .send(Cast {
                        to: outer_target,
                        message: b"x".to_vec(),
                    })
                    .send(send_to(BYSTANDER)),
            )
        })
        .on(CALLEE, move |input| {
            echo(
                input,
                Response::keep().send(Cast {
                    to: inner_target,
                    message: b"y".to_vec(),
                }),
            )
        })
        .on(BYSTANDER, sending(Vec::new()));

    let (_, _, casts) = settled(
        run(
            declared(vec![ENTRY, CALLEE, BYSTANDER]),
            &[],
            live(ENTRY),
            &mut script,
        )
        .unwrap(),
    );

    assert_eq!(
        order(&script),
        vec![
            (ENTRY, Origin::Root),
            (CALLEE, Origin::Program(id(9))),
            (BYSTANDER, Origin::Program(id(9))),
        ]
    );
    assert_eq!(
        casts,
        vec![
            MessageBody {
                origin_program: id(9),
                to: inner_target,
                message: b"y".to_vec(),
            },
            MessageBody {
                origin_program: id(9),
                to: outer_target,
                message: b"x".to_vec(),
            },
        ]
    );
}

#[test]
fn a_receipt_root_delivers_its_stored_origin_and_message_and_its_origin_grants_nothing() {
    let vault = public_pda(id(5), PdaSeed::new([5; 32]));
    let record = stored(id(5), vault, b"stored");
    let mut script = Script::default().on(vault, sending(Vec::new()));

    run(
        declared(vec![vault]),
        &[],
        Mode::Live(TransactionEntry::Receive(record)),
        &mut script,
    )
    .unwrap();

    assert_eq!(
        script.log,
        vec![ReceiveInput {
            receiver: vault,
            origin: Origin::Program(id(5)),
            is_authorized: false,
            pre_data: ShardData::empty(),
            message: b"stored".to_vec(),
        }]
    );
}

#[test]
fn a_recorded_receipt_root_to_a_private_actor_runs_privately_with_its_stored_origin() {
    let keys = Keys::new(1);
    let record = stored(id(5), holder(&keys), b"stored");
    let mut script = Script::default().on(holder(&keys), sending(Vec::new()));

    let outcome = run(
        Declared::default(),
        &[keys.regular(false)],
        Mode::Record {
            root: TransactionEntry::Receive(record),
            assumed: Vec::new(),
        },
        &mut script,
    )
    .unwrap();

    assert_eq!(
        order(&script),
        vec![(holder(&keys), Origin::Program(id(5)))]
    );
    assert_eq!(recorded_boundary(outcome), Boundary::default());
}

#[test]
fn a_checked_private_cast_is_published_in_execution_order_with_the_live_casts() {
    let keys = Keys::new(1);
    let (private_target, public_target) = (actor(6, 7), actor(7, 7));
    let private_cast = MessageBody {
        origin_program: id(8),
        to: private_target,
        message: b"x".to_vec(),
    };
    let mut recording = Script::default().on(holder(&keys), move |input| {
        echo(
            input,
            Response::keep().send(send_to(ENTRY)).send(Cast {
                to: private_target,
                message: b"x".to_vec(),
            }),
        )
    });
    let boundary = recorded_boundary(
        run(
            declared(vec![ENTRY]),
            &[keys.regular(false)],
            Mode::Record {
                root: root(holder(&keys)),
                assumed: vec![Vec::new()],
            },
            &mut recording,
        )
        .unwrap(),
    );

    assert_eq!(boundary.schedule, vec![CallPublic, ReturnPublic, Publish]);
    assert_eq!(boundary.publications, vec![private_cast.clone()]);

    let mut checking = Script::default().on(ENTRY, move |input| {
        echo(
            input,
            Response::keep().send(Cast {
                to: public_target,
                message: b"y".to_vec(),
            }),
        )
    });
    let (_, _, casts) = settled(
        run(
            declared(vec![ENTRY]),
            &[],
            Mode::Check(boundary),
            &mut checking,
        )
        .unwrap(),
    );

    assert_eq!(
        casts,
        vec![
            MessageBody {
                origin_program: id(9),
                to: public_target,
                message: b"y".to_vec(),
            },
            private_cast,
        ]
    );
}

#[test]
fn a_check_rejects_a_publication_its_schedule_never_reaches() {
    let boundary = Boundary {
        publications: vec![MessageBody {
            origin_program: id(8),
            to: CALLEE,
            message: b"x".to_vec(),
        }],
        ..root_statement()
    };
    let mut script = Script::default().on(ENTRY, sending(Vec::new()));

    let result = run(
        declared(vec![ENTRY]),
        &[],
        Mode::Check(boundary),
        &mut script,
    );

    assert!(matches!(result, Err(ExecutionError::IncompleteBoundary)));
}
