use super::{
    BoundaryStep::{EndPrivateSubtree, EndPublicSubtree, PrivateToPublic, PublicToPrivate},
    *,
};
use crate::{
    AuthorizationSecretKey, NullifierPublicKey, NullifierSecretKey, NullifierWitness, RegularKey,
    WitnessKind,
    encryption::ViewingPublicKey,
    native_token,
    program::{BlockValidityWindow, Call, Cast, Response},
};

const ENTRY: Actor = Actor::new(AccountId::new([1; 32]), AccountId::new([9; 32]));
const CALLEE: Actor = Actor::new(AccountId::new([2; 32]), AccountId::new([9; 32]));
const BYSTANDER: Actor = Actor::new(AccountId::new([3; 32]), AccountId::new([9; 32]));
const ENTER: &[u8] = b"enter";
const GENERATED_DEPTH: u8 = 3;
const READ_BACK: u8 = u8::MAX;

type Handler = Box<dyn FnMut(&ReceiveInput) -> Transition>;

struct Rng(u64);

impl Rng {
    fn below(&mut self, bound: usize) -> usize {
        self.0 ^= self.0.wrapping_shl(13);
        self.0 ^= self.0.wrapping_shr(7);
        self.0 ^= self.0.wrapping_shl(17);
        usize::try_from(self.0.rem_euclid(u64::try_from(bound).unwrap())).unwrap()
    }
}

struct Graph {
    root: Actor,
    public: Vec<Actor>,
    keys: Vec<Keys>,
    calls: HashMap<(Actor, u8), Vec<Actor>>,
}

impl Graph {
    fn generate(seed: u64) -> Self {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let public: Vec<Actor> = (0..=rng.below(3))
            .map(|index| actor(20_u8.saturating_add(u8::try_from(index).unwrap()), 9))
            .collect();
        let keys: Vec<Keys> = (0..=rng.below(3))
            .map(|index| Keys::new(30_u8.saturating_add(u8::try_from(index).unwrap())))
            .collect();
        let actors = participants(&public, &keys);
        let mut calls = HashMap::new();
        for &receiver in &actors {
            for depth in 1..=GENERATED_DEPTH {
                let count = rng.below(3);
                let targets = std::iter::repeat_with(|| actors[rng.below(actors.len())])
                    .take(count)
                    .collect();
                calls.insert((receiver, depth), targets);
            }
        }
        Self {
            root: actors[rng.below(actors.len())],
            public,
            keys,
            calls,
        }
    }

    fn script(&self) -> Script {
        let actors = participants(&self.public, &self.keys);
        let mut script = Script::default();
        for &receiver in &actors {
            let (calls, read_back) = (self.calls.clone(), actors.clone());
            script = script.on(receiver, move |input| {
                let depth = input.message[0];
                if depth == READ_BACK {
                    return echo(input, Response::keep_state());
                }
                let next = depth.saturating_sub(1);
                let mut sends: Vec<Call> = calls
                    .get(&(receiver, depth))
                    .into_iter()
                    .flatten()
                    .map(|&to| Call {
                        message: vec![next],
                        ..send_to(to)
                    })
                    .collect();
                if depth == GENERATED_DEPTH {
                    sends.extend(read_back.iter().map(|&to| Call {
                        message: vec![READ_BACK],
                        ..send_to(to)
                    }));
                }
                let mut written = input.pre_state.to_vec();
                written.push(depth);
                echo(
                    input,
                    Response {
                        calls: sends,
                        ..Response::set_state(written)
                    },
                )
            });
        }
        script
    }
}

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
        AccountId::for_regular_private_account(&self.npk(), &self.vpk)
    }

    fn pda_id(&self, program: AccountId, seed: PdaSeed) -> AccountId {
        AccountId::for_private_pda(&program, &seed, &self.npk(), &self.vpk)
    }

    fn witness(&self, kind: WitnessKind) -> PrivateWitness {
        PrivateWitness {
            vpk: self.vpk.clone(),
            random_seed: [0; 32],
            kind,
            nullifier: NullifierWitness::Init {
                commitment_root: [8; 32],
            },
            openings: BTreeSet::new(),
        }
    }

    fn regular(&self, ask: bool) -> PrivateWitness {
        self.witness(WitnessKind::Regular(if ask {
            RegularKey::Authorized(self.ask)
        } else {
            RegularKey::Nullifying(self.nsk())
        }))
    }

    fn pda(&self, program: AccountId, seed: PdaSeed) -> PrivateWitness {
        self.witness(WitnessKind::Pda {
            nsk: self.nsk(),
            binding: (program, seed),
        })
    }
}

#[derive(Default)]
struct Script {
    handlers: HashMap<Actor, Handler>,
    actor_states: HashMap<Actor, ActorState>,
    log: Vec<ReceiveInput>,
    sender_presentations: Option<std::collections::VecDeque<SenderPresentation>>,
    public_promotions: BTreeSet<u64>,
    private_promotions: BTreeSet<u64>,
    refused: BTreeSet<AccountId>,
    offered: Vec<(Placement, u64, Actor)>,
}

impl Script {
    fn on(
        mut self,
        receiver: Actor,
        handler: impl FnMut(&ReceiveInput) -> Transition + 'static,
    ) -> Self {
        self.actor_states
            .entry(receiver)
            .or_insert_with(ActorState::empty);
        self.handlers.insert(receiver, Box::new(handler));
        self
    }

    fn actor_state(mut self, receiver: Actor, bytes: &[u8]) -> Self {
        self.actor_states.insert(receiver, data(bytes));
        self
    }

    fn presenting(
        mut self,
        sender_presentations: impl IntoIterator<Item = SenderPresentation>,
    ) -> Self {
        self.sender_presentations = Some(sender_presentations.into_iter().collect());
        self
    }

    fn promoting(mut self, placement: Placement, index: u64) -> Self {
        match placement {
            Placement::Public => self.public_promotions.insert(index),
            Placement::Private => self.private_promotions.insert(index),
        };
        self
    }

    fn refusing(mut self, actor: Actor) -> Self {
        self.refused.insert(actor.account_id);
        self
    }
}

impl ExecutionEnvironment for Script {
    type Error = ExecutionError;

    fn handle_message(
        &mut self,
        input: &ReceiveInput,
        _view: &TransitionView<'_>,
    ) -> Result<Transition, ExecutionError> {
        self.log.push(input.clone());
        let handler = self
            .handlers
            .get_mut(&input.receiver)
            .unwrap_or_else(|| panic!("no handler for {:?}", input.receiver));
        Ok(handler(input))
    }

    fn public_actor_state(&mut self, actor: Actor) -> Result<ActorState, ExecutionError> {
        self.actor_states
            .get(&actor)
            .cloned()
            .ok_or(ExecutionError::PublicActorStateUnavailable { actor })
    }

    fn present(&mut self, sender: Actor) -> Result<SenderPresentation, ExecutionError> {
        self.sender_presentations.as_mut().map_or(
            Ok(SenderPresentation::Canonical),
            |sender_presentations| {
                sender_presentations
                    .pop_front()
                    .ok_or(ExecutionError::MissingSenderPresentation { sender })
            },
        )
    }

    fn promote(
        &mut self,
        placement: Placement,
        index: u64,
        body: &MessageBody,
    ) -> Result<bool, ExecutionError> {
        self.offered.push((placement, index, body.to));
        Ok(match placement {
            Placement::Public => self.public_promotions.remove(&index),
            Placement::Private => self.private_promotions.remove(&index),
        })
    }

    fn admits(&mut self, account_id: AccountId) -> Result<bool, ExecutionError> {
        Ok(!self.refused.contains(&account_id))
    }
}

struct Pipeline {
    whole: Script,
    predicted_cross_messages: PredictedCrossMessages,
    private: Script,
    boundary: Boundary,
    public: Script,
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

fn data(bytes: &[u8]) -> ActorState {
    bytes.to_vec().into()
}

fn send_to(receiver: Actor) -> Call {
    Call {
        to: receiver,
        message: Vec::new(),
        pda_seeds: BTreeSet::new(),
    }
}

// The private holder of `Keys::new(1)`, entered from a public transition.
fn enter(message: &[u8]) -> Call {
    Call {
        to: holder(&Keys::new(1)),
        message: message.to_vec(),
        pda_seeds: BTreeSet::new(),
    }
}

fn delivery<S>(from: S, to: Actor, message: &[u8]) -> Delivery<S> {
    Delivery {
        envelope: MessageEnvelope {
            from,
            to,
            message: message.to_vec(),
        },
        inherited_authorizations: BTreeSet::new(),
        inherits_entry_authorizations: true,
        pda_seeds: BTreeSet::new(),
    }
}

fn echo(input: &ReceiveInput, response: Response) -> Transition {
    response.into_transition(input.clone())
}

fn sending(calls: Vec<Call>) -> impl Fn(&ReceiveInput) -> Transition {
    move |input| {
        echo(
            input,
            Response {
                calls: calls.clone(),
                ..Response::keep_state()
            },
        )
    }
}

fn sending_when(from: Option<Actor>, calls: Vec<Call>) -> impl Fn(&ReceiveInput) -> Transition {
    let send = sending(calls);
    move |input| {
        if input.from == from {
            send(input)
        } else {
            echo(input, Response::keep_state())
        }
    }
}

fn root_call(to: Actor) -> RootCall {
    RootCall {
        to,
        message: Vec::new(),
    }
}

fn root(to: Actor) -> TransactionEntry<MessageBody> {
    TransactionEntry::Call(root_call(to))
}

fn context(actors: Vec<Actor>) -> PublicExecutionContext {
    PublicExecutionContext::new(actors, [])
}

fn whole(
    context: PublicExecutionContext,
    witnesses: &[PrivateWitness],
    entry: TransactionEntry<MessageBody>,
    script: &mut Script,
) -> Result<WholeTransactionOutcome, ExecutionError> {
    WholeTransaction::new(context, entry, witnesses)?.execute(script)
}

fn public_transaction(
    context: PublicExecutionContext,
    to: Actor,
    script: &mut Script,
) -> Result<PublicOutcome, ExecutionError> {
    Ok(whole(context, &[], root(to), script)?.public)
}

fn private_part(
    context: PublicExecutionContext,
    witnesses: &[PrivateWitness],
    entry: TransactionEntry<MessageBody>,
    predicted_cross_messages: PredictedCrossMessages,
    script: &mut Script,
) -> Result<PrivatePartOutcome, ExecutionError> {
    PrivatePart::new(context, entry, witnesses, predicted_cross_messages)?.execute(script)
}

fn public_part(
    context: PublicExecutionContext,
    root: RootCall,
    boundary: Boundary,
    script: &mut Script,
) -> Result<PublicOutcome, ExecutionError> {
    PublicPart::new(context, Some(root), boundary)?.execute(script)
}

fn pipeline(
    actors: &[Actor],
    witnesses: &[PrivateWitness],
    to: Actor,
    scripted: impl Fn() -> Script,
) -> Pipeline {
    let mut whole_script = scripted();
    let predicted_cross_messages = whole(
        context(actors.to_vec()),
        witnesses,
        root(to),
        &mut whole_script,
    )
    .unwrap()
    .predicted_cross_messages;
    let mut private_script = scripted();
    let boundary = private_part(
        context(actors.to_vec()),
        witnesses,
        root(to),
        predicted_cross_messages.clone(),
        &mut private_script,
    )
    .unwrap()
    .boundary;
    let mut public_script = scripted();
    public_part(
        context(actors.to_vec()),
        root_call(to),
        boundary.clone(),
        &mut public_script,
    )
    .unwrap();
    Pipeline {
        whole: whole_script,
        predicted_cross_messages,
        private: private_script,
        boundary,
        public: public_script,
    }
}
fn order(script: &Script) -> Vec<(Actor, Option<Actor>)> {
    script
        .log
        .iter()
        .map(|input| (input.receiver, input.from))
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
        pda_seeds: BTreeSet::from([seed]),
        ..send_to(to)
    }
}

fn participants(public: &[Actor], keys: &[Keys]) -> Vec<Actor> {
    public
        .iter()
        .copied()
        .chain(keys.iter().map(holder))
        .collect()
}

fn public_pda(program: AccountId, seed: PdaSeed) -> Actor {
    Actor::new(AccountId::for_public_pda(&program, &seed), program)
}

fn stored(from: Actor, to: Actor, message: &[u8]) -> MessageBody {
    MessageBody {
        from,
        to,
        message: message.to_vec(),
    }
}

fn public_calls(boundary: &[BoundaryStep]) -> Vec<Delivery<Actor>> {
    boundary
        .iter()
        .filter_map(|step| match step {
            PrivateToPublic(delivery) => Some(delivery.clone()),
            PublicToPrivate(_) | EndPrivateSubtree | EndPublicSubtree => None,
        })
        .collect()
}

// `ENTRY` enters the private holder, whose transition calls `CALLEE`.
fn nested_cross_messages() -> PredictedCrossMessages {
    vec![
        vec![delivery(ENTRY, holder(&Keys::new(1)), ENTER)],
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

fn nested_pipeline() -> Pipeline {
    pipeline(
        &[ENTRY, CALLEE, BYSTANDER],
        &[Keys::new(1).regular(false)],
        ENTRY,
        || nested_public(nested_private(), vec![enter(ENTER), send_to(BYSTANDER)]),
    )
}
fn run_public_nested(
    boundary: Boundary,
    entry_sends: Vec<Call>,
) -> (Result<PublicOutcome, ExecutionError>, Script) {
    let mut script = nested_public(Script::default(), entry_sends);
    let result = public_part(
        context(vec![ENTRY, CALLEE, BYSTANDER]),
        root_call(ENTRY),
        boundary,
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
        .actor_state(receiver, b"old")
        .on(receiver, move |input| {
            echo(
                input,
                Response::set_state(b"new".to_vec()).event(emitted.clone()),
            )
        });

    let PublicOutcome {
        accounts: public,
        events,
        ..
    } = public_transaction(context(vec![receiver]), receiver, &mut script).unwrap();

    assert_eq!(
        public,
        BTreeMap::from([(
            receiver.account_id,
            AccountData::default().with_actor_state(receiver.program_account_id, data(b"new"))
        )])
    );
    assert_eq!(events, vec![(receiver, event)]);
}

#[test]
fn sends_run_depth_first_with_each_sender_as_from() {
    let (parent, first, second, nested) = (actor(1, 9), actor(2, 7), actor(3, 9), actor(4, 9));
    let mut script = Script::default()
        .on(parent, sending(vec![send_to(first), send_to(second)]))
        .on(first, sending(vec![send_to(nested)]))
        .on(second, sending(Vec::new()))
        .on(nested, sending(Vec::new()));

    public_transaction(
        context(vec![parent, first, second, nested]),
        parent,
        &mut script,
    )
    .unwrap();

    assert_eq!(
        order(&script),
        vec![
            (parent, None),
            (first, Some(parent)),
            (nested, Some(first)),
            (second, Some(parent)),
        ]
    );
}

#[test]
fn a_send_to_an_undeclared_actor_is_rejected() {
    let (parent, stranger, sibling) = (actor(1, 9), actor(2, 9), actor(3, 9));
    let mut script = Script::default()
        .on(parent, sending(vec![send_to(stranger), send_to(sibling)]))
        .on(sibling, sending(Vec::new()));

    let result = public_transaction(context(vec![parent, sibling]), parent, &mut script);

    assert!(matches!(
        result,
        Err(ExecutionError::UndeclaredActor { actor: rejected }) if rejected == stranger
    ));
    assert_eq!(order(&script), vec![(parent, None)]);
}

#[test]
fn a_transition_that_forges_its_input_is_rejected() {
    let receiver = actor(1, 9);
    let mut script = Script::default().on(receiver, |input| {
        Response::keep_state().into_transition(ReceiveInput {
            message: b"forged".to_vec(),
            ..input.clone()
        })
    });

    assert!(matches!(
        public_transaction(context(vec![receiver]), receiver, &mut script),
        Err(ExecutionError::TransitionInputMismatch { .. })
    ));
}

#[test]
fn a_revisited_actor_sees_its_staged_write() {
    let looping = actor(1, 9);
    let mut script = Script::default().on(looping, move |input| {
        if input.pre_state.is_empty() {
            echo(
                input,
                Response::set_state(b"x".to_vec()).send(send_to(looping)),
            )
        } else {
            echo(input, Response::keep_state())
        }
    });

    public_transaction(context(vec![looping]), looping, &mut script).unwrap();

    let seen: Vec<_> = script
        .log
        .iter()
        .map(|input| (input.pre_state.clone(), input.receiver))
        .collect();
    assert_eq!(
        seen,
        vec![(ActorState::empty(), looping), (data(b"x"), looping)]
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
        pda_seeds: BTreeSet::from([seed]),
        ..send_to(vault)
    };
    let mut script = Script::default()
        .on(owner, sending(vec![seeded, send_to(forwarder)]))
        .on(vault, sending_when(Some(owner), vec![send_to(relay)]))
        .on(relay, sending(vec![send_to(vault)]))
        .on(forwarder, sending(vec![send_to(vault)]));

    public_transaction(
        context(vec![owner, forwarder, relay, vault]),
        owner,
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
        .on(signer, sending_when(None, vec![send_to(peer)]))
        .on(peer, sending(vec![send_to(signer)]));

    public_transaction(
        PublicExecutionContext::new(vec![signer, peer], [signer.account_id]),
        signer,
        &mut script,
    )
    .unwrap();

    assert_eq!(
        authorized(&script),
        vec![(signer, true), (peer, false), (signer, true)]
    );
}

#[test]
fn transition_windows_intersect_and_disjoint_ones_are_rejected() {
    let (outer, inner) = (actor(1, 9), actor(2, 9));
    let windowed = |inner_window: std::ops::Range<u64>| {
        Script::default()
            .on(outer, move |input| {
                echo(
                    input,
                    Response::keep_state()
                        .try_block_window(1_u64..10)
                        .unwrap()
                        .send(send_to(inner)),
                )
            })
            .on(inner, move |input| {
                echo(
                    input,
                    Response::keep_state()
                        .try_block_window(inner_window.clone())
                        .unwrap(),
                )
            })
    };
    let execute =
        |script: &mut Script| public_transaction(context(vec![outer, inner]), outer, script);

    let outcome = execute(&mut windowed(5..20)).unwrap();

    assert_eq!(
        outcome.validity.blocks,
        BlockValidityWindow::try_from(5..10).unwrap()
    );
    assert!(matches!(
        execute(&mut windowed(10..20)),
        Err(ExecutionError::EmptyValidityWindowIntersection)
    ));
}

#[test]
fn a_long_self_send_chain_completes_in_every_part() {
    let chain = || {
        let mut remaining = 128_u32;
        Script::default().on(ENTRY, move |input| {
            let response = if remaining == 0 {
                Response::keep_state()
            } else {
                remaining = remaining.saturating_sub(1);
                Response::keep_state().send(send_to(ENTRY))
            };
            echo(input, response)
        })
    };

    let Pipeline { whole, public, .. } = pipeline(&[ENTRY], &[], ENTRY, chain);
    assert_eq!(whole.log.len(), 129);
    assert_eq!(public.log.len(), 129);
}

#[test]
fn a_public_actor_state_is_fetched_once_and_a_cleared_actor_state_is_reported_empty() {
    let clearing = actor(1, 9);
    let mut script = Script::default()
        .actor_state(clearing, b"orig")
        .on(clearing, move |input| {
            if input.pre_state.is_empty() {
                echo(input, Response::keep_state())
            } else {
                echo(
                    input,
                    Response::set_state(Vec::new()).send(send_to(clearing)),
                )
            }
        });

    let public = public_transaction(context(vec![clearing]), clearing, &mut script)
        .unwrap()
        .accounts;

    let seen: Vec<_> = script
        .log
        .iter()
        .map(|input| input.pre_state.clone())
        .collect();
    assert_eq!(seen, vec![data(b"orig"), ActorState::empty()]);
    assert_eq!(script.actor_states[&clearing], data(b"orig"));
    assert_eq!(
        public,
        BTreeMap::from([(
            clearing.account_id,
            AccountData {
                actor_states: [(clearing.program_account_id, ActorState::empty())].into(),
            }
        )])
    );
}

#[test]
fn a_private_root_records_its_public_call_and_the_predicted_reply() {
    let keys = Keys::new(1);
    let owner = holder(&keys);
    let vault = actor(2, 9);
    let credit = Call {
        to: vault,
        message: b"credit".to_vec(),
        pda_seeds: BTreeSet::new(),
    };
    let reply = delivery(vault, owner, b"credit");
    let event = ProgramEvent {
        selector: [7; 8],
        data: Vec::new(),
    };
    let mut script = Script::default().on(owner, move |input| {
        if input.from.is_none() {
            echo(
                input,
                Response::set_state(b"first".to_vec()).send(credit.clone()),
            )
        } else {
            echo(
                input,
                Response::set_state(b"second".to_vec()).event(event.clone()),
            )
        }
    });

    let PrivatePartOutcome {
        private_accounts,
        boundary,
        ..
    } = private_part(
        context(vec![vault]),
        &[keys.regular(true)],
        root(owner),
        vec![vec![reply.clone()]],
        &mut script,
    )
    .unwrap();

    assert_eq!(order(&script), vec![(owner, None), (owner, Some(vault))]);
    assert_eq!(
        boundary,
        vec![
            PrivateToPublic(delivery(owner, vault, b"credit")),
            PublicToPrivate(reply),
            EndPrivateSubtree,
            EndPublicSubtree,
        ]
    );
    assert_eq!(
        private_accounts[&owner.account_id],
        AccountData::default().with_actor_state(owner.program_account_id, data(b"second"))
    );
}

#[test]
fn a_nested_mixed_graph_is_predicted_bracketed_and_replayed_through_every_part() {
    let Pipeline {
        predicted_cross_messages,
        private,
        boundary,
        public,
        ..
    } = nested_pipeline();

    assert_eq!(predicted_cross_messages, nested_cross_messages());
    assert_eq!(
        boundary,
        vec![
            PublicToPrivate(nested_cross_messages()[0][0].clone()),
            PrivateToPublic(delivery(holder(&Keys::new(1)), CALLEE, &[])),
            EndPublicSubtree,
            EndPrivateSubtree,
        ]
    );
    assert_eq!(order(&private), vec![(holder(&Keys::new(1)), Some(ENTRY))]);
    assert_eq!(
        order(&public),
        vec![
            (ENTRY, None),
            (CALLEE, Some(holder(&Keys::new(1)))),
            (BYSTANDER, Some(ENTRY)),
        ]
    );
}

#[test]
fn predicted_cross_messages_must_match_the_recorded_public_deliveries() {
    let keys = Keys::new(1);
    let vault = actor(2, 9);
    let stranger = actor(5, 9);
    let run_private = |predicted_cross_messages: PredictedCrossMessages| {
        let mut script = Script::default().on(holder(&keys), sending(vec![send_to(vault)]));
        private_part(
            context(vec![vault]),
            &[keys.regular(false)],
            root(holder(&keys)),
            predicted_cross_messages,
            &mut script,
        )
    };
    let reply = delivery(stranger, holder(&keys), &[]);

    assert!(matches!(
        run_private(Vec::new()),
        Err(ExecutionError::MissingPredictedCrossMessages { index: 0 })
    ));
    assert!(matches!(
        run_private(vec![Vec::new(), Vec::new()]),
        Err(ExecutionError::UnusedPredictedCrossMessages)
    ));
    assert!(matches!(
        run_private(vec![vec![reply]]),
        Err(ExecutionError::UndeclaredCrossMessageSender { actor: sender }) if sender == stranger
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
        .on(owner, sending_when(None, vec![send_to(vault)]))
        .on(custody, sending(Vec::new()));
    let predicted = vec![vec![
        delivery(vault, owner, &[]),
        Delivery {
            pda_seeds: BTreeSet::from([seed]),
            ..delivery(vault, custody, &[])
        },
    ]];

    private_part(
        context(vec![vault]),
        &[keys.regular(true), keys.pda(vault.program_account_id, seed)],
        root(owner),
        predicted,
        &mut script,
    )
    .unwrap();

    assert_eq!(
        authorized(&script),
        vec![(owner, true), (owner, true), (custody, true)]
    );
}

#[test]
fn a_public_part_rejects_public_behaviour_that_departs_from_the_boundary() {
    let boundary = nested_pipeline().boundary;
    let run_public = |sends: Vec<Call>| run_public_nested(boundary.clone(), sends).0;
    let truncated = boundary[..1].to_vec();

    assert!(matches!(
        run_public(vec![send_to(BYSTANDER)]),
        Err(ExecutionError::IncompleteBoundary)
    ));
    assert!(matches!(
        run_public(vec![enter(b"other")]),
        Err(ExecutionError::CrossMessageMismatch { index: 0 })
    ));
    assert!(matches!(
        run_public(vec![enter(ENTER), enter(ENTER)]),
        Err(ExecutionError::BoundaryMismatch { index: 4 })
    ));
    assert!(matches!(
        run_public_nested(truncated, vec![enter(ENTER), send_to(BYSTANDER)]).0,
        Err(ExecutionError::BoundaryMismatch { index: 1 })
    ));
}

#[test]
fn a_public_part_runs_a_proven_call_from_its_presented_sender() {
    let from = holder(&Keys::new(1));
    let boundary = vec![
        PrivateToPublic(delivery(from, ENTRY, &[])),
        EndPublicSubtree,
    ];
    let mut script = Script::default().on(ENTRY, sending(Vec::new()));

    let result = public_part(
        context(vec![ENTRY]),
        root_call(holder(&Keys::new(1))),
        boundary,
        &mut script,
    );

    assert!(result.is_ok());
    assert_eq!(order(&script), vec![(ENTRY, Some(from))]);
}

#[test]
fn initialization_rejects_inconsistent_declarations() {
    let keys = Keys::new(1);
    let owned = holder(&keys);
    let public_actor = actor(2, 9);
    let private_witnesses = [keys.regular(false)];
    let init = |public_actors: Vec<Actor>, witnesses: &[PrivateWitness]| {
        WholeTransaction::new(context(public_actors), root(public_actor), witnesses).err()
    };

    assert!(matches!(
        init(vec![Actor::new(owned.account_id, id(9))], &private_witnesses),
        Some(ExecutionError::PublicAndPrivate { account_id }) if account_id == owned.account_id
    ));
}

#[test]
fn each_part_executes_the_root_only_on_its_side() {
    let keys = Keys::new(1);
    let witnesses = [keys.regular(false)];
    let script = || {
        Script::default()
            .on(ENTRY, sending(Vec::new()))
            .on(holder(&keys), sending(Vec::new()))
    };

    for (to, runs_publicly) in [(ENTRY, true), (holder(&keys), false)] {
        let Pipeline {
            private, public, ..
        } = pipeline(&[ENTRY], &witnesses, to, script);
        let (ran, skipped) = if runs_publicly {
            (&public, &private)
        } else {
            (&private, &public)
        };
        assert_eq!(
            order(ran),
            vec![(to, None)],
            "{to:?} did not run on its side"
        );
        assert!(
            order(skipped).is_empty(),
            "{to:?} also ran on the other side"
        );
    }
}

#[test]
fn a_public_part_whose_live_subtree_reaches_the_loader_fails() {
    let loader = Actor::new(id(4), PROGRAM_LOADER_ACCOUNT_ID);
    let mut script = Script::default()
        .on(ENTRY, sending(vec![send_to(loader)]))
        .on(loader, sending(Vec::new()));

    let result = public_part(
        context(vec![ENTRY, loader]),
        root_call(ENTRY),
        Boundary::new(),
        &mut script,
    );

    assert!(matches!(
        result,
        Err(ExecutionError::LoaderOutsidePublicExecution { actor }) if actor == loader
    ));
    assert_eq!(order(&script), vec![(ENTRY, None)]);
}

#[test]
fn a_private_part_refuses_an_explicit_delivery_to_the_loader() {
    let keys = Keys::new(1);
    let loader = Actor::new(id(4), PROGRAM_LOADER_ACCOUNT_ID);
    let mut script = Script::default().on(holder(&keys), sending(vec![send_to(loader)]));

    let result = private_part(
        context(vec![loader]),
        &[keys.regular(false)],
        root(holder(&keys)),
        vec![Vec::new()],
        &mut script,
    );

    assert!(matches!(
        result,
        Err(ExecutionError::LoaderOutsidePublicExecution { actor }) if actor == loader
    ));
    assert_eq!(order(&script), vec![(holder(&keys), None)]);
}

// The public owner seeds two PDAs; the first enters the private relay, whose call back to it
// carries its grant. `predicted_authorizations` is what the proof claims the relay received.
fn relayed_grant(
    predicted_authorizations: BTreeSet<AccountId>,
) -> (Result<PublicOutcome, ExecutionError>, Script) {
    let keys = Keys::new(1);
    let relay = holder(&keys);
    let owner = ENTRY;
    let (seed, sibling_seed) = (PdaSeed::new([5; 32]), PdaSeed::new([6; 32]));
    let vault = public_pda(owner.program_account_id, seed);
    let sibling = public_pda(owner.program_account_id, sibling_seed);
    let actors = vec![owner, sibling, vault];

    let mut private_script = Script::default().on(relay, sending(vec![send_to(vault)]));
    let private_outcome = private_part(
        context(actors.clone()),
        &[keys.regular(false)],
        root(owner),
        vec![
            vec![Delivery {
                inherited_authorizations: predicted_authorizations,
                ..delivery(vault, relay, ENTER)
            }],
            Vec::new(),
        ],
        &mut private_script,
    )
    .unwrap();

    let mut public_script = Script::default()
        .on(
            owner,
            sending(vec![
                seeded_to(vault, seed),
                seeded_to(sibling, sibling_seed),
            ]),
        )
        .on(sibling, sending(Vec::new()))
        .on(vault, sending_when(Some(owner), vec![enter(ENTER)]));
    let result = public_part(
        context(actors),
        root_call(owner),
        private_outcome.boundary,
        &mut public_script,
    );
    (result, public_script)
}

#[test]
fn a_public_grant_crosses_a_private_relay_and_authorizes_the_reply() {
    let vault = public_pda(ENTRY.program_account_id, PdaSeed::new([5; 32]));
    let sibling = public_pda(ENTRY.program_account_id, PdaSeed::new([6; 32]));

    let (result, script) = relayed_grant(BTreeSet::from([vault.account_id]));

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
fn a_predicted_cross_message_must_claim_exactly_the_delivered_grants() {
    let sibling = public_pda(ENTRY.program_account_id, PdaSeed::new([6; 32]));

    for claimed in [BTreeSet::from([sibling.account_id]), BTreeSet::new()] {
        assert!(matches!(
            relayed_grant(claimed).0,
            Err(ExecutionError::CrossMessageMismatch { index: 0 })
        ));
    }
}

#[test]
fn a_withheld_private_grant_authorizes_the_return_through_a_public_actor() {
    let (keys, pda_keys) = (Keys::new(1), Keys::new(2));
    let owner = holder(&keys);
    let seed = PdaSeed::new([5; 32]);
    let custody = Actor::new(pda_keys.pda_id(owner.program_account_id, seed), id(8));
    let peer = actor(3, 9);
    let peer_vault = public_pda(peer.program_account_id, seed);
    let mut private_script = Script::default()
        .on(owner, sending(vec![seeded_to(custody, seed)]))
        .on(custody, sending_when(Some(owner), vec![send_to(peer)]));

    let private_outcome = private_part(
        context(vec![peer, peer_vault]),
        &[
            keys.regular(false),
            pda_keys.pda(owner.program_account_id, seed),
        ],
        root(owner),
        vec![vec![delivery(peer, custody, &[])]],
        &mut private_script,
    )
    .unwrap();

    assert_eq!(
        authorized(&private_script),
        vec![(owner, false), (custody, true), (custody, true)]
    );
    let boundary = private_outcome.boundary;
    assert!(
        public_calls(&boundary)[0]
            .inherited_authorizations
            .is_empty()
    );

    let mut public_script = Script::default()
        .on(
            peer,
            sending(vec![send_to(custody), seeded_to(peer_vault, seed)]),
        )
        .on(peer_vault, sending(Vec::new()));
    assert!(
        public_part(
            context(vec![peer, peer_vault]),
            root_call(owner),
            boundary,
            &mut public_script
        )
        .is_ok()
    );
    assert_eq!(
        authorized(&public_script),
        vec![(peer, false), (peer_vault, true)]
    );
}

#[test]
fn a_private_seed_grant_reaches_its_subtree_but_not_a_sibling_call() {
    let (keys, pda_keys, relay_keys) = (Keys::new(1), Keys::new(2), Keys::new(3));
    let owner = holder(&keys);
    let seed = PdaSeed::new([5; 32]);
    let custody = Actor::new(pda_keys.pda_id(owner.program_account_id, seed), id(8));
    let forwarded = Actor::new(custody.account_id, id(7));
    let relay = holder(&relay_keys);
    let mut visited = false;
    let mut script = Script::default()
        .on(
            owner,
            sending(vec![seeded_to(custody, seed), send_to(custody)]),
        )
        .on(custody, move |input| {
            let calls = if std::mem::replace(&mut visited, true) {
                Vec::new()
            } else {
                vec![send_to(forwarded), send_to(relay)]
            };
            echo(
                input,
                Response {
                    calls,
                    ..Response::keep_state()
                },
            )
        })
        .on(forwarded, sending(Vec::new()))
        .on(relay, sending(vec![send_to(custody)]));

    private_part(
        PublicExecutionContext::default(),
        &[
            keys.regular(false),
            pda_keys.pda(owner.program_account_id, seed),
            relay_keys.regular(false),
        ],
        root(owner),
        Vec::new(),
        &mut script,
    )
    .unwrap();

    assert_eq!(
        authorized(&script),
        vec![
            (owner, false),
            (custody, true),
            (forwarded, true),
            (relay, false),
            (custody, true),
            (custody, false),
        ]
    );
}

// `peer`'s seed grants the private `custody` from the public side; custody's own detour through
// `relay` returns to it, and `peer`'s later sibling call arrives without the seed.
#[test]
fn a_private_grant_survives_its_own_public_detour_but_not_a_sibling_call() {
    let (keys, pda_keys) = (Keys::new(1), Keys::new(2));
    let owner = holder(&keys);
    let (peer, relay) = (actor(3, 9), actor(4, 7));
    let seed = PdaSeed::new([5; 32]);
    let custody = Actor::new(pda_keys.pda_id(peer.program_account_id, seed), id(8));
    let witnesses = [
        keys.regular(false),
        pda_keys.pda(peer.program_account_id, seed),
    ];
    let script = || {
        let mut detoured = false;
        Script::default()
            .on(owner, sending(vec![send_to(peer)]))
            .on(
                peer,
                sending(vec![seeded_to(custody, seed), send_to(custody)]),
            )
            .on(custody, move |input| {
                let calls = if std::mem::replace(&mut detoured, true) {
                    Vec::new()
                } else {
                    vec![send_to(relay)]
                };
                echo(
                    input,
                    Response {
                        calls,
                        ..Response::keep_state()
                    },
                )
            })
            .on(relay, sending(vec![send_to(custody)]))
    };
    let expected = vec![
        (owner, false),
        (custody, true),
        (custody, true),
        (custody, false),
    ];

    let Pipeline {
        whole: whole_script,
        private: private_script,
        boundary,
        ..
    } = pipeline(&[peer, relay], &witnesses, owner, script);
    let private_transitions: Vec<_> = authorized(&whole_script)
        .into_iter()
        .filter(|(actor, _)| *actor == owner || *actor == custody)
        .collect();
    assert_eq!(private_transitions, expected);
    assert_eq!(authorized(&private_script), expected);
    assert!(boundary.iter().all(|step| match step {
        PrivateToPublic(delivery) | PublicToPrivate(delivery) => {
            !delivery
                .inherited_authorizations
                .contains(&custody.account_id)
        }
        EndPrivateSubtree | EndPublicSubtree => true,
    }));
}
#[test]
fn a_predicted_grant_over_a_private_account_authorizes_nothing() {
    let (keys, pda_keys) = (Keys::new(1), Keys::new(2));
    let owner = holder(&keys);
    let peer = actor(3, 9);
    let seed = PdaSeed::new([5; 32]);
    let custody = Actor::new(pda_keys.pda_id(peer.program_account_id, seed), id(8));
    let mut script = Script::default()
        .on(owner, sending(vec![send_to(peer)]))
        .on(custody, sending(Vec::new()));

    let boundary = private_part(
        context(vec![peer]),
        &[
            keys.regular(false),
            pda_keys.pda(peer.program_account_id, seed),
        ],
        root(owner),
        vec![vec![Delivery {
            inherited_authorizations: BTreeSet::from([custody.account_id]),
            ..delivery(peer, custody, &[])
        }]],
        &mut script,
    )
    .unwrap()
    .boundary;

    assert_eq!(authorized(&script), vec![(owner, false), (custody, false)]);
    assert!(matches!(
        boundary.as_slice(),
        [PrivateToPublic(_), PublicToPrivate(forged), EndPrivateSubtree, EndPublicSubtree] if forged.inherited_authorizations.is_empty()
    ));
}

#[test]
fn a_private_pda_family_cannot_declare_its_public_member() {
    let keys = Keys::new(1);
    let (program, seed) = (id(8), PdaSeed::new([5; 32]));
    let custody = Actor::new(keys.pda_id(program, seed), program);
    let public_member = Actor::new(AccountId::for_public_pda(&program, &seed), id(9));
    let witnesses = [keys.pda(program, seed)];

    let result = PrivatePart::new(
        context(vec![public_member]),
        root(custody),
        &witnesses,
        Vec::new(),
    );

    assert!(matches!(
        result.err(),
        Some(ExecutionError::PublicFamilyMemberDeclared { account_id })
            if account_id == public_member.account_id
    ));
}

#[test]
fn a_public_part_publishes_live_events() {
    let event = ProgramEvent {
        selector: [7; 8],
        data: Vec::new(),
    };
    let emitted = event.clone();
    let mut public_script = Script::default().on(ENTRY, move |input| {
        echo(input, Response::keep_state().event(emitted.clone()))
    });

    let events = public_part(
        context(vec![ENTRY]),
        root_call(ENTRY),
        Boundary::new(),
        &mut public_script,
    )
    .unwrap()
    .events;

    assert_eq!(events, vec![(ENTRY, event)]);
}

// A public transition asks a private account's native balance to pay: the private transition runs
// under the account's own credential, and without it the debit is refused.
#[test]
fn a_public_transition_requests_a_private_debit_that_the_private_credential_authorizes() {
    let keys = Keys::new(1);
    let (requester, payee) = (actor(2, 9), Actor::native_balance(id(3)));
    let payer = Actor::native_balance(keys.regular_id());
    let run_private = |credential: bool| {
        let mut script = Script::default().on(payer, |input| {
            native_token::handle_message(input).unwrap_or_else(|error| panic!("{error}"))
        });
        private_part(
            context(vec![requester, payee]),
            &[keys.regular(credential)],
            root(requester),
            vec![
                vec![delivery(
                    requester,
                    payer,
                    &borsh::to_vec(&native_token::Message::Transfer {
                        to: payee.account_id,
                        amount: 0,
                    })
                    .unwrap(),
                )],
                Vec::new(),
            ],
            &mut script,
        )
    };

    assert_eq!(
        public_calls(&run_private(true).unwrap().boundary)[0],
        delivery(
            payer,
            payee,
            &borsh::to_vec(&native_token::Message::Credit(0)).unwrap(),
        )
    );
    let Err(refused) =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_private(false)))
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

    let mut private_script = Script::default().on(owner, sending(vec![send_to(stray)]));
    let private_result = private_part(
        context(vec![ENTRY]),
        &[keys.regular(false)],
        root(owner),
        Vec::new(),
        &mut private_script,
    );
    let mut public_script = Script::default().on(ENTRY, sending(vec![send_to(stray)]));
    let public_result = public_part(
        context(vec![ENTRY]),
        root_call(ENTRY),
        Boundary::new(),
        &mut public_script,
    );

    for error in [private_result.err(), public_result.err()] {
        assert!(matches!(
            error,
            Some(ExecutionError::UndeclaredActor { actor }) if actor == stray
        ));
    }
}

#[test]
fn an_output_from_a_private_sender_carries_its_presented_actor() {
    let keys = Keys::new(1);
    let mut script = Script::default().on(holder(&keys), sending(vec![send_to(ENTRY)]));

    let private_outcome = private_part(
        context(vec![ENTRY]),
        &[keys.regular(false)],
        root(holder(&keys)),
        vec![Vec::new()],
        &mut script,
    )
    .unwrap();

    assert_eq!(
        public_calls(&private_outcome.boundary),
        vec![delivery(holder(&keys), ENTRY, &[])]
    );
}

#[test]
fn a_live_delivery_from_another_actor_of_the_same_program_does_not_satisfy_a_predicted_cross_message()
 {
    let boundary = nested_pipeline().boundary;
    let mut script = nested_public(Script::default(), vec![send_to(BYSTANDER)])
        .on(BYSTANDER, sending(vec![enter(ENTER)]));
    assert_eq!(BYSTANDER.program_account_id, ENTRY.program_account_id);

    let result = public_part(
        context(vec![ENTRY, CALLEE, BYSTANDER]),
        root_call(ENTRY),
        boundary,
        &mut script,
    );

    assert!(matches!(
        result,
        Err(ExecutionError::CrossMessageMismatch { index: 0 })
    ));
}

#[test]
fn a_parents_casts_precede_its_childrens_and_never_run_their_recipients() {
    let (outer_target, inner_target) = (actor(6, 7), actor(7, 7));
    let mut script = Script::default()
        .on(ENTRY, move |input| {
            echo(
                input,
                Response::keep_state()
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
                Response::keep_state().send(Cast {
                    to: inner_target,
                    message: b"y".to_vec(),
                }),
            )
        })
        .on(BYSTANDER, sending(Vec::new()));

    let casts = public_transaction(context(vec![ENTRY, CALLEE, BYSTANDER]), ENTRY, &mut script)
        .unwrap()
        .casts;

    assert_eq!(
        order(&script),
        vec![
            (ENTRY, None),
            (CALLEE, Some(ENTRY)),
            (BYSTANDER, Some(ENTRY)),
        ]
    );
    assert_eq!(
        casts,
        vec![
            MessageBody {
                from: ENTRY,
                to: outer_target,
                message: b"x".to_vec(),
            },
            MessageBody {
                from: CALLEE,
                to: inner_target,
                message: b"y".to_vec(),
            },
        ]
    );
}

#[test]
fn a_receipt_root_to_a_private_actor_runs_privately_with_its_stored_sender() {
    let keys = Keys::new(1);
    let record = stored(actor(4, 5), holder(&keys), b"stored");
    let mut script = Script::default().on(holder(&keys), sending(Vec::new()));

    let outcome = private_part(
        PublicExecutionContext::default(),
        &[keys.regular(false)],
        TransactionEntry::Cast(record),
        Vec::new(),
        &mut script,
    )
    .unwrap();

    assert_eq!(order(&script), vec![(holder(&keys), Some(actor(4, 5)))]);
    assert_eq!(outcome.boundary, Boundary::default());
}

#[test]
fn a_private_part_keeps_its_casts_out_of_the_boundary_and_a_public_part_returns_only_live_casts() {
    let keys = Keys::new(1);
    let (private_target, public_target) = (actor(6, 7), actor(7, 7));
    let private_cast = MessageBody {
        from: holder(&keys),
        to: private_target,
        message: b"x".to_vec(),
    };
    let mut private_script = Script::default().on(holder(&keys), move |input| {
        echo(
            input,
            Response::keep_state().send(send_to(ENTRY)).send(Cast {
                to: private_target,
                message: b"x".to_vec(),
            }),
        )
    });
    let PrivatePartOutcome {
        boundary,
        casts: proven_casts,
        ..
    } = private_part(
        context(vec![ENTRY]),
        &[keys.regular(false)],
        root(holder(&keys)),
        vec![Vec::new()],
        &mut private_script,
    )
    .unwrap();

    assert_eq!(
        boundary,
        vec![
            PrivateToPublic(delivery(holder(&keys), ENTRY, &[])),
            EndPublicSubtree,
        ]
    );
    assert_eq!(proven_casts, vec![private_cast]);

    let mut public_script = Script::default().on(ENTRY, move |input| {
        echo(
            input,
            Response::keep_state().send(Cast {
                to: public_target,
                message: b"y".to_vec(),
            }),
        )
    });
    let casts = public_part(
        context(vec![ENTRY]),
        root_call(holder(&keys)),
        boundary,
        &mut public_script,
    )
    .unwrap()
    .casts;

    assert_eq!(
        casts,
        vec![MessageBody {
            from: ENTRY,
            to: public_target,
            message: b"y".to_vec(),
        }]
    );
}

fn call_with(to: Actor, message: &[u8]) -> Call {
    Call {
        to,
        message: message.to_vec(),
        pda_seeds: BTreeSet::new(),
    }
}

// `B(C1)` stages 1 and calls `B(C1a)`, which stages 2; `B(C2)` keeps what it finds.
fn sibling_receiver(receiver: Actor) -> impl FnMut(&ReceiveInput) -> Transition {
    move |input| {
        let response = match input.message.as_slice() {
            b"c1" => Response::set_state(b"1".to_vec()).send(call_with(receiver, b"c1a")),
            b"c1a" => Response::set_state(b"2".to_vec()),
            _ => Response::keep_state(),
        };
        echo(input, response)
    }
}

fn siblings(receiver: Actor) -> Vec<Call> {
    vec![call_with(receiver, b"c1"), call_with(receiver, b"c2")]
}

fn transitions_of(script: &Script, receiver: Actor) -> Vec<(MessageData, ActorState)> {
    script
        .log
        .iter()
        .filter(|input| input.receiver == receiver)
        .map(|input| (input.message.clone(), input.pre_state.clone()))
        .collect()
}

fn completed_c1_then_c2() -> Vec<(MessageData, ActorState)> {
    vec![
        (b"c1".to_vec(), ActorState::empty()),
        (b"c1a".to_vec(), data(b"1")),
        (b"c2".to_vec(), data(b"2")),
    ]
}

#[test]
fn a_public_sibling_call_sees_the_state_its_earlier_siblings_subtree_left() {
    let (sender, receiver) = (actor(1, 9), actor(2, 9));
    let mut script = Script::default()
        .on(sender, sending(siblings(receiver)))
        .on(receiver, sibling_receiver(receiver));

    public_transaction(context(vec![sender, receiver]), sender, &mut script).unwrap();

    assert_eq!(transitions_of(&script, receiver), completed_c1_then_c2());
}

#[test]
fn a_private_sibling_call_sees_the_state_its_earlier_siblings_subtree_left() {
    let (sender_keys, receiver_keys) = (Keys::new(1), Keys::new(2));
    let receiver = holder(&receiver_keys);
    let mut script = Script::default()
        .on(holder(&sender_keys), sending(siblings(receiver)))
        .on(receiver, sibling_receiver(receiver));

    let outcome = private_part(
        PublicExecutionContext::default(),
        &[sender_keys.regular(false), receiver_keys.regular(false)],
        root(holder(&sender_keys)),
        Vec::new(),
        &mut script,
    )
    .unwrap();

    assert_eq!(transitions_of(&script, receiver), completed_c1_then_c2());
    assert!(outcome.boundary.is_empty());
}

#[test]
fn a_public_sibling_called_from_a_private_transition_sees_the_state_its_earlier_siblings_subtree_left()
 {
    let keys = Keys::new(1);
    let receiver = actor(2, 9);
    let mut private_script = Script::default().on(holder(&keys), sending(siblings(receiver)));
    let boundary = private_part(
        context(vec![receiver]),
        &[keys.regular(false)],
        root(holder(&keys)),
        vec![Vec::new(), Vec::new()],
        &mut private_script,
    )
    .unwrap()
    .boundary;
    let mut public_script = Script::default().on(receiver, sibling_receiver(receiver));

    public_part(
        context(vec![receiver]),
        root_call(holder(&keys)),
        boundary,
        &mut public_script,
    )
    .unwrap();

    assert_eq!(
        transitions_of(&public_script, receiver),
        completed_c1_then_c2()
    );
}

#[test]
fn a_private_sibling_called_from_a_public_transition_sees_the_state_its_earlier_siblings_subtree_left()
 {
    let keys = Keys::new(1);
    let (sender, receiver) = (actor(1, 9), holder(&keys));
    let mut private_script = Script::default().on(receiver, sibling_receiver(receiver));
    let boundary = private_part(
        context(vec![sender]),
        &[keys.regular(false)],
        root(sender),
        vec![vec![
            delivery(sender, receiver, b"c1"),
            delivery(sender, receiver, b"c2"),
        ]],
        &mut private_script,
    )
    .unwrap()
    .boundary;
    let mut public_script = Script::default().on(sender, sending(siblings(receiver)));

    public_part(
        context(vec![sender]),
        root_call(sender),
        boundary,
        &mut public_script,
    )
    .unwrap();

    assert_eq!(
        transitions_of(&private_script, receiver),
        completed_c1_then_c2()
    );
}

#[test]
fn a_public_subtree_entered_from_c1_finishes_before_c2_in_every_part() {
    let keys = Keys::new(1);
    let (sender, receiver) = (actor(1, 9), holder(&keys));
    let (crossed, descendant) = (actor(3, 9), actor(4, 9));
    let scripted = || {
        Script::default()
            .on(sender, sending(siblings(receiver)))
            .on(receiver, move |input| {
                let response = if input.message == b"c1" {
                    Response::set_state(b"1".to_vec()).send(send_to(crossed))
                } else {
                    Response::keep_state()
                };
                echo(input, response)
            })
            .on(crossed, sending(vec![send_to(descendant)]))
            .on(descendant, sending(Vec::new()))
    };
    let simulating = pipeline(
        &[sender, crossed, descendant],
        &[keys.regular(false)],
        sender,
        scripted,
    )
    .whole;

    assert_eq!(
        order(&simulating),
        vec![
            (sender, None),
            (receiver, Some(sender)),
            (crossed, Some(receiver)),
            (descendant, Some(crossed)),
            (receiver, Some(sender)),
        ]
    );
}
#[test]
fn a_failing_descendant_of_c1_stops_the_transaction_before_c2() {
    let (sender, receiver, stranger) = (actor(1, 9), actor(2, 9), actor(5, 9));
    let mut script = Script::default()
        .on(sender, sending(siblings(receiver)))
        .on(receiver, move |input| {
            let response = if input.message == b"c1" {
                Response::set_state(b"1".to_vec())
                    .send(Cast {
                        to: stranger,
                        message: b"x".to_vec(),
                    })
                    .send(send_to(stranger))
            } else {
                Response::keep_state()
            };
            echo(input, response)
        });

    let result = public_transaction(context(vec![sender, receiver]), sender, &mut script);

    assert!(matches!(
        result,
        Err(ExecutionError::UndeclaredActor { actor }) if actor == stranger
    ));
    assert_eq!(
        transitions_of(&script, receiver),
        vec![(b"c1".to_vec(), ActorState::empty())]
    );
}

#[test]
fn a_public_call_without_callbacks_keeps_an_empty_group_before_one_with_callbacks() {
    let keys = Keys::new(1);
    let owner = holder(&keys);
    let (quiet, replying) = (actor(2, 9), actor(3, 9));
    let scripted = || {
        Script::default()
            .on(
                owner,
                sending_when(None, vec![send_to(quiet), send_to(replying)]),
            )
            .on(quiet, sending(Vec::new()))
            .on(replying, sending(vec![call_with(owner, b"back")]))
    };

    assert_eq!(
        pipeline(&[quiet, replying], &[keys.regular(false)], owner, scripted)
            .predicted_cross_messages,
        vec![Vec::new(), vec![delivery(replying, owner, b"back")]]
    );
}
fn alias(actor: Actor, factor: [u8; 32]) -> Actor {
    Actor::new(actor.account_id.blinded(&factor), actor.program_account_id)
}

fn opened(witness: PrivateWitness, factors: &[[u8; 32]]) -> PrivateWitness {
    PrivateWitness {
        openings: factors.iter().copied().collect(),
        ..witness
    }
}

#[test]
fn deliveries_at_two_aliases_and_the_account_itself_share_one_account() {
    let keys = Keys::new(1);
    let owner = holder(&keys);
    let (first, second) = (alias(owner, [7; 32]), alias(owner, [8; 32]));
    let mut script = Script::default().on(owner, move |input| {
        let response = if input.pre_state.is_empty() {
            Response::set_state(b"1".to_vec()).send(send_to(second))
        } else if input.pre_state == data(b"1") {
            Response::set_state(b"2".to_vec()).send(send_to(owner))
        } else {
            Response::keep_state()
        };
        echo(input, response)
    });

    let outcome = private_part(
        PublicExecutionContext::default(),
        &[opened(keys.regular(false), &[[7; 32], [8; 32]])],
        root(first),
        Vec::new(),
        &mut script,
    )
    .unwrap();

    let seen: Vec<_> = script
        .log
        .iter()
        .map(|input| (input.receiver, input.pre_state.clone()))
        .collect();
    assert_eq!(
        seen,
        vec![
            (owner, ActorState::empty()),
            (owner, data(b"1")),
            (owner, data(b"2"))
        ]
    );
    assert_eq!(
        outcome.private_accounts,
        HashMap::from([(
            owner.account_id,
            AccountData::default().with_actor_state(owner.program_account_id, data(b"2"))
        )])
    );
}

#[test]
fn an_alias_without_its_opening_is_an_undeclared_actor() {
    let keys = Keys::new(1);
    let unopened = alias(holder(&keys), [7; 32]);

    let result = private_part(
        PublicExecutionContext::default(),
        &[keys.regular(false)],
        root(unopened),
        Vec::new(),
        &mut Script::default(),
    );

    assert!(matches!(
        result,
        Err(ExecutionError::UndeclaredActor { actor }) if actor == unopened
    ));
}

#[test]
fn an_opening_whose_alias_is_a_declared_actor_is_refused() {
    let keys = Keys::new(1);
    let declared = alias(holder(&keys), [7; 32]);

    let result = whole(
        context(vec![declared]),
        &[opened(keys.regular(false), &[[7; 32]])],
        root(declared),
        &mut Script::default(),
    );

    assert!(matches!(
        result,
        Err(ExecutionError::AliasCollision { alias }) if alias == declared.account_id
    ));
}

// The private owner calls `ENTRY` at an alias, and `ENTRY` answers whoever called it.
#[test]
fn a_reply_to_a_presented_alias_returns_to_the_account_in_every_part() {
    let keys = Keys::new(1);
    let owner = holder(&keys);
    let presented = alias(owner, [5; 32]);
    let scripted = || {
        Script::default()
            .presenting([SenderPresentation::Blinded([5; 32])])
            .on(owner, |input| {
                let response = if input.from.is_none() {
                    Response::keep_state().send(send_to(ENTRY))
                } else {
                    Response::keep_state()
                };
                echo(input, response)
            })
            .on(ENTRY, |input| {
                let caller = input.from.expect("a call has a sender");
                echo(
                    input,
                    Response::keep_state().send(call_with(caller, b"reply")),
                )
            })
    };
    let Pipeline {
        whole: simulating,
        boundary,
        ..
    } = pipeline(&[ENTRY], &[keys.regular(false)], owner, scripted);

    assert_eq!(
        order(&simulating),
        vec![
            (owner, None),
            (ENTRY, Some(presented)),
            (owner, Some(ENTRY))
        ]
    );
    assert_eq!(
        boundary,
        vec![
            PrivateToPublic(delivery(presented, ENTRY, &[])),
            PublicToPrivate(delivery(ENTRY, presented, b"reply")),
            EndPrivateSubtree,
            EndPublicSubtree,
        ]
    );
}
// `ENTRY` queries the private owner at an alias and at its own address; each answer reaches `ENTRY`
// from the address `ENTRY` used, and no answer takes a presentation.
#[test]
fn a_reply_presents_the_address_its_sender_reached() {
    let keys = Keys::new(1);
    let owner = holder(&keys);
    let aliased = alias(owner, [7; 32]);
    let witnesses = [opened(keys.regular(false), &[[7; 32]])];
    let scripted = || {
        Script::default()
            .presenting([])
            .on(ENTRY, move |input| {
                let response = if input.from.is_none() {
                    Response::keep_state()
                        .send(call_with(aliased, b"query"))
                        .send(call_with(owner, b"query"))
                } else {
                    Response::keep_state()
                };
                echo(input, response)
            })
            .on(owner, |input| {
                let sender = input.from.expect("a query has a sender");
                echo(
                    input,
                    Response::keep_state().send(call_with(sender, b"answer")),
                )
            })
    };
    let Pipeline {
        whole: simulating,
        boundary,
        ..
    } = pipeline(&[ENTRY], &witnesses, ENTRY, scripted);

    assert_eq!(
        order(&simulating),
        vec![
            (ENTRY, None),
            (owner, Some(ENTRY)),
            (ENTRY, Some(aliased)),
            (owner, Some(ENTRY)),
            (ENTRY, Some(owner)),
        ]
    );
    assert_eq!(
        public_calls(&boundary),
        vec![
            delivery(aliased, ENTRY, b"answer"),
            delivery(owner, ENTRY, b"answer")
        ]
    );
}
#[test]
fn a_cast_reply_to_a_private_call_can_blind_its_sender() {
    let (caller_keys, callee_keys) = (Keys::new(1), Keys::new(2));
    let (caller, callee) = (holder(&caller_keys), holder(&callee_keys));
    let mut script = Script::default()
        .presenting([
            SenderPresentation::Blinded([5; 32]),
            SenderPresentation::Blinded([6; 32]),
        ])
        .on(caller, sending(vec![send_to(callee)]))
        .on(callee, |input| {
            echo(
                input,
                Response::keep_state().send(Cast {
                    to: input.from.expect("a call has a sender"),
                    message: b"reply".to_vec(),
                }),
            )
        });

    let outcome = private_part(
        PublicExecutionContext::default(),
        &[caller_keys.regular(false), callee_keys.regular(false)],
        root(caller),
        Vec::new(),
        &mut script,
    )
    .unwrap();

    assert!(outcome.boundary.is_empty());
    assert_eq!(
        outcome.casts,
        vec![MessageBody {
            from: alias(callee, [6; 32]),
            to: alias(caller, [5; 32]),
            message: b"reply".to_vec(),
        }]
    );
}

#[test]
fn a_private_message_without_a_presentation_is_refused() {
    let keys = Keys::new(1);
    let owner = holder(&keys);
    let mut script = Script::default()
        .presenting([])
        .on(owner, sending(vec![send_to(ENTRY)]));

    let result = private_part(
        context(vec![ENTRY]),
        &[keys.regular(false)],
        root(owner),
        vec![Vec::new()],
        &mut script,
    );

    assert!(matches!(
        result,
        Err(ExecutionError::MissingSenderPresentation { sender }) if sender == owner
    ));
}

#[test]
fn each_message_of_a_private_transition_presents_the_sender_its_presentation_selects() {
    let keys = Keys::new(1);
    let owner = holder(&keys);
    let target = actor(6, 7);
    let mut script = Script::default()
        .presenting([
            SenderPresentation::Blinded([1; 32]),
            SenderPresentation::Canonical,
            SenderPresentation::Blinded([2; 32]),
        ])
        .on(owner, move |input| {
            echo(
                input,
                Response::keep_state()
                    .send(send_to(ENTRY))
                    .send(Cast {
                        to: target,
                        message: Vec::new(),
                    })
                    .send(send_to(BYSTANDER)),
            )
        });

    let outcome = private_part(
        context(vec![ENTRY, BYSTANDER]),
        &[keys.regular(false)],
        root(owner),
        vec![Vec::new(), Vec::new()],
        &mut script,
    )
    .unwrap();

    assert_eq!(
        public_calls(&outcome.boundary),
        vec![
            delivery(alias(owner, [1; 32]), ENTRY, &[]),
            delivery(owner, BYSTANDER, &[])
        ]
    );
    assert_eq!(
        outcome.casts,
        vec![MessageBody {
            from: alias(owner, [2; 32]),
            to: target,
            message: Vec::new(),
        }]
    );
}

#[test]
fn a_cast_at_an_opened_alias_is_received_privately_by_the_account() {
    let keys = Keys::new(1);
    let owner = holder(&keys);
    let record = stored(ENTRY, alias(owner, [7; 32]), b"stored");
    let mut script = Script::default().on(owner, sending(Vec::new()));

    let outcome = private_part(
        PublicExecutionContext::default(),
        &[opened(keys.regular(false), &[[7; 32]])],
        TransactionEntry::Cast(record),
        Vec::new(),
        &mut script,
    )
    .unwrap();

    assert_eq!(order(&script), vec![(owner, Some(ENTRY))]);
    assert_eq!(outcome.boundary, Boundary::default());
}

fn cast_with(to: Actor, message: &[u8]) -> Cast {
    Cast {
        to,
        message: message.to_vec(),
    }
}

#[test]
fn casts_to_declared_public_actors_run_after_their_emitters_calls_and_publish_nothing() {
    let (parent, first, second) = (actor(1, 9), actor(2, 9), actor(3, 9));
    let (third, fourth, nested) = (actor(4, 9), actor(5, 9), actor(6, 9));
    let mut script = Script::default()
        .on(parent, move |input| {
            echo(
                input,
                Response::keep_state()
                    .send(send_to(first))
                    .send(cast_with(third, &[]))
                    .send(send_to(second))
                    .send(cast_with(fourth, &[])),
            )
        })
        .on(first, sending(Vec::new()))
        .on(second, sending(Vec::new()))
        .on(third, move |input| {
            echo(input, Response::keep_state().send(cast_with(nested, &[])))
        })
        .on(fourth, sending(Vec::new()))
        .on(nested, sending(Vec::new()));

    let outcome = public_transaction(
        context(vec![parent, first, second, third, fourth, nested]),
        parent,
        &mut script,
    )
    .unwrap();

    assert_eq!(
        order(&script),
        vec![
            (parent, None),
            (first, Some(parent)),
            (second, Some(parent)),
            (third, Some(parent)),
            (nested, Some(third)),
            (fourth, Some(parent)),
        ]
    );
    assert!(outcome.casts.is_empty());
}

#[test]
fn a_cast_to_a_declared_but_unadmitted_account_is_refused() {
    let (parent, target) = (actor(1, 9), actor(2, 9));
    let scripted = || {
        Script::default()
            .on(parent, move |input| {
                echo(input, Response::keep_state().send(cast_with(target, &[])))
            })
            .on(target, sending(Vec::new()))
    };

    let mut refused = scripted().refusing(target);
    let result = public_transaction(context(vec![parent, target]), parent, &mut refused);
    let mut promoted = scripted();
    public_transaction(context(vec![parent, target]), parent, &mut promoted).unwrap();

    assert!(matches!(
        result,
        Err(ExecutionError::UnadmittedPublicActor { actor }) if actor == target
    ));
    assert_eq!(order(&refused), vec![(parent, None)]);
    assert_eq!(
        order(&promoted),
        vec![(parent, None), (target, Some(parent))]
    );
}

// `owner` seeds `vault`, whose sibling Call keeps the grant; vault's promoted Cast reaches `relay`,
// whose call back does not, though relay's own seed grants afresh. The signer keeps its credential.
#[test]
fn a_promoted_cast_delegates_no_authorization_but_keeps_transaction_credentials() {
    let (owner, sibling, relay, signer) = (actor(1, 9), actor(2, 7), actor(3, 8), actor(4, 7));
    let (seed, relay_seed) = (PdaSeed::new([5; 32]), PdaSeed::new([6; 32]));
    let vault = public_pda(owner.program_account_id, seed);
    let relay_vault = public_pda(relay.program_account_id, relay_seed);
    let mut script = Script::default()
        .on(owner, move |input| {
            echo(
                input,
                Response::keep_state()
                    .send(Call {
                        message: b"seeded".to_vec(),
                        ..seeded_to(vault, seed)
                    })
                    .send(cast_with(vault, &[]))
                    .send(cast_with(signer, &[])),
            )
        })
        .on(vault, move |input| {
            let response = if input.message == b"seeded" {
                Response::keep_state()
                    .send(send_to(sibling))
                    .send(cast_with(relay, &[]))
            } else {
                Response::keep_state()
            };
            echo(input, response)
        })
        .on(sibling, sending(vec![send_to(vault)]))
        .on(
            relay,
            sending(vec![send_to(vault), seeded_to(relay_vault, relay_seed)]),
        )
        .on(relay_vault, sending(Vec::new()))
        .on(signer, sending(Vec::new()));

    public_transaction(
        PublicExecutionContext {
            authorized_accounts: BTreeSet::from([signer.account_id]),
            ..context(vec![owner, vault, sibling, relay, relay_vault, signer])
        },
        owner,
        &mut script,
    )
    .unwrap();

    assert_eq!(
        authorized(&script),
        vec![
            (owner, false),
            (vault, true),
            (sibling, false),
            (vault, true),
            (relay, false),
            (vault, false),
            (relay_vault, true),
            (vault, false),
            (signer, true),
        ]
    );
}

// The private `owner` seeds its PDA `custody`, which calls public `peer`; peer calls custody and
// reaches public `relay`, by Cast when `cast` and otherwise by Call, whose call back reseeds
// custody when `regrant`. `forge` flips the inheritance the proof claims for that callback.
fn custody_callbacks(
    cast: bool,
    regrant: bool,
    forge: bool,
) -> (
    Vec<bool>,
    Vec<bool>,
    Vec<bool>,
    Result<PublicOutcome, ExecutionError>,
) {
    let (keys, pda_keys) = (Keys::new(1), Keys::new(2));
    let owner = holder(&keys);
    let seed = PdaSeed::new([5; 32]);
    let custody = Actor::new(pda_keys.pda_id(owner.program_account_id, seed), id(8));
    let (peer, relay) = (actor(3, 9), actor(4, 8));
    let witnesses = [
        keys.regular(false),
        pda_keys.pda(owner.program_account_id, seed),
    ];
    let callback = if regrant {
        seeded_to(custody, seed)
    } else {
        send_to(custody)
    };
    let script = || {
        Script::default()
            .on(owner, sending(vec![seeded_to(custody, seed)]))
            .on(custody, sending_when(Some(owner), vec![send_to(peer)]))
            .on(peer, move |input| {
                let response = Response::keep_state().send(send_to(custody));
                echo(
                    input,
                    if cast {
                        response.cast(relay, &())
                    } else {
                        response.call(relay, &())
                    },
                )
            })
            .on(relay, sending(vec![callback.clone()]))
    };
    let custody_authorizations = |executed: &Script| {
        authorized(executed)
            .into_iter()
            .filter_map(|(actor, is_authorized)| (actor == custody).then_some(is_authorized))
            .collect()
    };

    let mut whole_script = script();
    let mut predicted_cross_messages = whole(
        context(vec![peer, relay]),
        &witnesses,
        root(owner),
        &mut whole_script,
    )
    .unwrap()
    .predicted_cross_messages;
    if forge {
        let forged = predicted_cross_messages[0]
            .last_mut()
            .expect("relay's callback is the last cross message of peer's call");
        assert!(forged.inherited_authorizations.is_empty());
        forged.inherits_entry_authorizations = !forged.inherits_entry_authorizations;
    }
    let mut private_script = script();
    let boundary = private_part(
        context(vec![peer, relay]),
        &witnesses,
        root(owner),
        predicted_cross_messages,
        &mut private_script,
    )
    .unwrap()
    .boundary;
    let inheritance = boundary
        .iter()
        .filter_map(|step| match step {
            PublicToPrivate(delivery) => Some(delivery.inherits_entry_authorizations),
            PrivateToPublic(_) | EndPrivateSubtree | EndPublicSubtree => None,
        })
        .collect();
    let settled = public_part(
        context(vec![peer, relay]),
        root_call(owner),
        boundary,
        &mut script(),
    );
    (
        custody_authorizations(&whole_script),
        custody_authorizations(&private_script),
        inheritance,
        settled,
    )
}

#[test]
fn a_withheld_private_grant_returns_along_calls_but_not_across_a_promoted_cast() {
    for (cast, regrant, expected) in [
        (false, false, [true, true, true]),
        (true, false, [true, true, false]),
        (true, true, [true, true, true]),
    ] {
        let (in_whole, in_private, inheritance, settled) = custody_callbacks(cast, regrant, false);

        assert_eq!(in_whole, expected, "cast {cast}, regrant {regrant}");
        assert_eq!(in_private, expected, "cast {cast}, regrant {regrant}");
        assert_eq!(inheritance, [true, !cast], "cast {cast}");
        settled.unwrap_or_else(|error| panic!("cast {cast}, regrant {regrant}: {error:?}"));
    }
}

#[test]
fn settlement_refuses_a_forged_inheritance_bit_beside_matching_authorizations() {
    for cast in [false, true] {
        let (_, in_private, inheritance, settled) = custody_callbacks(cast, false, true);

        assert_eq!(in_private[2], cast, "cast {cast}");
        assert_eq!(inheritance, [true, cast], "cast {cast}");
        assert!(
            matches!(
                settled,
                Err(ExecutionError::CrossMessageMismatch { index: 3 })
            ),
            "cast {cast}"
        );
    }
}

// Runs `script` from the private `owner` beside the `public` actors, whole and then composed,
// settles the composed boundary, and returns the private transitions' authorizations from both
// runs.
fn private_authorizations(
    script: impl Fn() -> Script,
    public: &[Actor],
    witnesses: &[PrivateWitness],
    owner: Actor,
) -> [Vec<(Actor, bool)>; 2] {
    let Pipeline { whole, private, .. } = pipeline(public, witnesses, owner, script);
    [
        authorized(&whole)
            .into_iter()
            .filter(|(actor, _)| !public.contains(actor))
            .collect(),
        authorized(&private),
    ]
}

// Custody's first call from `peer` detours through public `relay`, whose promoted Cast reaches
// `back`, which calls custody without the grant; peer's later call still carries it.
#[test]
fn a_promoted_cast_inside_a_nested_detour_clears_only_its_own_callbacks() {
    let (keys, pda_keys) = (Keys::new(1), Keys::new(2));
    let owner = holder(&keys);
    let seed = PdaSeed::new([5; 32]);
    let custody = Actor::new(pda_keys.pda_id(owner.program_account_id, seed), id(8));
    let (peer, relay, back) = (actor(3, 9), actor(4, 7), actor(5, 7));
    let witnesses = [
        keys.regular(false),
        pda_keys.pda(owner.program_account_id, seed),
    ];
    let script = || {
        Script::default()
            .on(owner, sending(vec![seeded_to(custody, seed)]))
            .on(custody, move |input| {
                let calls = if input.from == Some(owner) {
                    vec![send_to(peer)]
                } else if input.message == ENTER {
                    vec![send_to(relay)]
                } else {
                    Vec::new()
                };
                echo(
                    input,
                    Response {
                        calls,
                        ..Response::keep_state()
                    },
                )
            })
            .on(
                peer,
                sending(vec![
                    Call {
                        message: ENTER.to_vec(),
                        ..send_to(custody)
                    },
                    send_to(custody),
                ]),
            )
            .on(relay, move |input| {
                echo(input, Response::keep_state().send(cast_with(back, &[])))
            })
            .on(back, sending(vec![send_to(custody)]))
    };
    let expected = vec![
        (owner, false),
        (custody, true),
        (custody, true),
        (custody, false),
        (custody, true),
    ];

    let [in_whole, in_private] =
        private_authorizations(script, &[peer, relay, back], &witnesses, owner);

    assert_eq!(in_whole, expected);
    assert_eq!(in_private, expected);
}

// `owner` casts to itself, then seeds `custody`, whose detour through public `peer` starts a new
// entry: peer's call back restores custody's grant although the path began with a promoted Cast.
#[test]
fn a_public_detour_after_a_promoted_cast_still_returns_what_its_entry_withheld() {
    let (keys, pda_keys) = (Keys::new(1), Keys::new(2));
    let owner = holder(&keys);
    let seed = PdaSeed::new([5; 32]);
    let custody = Actor::new(pda_keys.pda_id(owner.program_account_id, seed), id(8));
    let peer = actor(3, 9);
    let witnesses = [
        keys.regular(false),
        pda_keys.pda(owner.program_account_id, seed),
    ];
    let script = || {
        Script::default()
            .promoting(Placement::Private, 0)
            .on(owner, move |input| {
                let response = if input.from.is_none() {
                    Response::keep_state().send(cast_with(owner, ENTER))
                } else {
                    Response::keep_state().send(seeded_to(custody, seed))
                };
                echo(input, response)
            })
            .on(custody, sending_when(Some(owner), vec![send_to(peer)]))
            .on(peer, sending(vec![send_to(custody)]))
    };
    let expected = vec![
        (owner, false),
        (owner, false),
        (custody, true),
        (custody, true),
    ];

    let [in_whole, in_private] = private_authorizations(script, &[peer], &witnesses, owner);

    assert_eq!(in_whole, expected);
    assert_eq!(in_private, expected);
}

#[test]
fn a_promoted_private_cast_keeps_its_own_presentation_and_crosses_after_the_calls() {
    let keys = Keys::new(1);
    let owner = holder(&keys);
    let mut script = Script::default()
        .presenting([
            SenderPresentation::Blinded([1; 32]),
            SenderPresentation::Blinded([2; 32]),
        ])
        .on(owner, move |input| {
            echo(
                input,
                Response::keep_state()
                    .send(cast_with(ENTRY, &[]))
                    .send(send_to(BYSTANDER)),
            )
        });

    let outcome = private_part(
        context(vec![ENTRY, BYSTANDER]),
        &[keys.regular(false)],
        root(owner),
        vec![Vec::new(), Vec::new()],
        &mut script,
    )
    .unwrap();

    assert_eq!(
        public_calls(&outcome.boundary),
        vec![
            delivery(alias(owner, [1; 32]), BYSTANDER, &[]),
            delivery(alias(owner, [2; 32]), ENTRY, &[]),
        ]
    );
    assert!(outcome.casts.is_empty());
}

#[test]
fn a_selected_cast_between_witnessed_private_accounts_runs_inside_the_private_part() {
    let (keys, other) = (Keys::new(1), Keys::new(2));
    let (owner, recipient) = (holder(&keys), holder(&other));
    let mut script = Script::default()
        .promoting(Placement::Private, 0)
        .on(owner, move |input| {
            echo(
                input,
                Response::keep_state().send(cast_with(recipient, b"x")),
            )
        })
        .on(recipient, sending(Vec::new()));

    let outcome = private_part(
        context(Vec::new()),
        &[keys.regular(false), other.regular(false)],
        root(owner),
        Vec::new(),
        &mut script,
    )
    .unwrap();

    assert_eq!(
        order(&script),
        vec![(owner, None), (recipient, Some(owner))]
    );
    assert_eq!(outcome.boundary, Boundary::default());
    assert!(outcome.casts.is_empty());
}

#[test]
fn a_selected_public_cast_into_a_private_account_is_a_predicted_cross_message() {
    let keys = Keys::new(1);
    let owner = holder(&keys);
    let scripted = |message: &'static [u8]| {
        Script::default()
            .promoting(Placement::Public, 0)
            .on(ENTRY, move |input| {
                echo(
                    input,
                    Response::keep_state().send(cast_with(owner, message)),
                )
            })
            .on(owner, sending(Vec::new()))
    };
    let Pipeline {
        predicted_cross_messages,
        boundary,
        ..
    } = pipeline(&[ENTRY], &[keys.regular(false)], ENTRY, || scripted(b"m"));
    assert_eq!(
        predicted_cross_messages,
        vec![vec![Delivery {
            inherits_entry_authorizations: false,
            ..delivery(ENTRY, owner, b"m")
        }]]
    );
    assert!(matches!(
        public_part(
            context(vec![ENTRY]),
            root_call(ENTRY),
            boundary,
            &mut scripted(b"n")
        ),
        Err(ExecutionError::CrossMessageMismatch { .. })
    ));
}

// The private root casts `p` to `other` and calls ENTRY, which casts `x` back to the root and calls
// CALLEE, which casts `y` to `other`: ENTRY's Cast is numbered before CALLEE's and runs after it.
#[test]
fn every_part_numbers_the_same_candidates_and_a_parents_cast_runs_after_its_childs() {
    let (keys, other_keys) = (Keys::new(1), Keys::new(2));
    let (owner, other) = (holder(&keys), holder(&other_keys));
    let scripted = || {
        Script::default()
            .promoting(Placement::Private, 0)
            .promoting(Placement::Public, 0)
            .promoting(Placement::Public, 1)
            .on(owner, move |input| {
                let response = if input.from.is_none() {
                    Response::keep_state()
                        .send(cast_with(other, b"p"))
                        .send(send_to(ENTRY))
                } else {
                    Response::keep_state()
                };
                echo(input, response)
            })
            .on(ENTRY, move |input| {
                echo(
                    input,
                    Response::keep_state()
                        .send(cast_with(owner, b"x"))
                        .send(send_to(CALLEE)),
                )
            })
            .on(CALLEE, move |input| {
                echo(input, Response::keep_state().send(cast_with(other, b"y")))
            })
            .on(other, sending(Vec::new()))
    };
    let witnesses = [keys.regular(false), other_keys.regular(false)];
    let offered = |script: &Script, placement: Placement| -> Vec<(u64, Actor)> {
        script
            .offered
            .iter()
            .filter(|offer| offer.0 == placement)
            .map(|&(_, index, to)| (index, to))
            .collect()
    };

    let Pipeline {
        whole: whole_script,
        private: private_script,
        public: public_script,
        ..
    } = pipeline(&[ENTRY, CALLEE], &witnesses, owner, scripted);
    assert_eq!(
        order(&whole_script),
        vec![
            (owner, None),
            (ENTRY, Some(owner)),
            (CALLEE, Some(ENTRY)),
            (other, Some(CALLEE)),
            (owner, Some(ENTRY)),
            (other, Some(owner)),
        ]
    );
    assert_eq!(offered(&whole_script, Placement::Private), vec![(0, other)]);
    assert_eq!(
        offered(&whole_script, Placement::Public),
        vec![(0, owner), (1, other)]
    );
    assert_eq!(
        offered(&private_script, Placement::Private),
        vec![(0, other)]
    );
    assert!(offered(&private_script, Placement::Public).is_empty());
    assert_eq!(
        offered(&public_script, Placement::Public),
        vec![(0, owner), (1, other)]
    );
    assert!(offered(&public_script, Placement::Private).is_empty());
}

// ENTRY casts `m` to the private root's account, then CALLEE has it cast `m` again before setting
// BYSTANDER, whose state the root's callback, when there is one, reads back.
fn identical_casts(callback: bool, selected: u64) -> Script {
    let owner = holder(&Keys::new(1));
    Script::default()
        .promoting(Placement::Public, selected)
        .on(ENTRY, move |input| {
            let response = Response::keep_state().send(cast_with(owner, b"m"));
            echo(
                input,
                if input.from.is_none() {
                    response.send(send_to(CALLEE))
                } else {
                    response
                },
            )
        })
        .on(
            CALLEE,
            sending(vec![
                send_to(ENTRY),
                Call {
                    message: b"set".to_vec(),
                    ..send_to(BYSTANDER)
                },
            ]),
        )
        .on(BYSTANDER, move |input| {
            let response = if input.message == b"set" {
                Response::set_state(data(b"set"))
            } else {
                Response::keep_state().send(Call {
                    message: input.pre_state.to_vec(),
                    ..send_to(owner)
                })
            };
            echo(input, response)
        })
        .on(owner, move |input| {
            let response = if callback && input.message == b"m" {
                Response::keep_state().send(Call {
                    message: b"read".to_vec(),
                    ..send_to(BYSTANDER)
                })
            } else {
                Response::keep_state()
            };
            echo(input, response)
        })
}

#[test]
fn identical_casts_on_either_side_of_public_work_are_selected_by_index() {
    let witnesses = [Keys::new(1).regular(false)];
    for callback in [false, true] {
        for proven in [0, 1] {
            let Pipeline {
                predicted_cross_messages,
                boundary,
                ..
            } = pipeline(&[ENTRY, CALLEE, BYSTANDER], &witnesses, ENTRY, || {
                identical_casts(callback, proven)
            });
            if callback {
                let read: &[u8] = if proven == 0 { b"set" } else { b"" };
                assert_eq!(predicted_cross_messages[1][0].envelope.message, read);
            }
            let settled = 1 - proven;
            let result = public_part(
                context(vec![ENTRY, CALLEE, BYSTANDER]),
                root_call(ENTRY),
                boundary,
                &mut identical_casts(callback, settled),
            );
            if callback {
                assert!(
                    matches!(result, Err(ExecutionError::CrossMessageMismatch { .. })),
                    "proven {proven}, settled {settled}"
                );
            } else {
                assert!(result.is_ok(), "proven {proven}, settled {settled}");
            }
        }
    }
}

#[test]
fn a_selected_cast_to_an_undeclared_actor_of_a_declared_account_is_refused_like_a_call() {
    let undeclared = Actor::new(CALLEE.account_id, id(7));
    let scripted = |selected: bool| {
        let script = Script::default().on(ENTRY, move |input| {
            echo(
                input,
                Response::keep_state().send(cast_with(undeclared, b"m")),
            )
        });
        if selected {
            script.promoting(Placement::Public, 0)
        } else {
            script
        }
    };

    let published = public_transaction(context(vec![ENTRY, CALLEE]), ENTRY, &mut scripted(false))
        .unwrap()
        .casts;
    let in_whole = public_transaction(context(vec![ENTRY, CALLEE]), ENTRY, &mut scripted(true));
    let in_public_part = public_part(
        context(vec![ENTRY, CALLEE]),
        root_call(ENTRY),
        Boundary::default(),
        &mut scripted(true),
    );

    assert_eq!(published, vec![stored(ENTRY, undeclared, b"m")]);
    for result in [in_whole, in_public_part] {
        assert!(matches!(
            result,
            Err(ExecutionError::UndeclaredActor { actor }) if actor == undeclared
        ));
    }
}

#[test]
fn a_root_a_call_and_a_promoted_cast_reaching_a_refused_account_are_unadmitted() {
    let scripted = |refused: Actor| {
        Script::default()
            .refusing(refused)
            .on(ENTRY, move |input| {
                echo(
                    input,
                    Response::keep_state()
                        .send(send_to(CALLEE))
                        .send(cast_with(BYSTANDER, &[])),
                )
            })
            .on(CALLEE, sending(Vec::new()))
            .on(BYSTANDER, sending(Vec::new()))
    };
    let actors = || context(vec![ENTRY, CALLEE, BYSTANDER]);

    for refused in [ENTRY, CALLEE, BYSTANDER] {
        for result in [
            public_transaction(actors(), ENTRY, &mut scripted(refused)),
            public_part(
                actors(),
                root_call(ENTRY),
                Boundary::default(),
                &mut scripted(refused),
            ),
        ] {
            assert!(
                matches!(
                    result,
                    Err(ExecutionError::UnadmittedPublicActor { actor }) if actor == refused
                ),
                "{refused:?}"
            );
        }
    }
}

#[test]
fn a_seeded_call_admits_its_pda_for_the_rest_of_the_transaction_without_asking() {
    let seed = PdaSeed::new([5; 32]);
    let vault = public_pda(ENTRY.program_account_id, seed);
    let scripted = |entry_sends: Vec<Call>| {
        Script::default()
            .refusing(vault)
            .on(ENTRY, sending(entry_sends))
            .on(CALLEE, sending(vec![send_to(vault)]))
            .on(vault, sending(Vec::new()))
    };
    let actors = || context(vec![ENTRY, CALLEE, vault]);

    let mut seeded_first = scripted(vec![seeded_to(vault, seed), send_to(CALLEE)]);
    public_transaction(actors(), ENTRY, &mut seeded_first).unwrap();
    let unseeded_first = public_transaction(
        actors(),
        ENTRY,
        &mut scripted(vec![send_to(CALLEE), seeded_to(vault, seed)]),
    );

    assert_eq!(
        order(&seeded_first),
        vec![
            (ENTRY, None),
            (vault, Some(ENTRY)),
            (CALLEE, Some(ENTRY)),
            (vault, Some(CALLEE)),
        ]
    );
    assert!(matches!(
        unseeded_first,
        Err(ExecutionError::UnadmittedPublicActor { actor }) if actor == vault
    ));
}

#[test]
fn a_private_part_asks_no_public_account_for_admission() {
    let keys = Keys::new(1);
    let owner = holder(&keys);
    let mut script = Script::default()
        .refusing(ENTRY)
        .on(owner, sending(vec![send_to(ENTRY)]));

    let outcome = private_part(
        context(vec![ENTRY]),
        &[keys.regular(false)],
        root(owner),
        vec![Vec::new()],
        &mut script,
    )
    .unwrap();

    assert_eq!(
        public_calls(&outcome.boundary),
        vec![delivery(owner, ENTRY, &[])]
    );
}

#[test]
fn a_receipt_root_to_a_private_pda_grants_its_receiver_nothing() {
    let (keys, seed) = (Keys::new(1), PdaSeed::new([5; 32]));
    let custody = Actor::new(keys.pda_id(id(5), seed), id(5));
    let mut script = Script::default().on(custody, sending(Vec::new()));

    private_part(
        PublicExecutionContext::default(),
        &[keys.pda(id(5), seed)],
        TransactionEntry::Cast(stored(actor(4, 5), custody, b"stored")),
        Vec::new(),
        &mut script,
    )
    .unwrap();

    assert_eq!(
        script.log,
        vec![ReceiveInput {
            receiver: custody,
            from: Some(actor(4, 5)),
            is_authorized: false,
            pre_state: ActorState::empty(),
            message: b"stored".to_vec(),
        }]
    );
}

#[test]
fn a_selected_cast_whose_boundary_step_misstates_its_sender_destination_or_grants_is_refused() {
    let keys = Keys::new(1);
    let owner = holder(&keys);
    let scripted = || {
        Script::default()
            .promoting(Placement::Public, 0)
            .on(ENTRY, move |input| {
                echo(input, Response::keep_state().send(cast_with(owner, b"m")))
            })
            .on(owner, sending(Vec::new()))
    };
    let boundary = pipeline(&[ENTRY], &[keys.regular(false)], ENTRY, scripted).boundary;
    let Some(PublicToPrivate(selected)) = boundary.first() else {
        panic!("the selected Cast is the first crossing");
    };
    let envelope = |envelope: MessageEnvelope<Actor>| Delivery {
        envelope,
        ..selected.clone()
    };

    for forged in [
        envelope(MessageEnvelope {
            from: CALLEE,
            ..selected.envelope.clone()
        }),
        envelope(MessageEnvelope {
            to: holder(&Keys::new(2)),
            ..selected.envelope.clone()
        }),
        Delivery {
            inherited_authorizations: BTreeSet::from([ENTRY.account_id]),
            ..selected.clone()
        },
        Delivery {
            inherits_entry_authorizations: true,
            ..selected.clone()
        },
    ] {
        let mut forged_boundary = boundary.clone();
        forged_boundary[0] = PublicToPrivate(forged);

        assert!(matches!(
            public_part(
                context(vec![ENTRY]),
                root_call(ENTRY),
                forged_boundary,
                &mut scripted()
            ),
            Err(ExecutionError::CrossMessageMismatch { .. })
        ));
    }
}

// The private root calls ENTRY, which casts `e` to `other` and calls the root back; the callback
// casts `q` to `other` and calls CALLEE, which casts `z` to `other`: a private emission after
// re-entry, and a public one in the subtree a private callback entered, numbered after ENTRY's.
#[test]
fn every_part_numbers_the_candidates_of_a_private_callbacks_public_subtree_alike() {
    let (keys, other_keys) = (Keys::new(1), Keys::new(2));
    let (owner, other) = (holder(&keys), holder(&other_keys));
    let scripted = || {
        Script::default()
            .on(owner, move |input| {
                let response = if input.from.is_none() {
                    Response::keep_state().send(send_to(ENTRY))
                } else {
                    Response::keep_state()
                        .send(cast_with(other, b"q"))
                        .send(send_to(CALLEE))
                };
                echo(input, response)
            })
            .on(ENTRY, move |input| {
                echo(
                    input,
                    Response::keep_state()
                        .send(cast_with(other, b"e"))
                        .send(send_to(owner)),
                )
            })
            .on(CALLEE, move |input| {
                echo(input, Response::keep_state().send(cast_with(other, b"z")))
            })
    };
    let witnesses = [keys.regular(false), other_keys.regular(false)];
    let offered = |script: &Script, placement: Placement| -> Vec<(u64, Actor)> {
        script
            .offered
            .iter()
            .filter(|offer| offer.0 == placement)
            .map(|&(_, index, to)| (index, to))
            .collect()
    };

    let Pipeline {
        whole: whole_script,
        private: private_script,
        public: public_script,
        ..
    } = pipeline(&[ENTRY, CALLEE], &witnesses, owner, scripted);
    for script in [&whole_script, &private_script] {
        assert_eq!(offered(script, Placement::Private), vec![(0, other)]);
    }
    for script in [&whole_script, &public_script] {
        assert_eq!(
            offered(script, Placement::Public),
            vec![(0, other), (1, other)]
        );
    }
    assert!(offered(&private_script, Placement::Public).is_empty());
    assert!(offered(&public_script, Placement::Private).is_empty());
}

#[test]
fn a_generated_call_graph_runs_the_same_whole_and_split() {
    for seed in 0..200 {
        let graph = Graph::generate(seed);
        let witnesses: Vec<PrivateWitness> =
            graph.keys.iter().map(|keys| keys.regular(false)).collect();
        let entry = RootCall {
            to: graph.root,
            message: vec![GENERATED_DEPTH],
        };

        let mut whole_script = graph.script();
        let whole_outcome = whole(
            context(graph.public.clone()),
            &witnesses,
            TransactionEntry::Call(entry.clone()),
            &mut whole_script,
        )
        .unwrap_or_else(|error| panic!("seed {seed}: the whole run failed: {error:?}"));
        let mut private_script = graph.script();
        let private_outcome = private_part(
            context(graph.public.clone()),
            &witnesses,
            TransactionEntry::Call(entry.clone()),
            whole_outcome.predicted_cross_messages,
            &mut private_script,
        )
        .unwrap_or_else(|error| panic!("seed {seed}: the private part failed: {error:?}"));
        let mut public_script = graph.script();
        let public_outcome = public_part(
            context(graph.public.clone()),
            entry,
            private_outcome.boundary,
            &mut public_script,
        )
        .unwrap_or_else(|error| panic!("seed {seed}: the public part failed: {error:?}"));

        let private_accounts: BTreeSet<AccountId> =
            graph.keys.iter().map(Keys::regular_id).collect();
        let (private_log, public_log): (Vec<_>, Vec<_>) = whole_script
            .log
            .into_iter()
            .partition(|input| private_accounts.contains(&input.receiver.account_id));
        assert_eq!(
            private_log, private_script.log,
            "seed {seed}: private transitions"
        );
        assert_eq!(
            public_log, public_script.log,
            "seed {seed}: public transitions"
        );
        assert_eq!(
            whole_outcome.public.accounts, public_outcome.accounts,
            "seed {seed}: public writes"
        );
    }
}
