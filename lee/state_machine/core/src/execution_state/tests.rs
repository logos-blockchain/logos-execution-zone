use super::{
    BoundaryStep::{EndPrivateSubtree, EndPublicSubtree, PrivateToPublic, PublicToPrivate},
    *,
};
use crate::{
    AuthorizationSecretKey, NullifierPublicKey, NullifierSecretKey, NullifierWitness, RegularKey,
    WitnessKind,
    encryption::ViewingPublicKey,
    native_token,
    program::{AsyncMessage, BlockValidityWindow, Response, SyncMessage},
};

const ENTRY: Actor = Actor::new(AccountId::new([1; 32]), AccountId::new([9; 32]));
const CALLEE: Actor = Actor::new(AccountId::new([2; 32]), AccountId::new([9; 32]));
const BYSTANDER: Actor = Actor::new(AccountId::new([3; 32]), AccountId::new([9; 32]));
const ENTER: &[u8] = b"enter";
const GENERATED_DEPTH: u8 = 3;
const READ_BACK: u8 = u8::MAX;
const OPENING: [u8; 32] = [42; 32];

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
                let mut sends: Vec<SyncMessage> = calls
                    .get(&(receiver, depth))
                    .into_iter()
                    .flatten()
                    .map(|&to| SyncMessage {
                        message: vec![next],
                        ..send_to(to)
                    })
                    .collect();
                if depth == GENERATED_DEPTH {
                    sends.extend(read_back.iter().map(|&to| SyncMessage {
                        message: vec![READ_BACK],
                        ..send_to(to)
                    }));
                }
                let mut written = input.pre_state.to_vec();
                written.push(depth);
                echo(
                    input,
                    Response {
                        sync_messages: sends,
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
            address_openings: BTreeSet::new(),
            signer_programs: BTreeSet::new(),
        }
    }

    fn regular(&self, ask: bool) -> PrivateWitness {
        let witness = self.witness(WitnessKind::Regular(if ask {
            RegularKey::Authorized(self.ask)
        } else {
            RegularKey::Nullifying(self.nsk())
        }));
        PrivateWitness {
            signer_programs: BTreeSet::from([id(8), native_token::NATIVE_TOKEN_PROGRAM_ID]),
            ..witness
        }
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
        assert_eq!(
            input.is_authorized,
            input.grants.contains(&input.receiver),
            "a handler is authorized exactly when it holds its own grant"
        );
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

fn send_to(receiver: Actor) -> SyncMessage {
    SyncMessage {
        to: receiver,
        message: Vec::new(),
        pda_seeds: BTreeSet::new(),
        grants: BTreeSet::new(),
    }
}

// The private holder of `Keys::new(1)`, entered from a public transition.
fn enter(message: &[u8]) -> SyncMessage {
    SyncMessage {
        to: holder(&Keys::new(1)),
        message: message.to_vec(),
        pda_seeds: BTreeSet::new(),
        grants: BTreeSet::new(),
    }
}

fn delivery<S>(from: S, to: Actor, message: &[u8]) -> Delivery<S> {
    Delivery {
        envelope: MessageEnvelope {
            from,
            to,
            message: message.to_vec(),
        },
        grants: BTreeSet::new(),
        pda_seeds: BTreeSet::new(),
    }
}

fn echo(input: &ReceiveInput, response: Response) -> Transition {
    response.into_transition(input.clone())
}

fn sending(sync_messages: Vec<SyncMessage>) -> impl Fn(&ReceiveInput) -> Transition {
    move |input| {
        echo(
            input,
            Response {
                sync_messages: sync_messages.clone(),
                ..Response::keep_state()
            },
        )
    }
}

fn sending_when(
    from: Option<Actor>,
    sync_messages: Vec<SyncMessage>,
) -> impl Fn(&ReceiveInput) -> Transition {
    let send = sending(sync_messages);
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
    TransactionEntry::Sync(root_call(to))
}

fn public_context(actors: Vec<Actor>) -> PublicExecutionContext {
    PublicExecutionContext::new(actors.into_iter().map(|actor| (actor, Authority::None)), [])
}

fn whole(
    public_context: PublicExecutionContext,
    witnesses: &[PrivateWitness],
    entry: TransactionEntry<MessageBody>,
    script: &mut Script,
) -> Result<WholeExecutionOutcome, ExecutionError> {
    WholeExecution::new(public_context, entry, Vec::new(), None, witnesses)?.execute(script)
}

fn public_transaction(
    public_context: PublicExecutionContext,
    to: Actor,
    script: &mut Script,
) -> Result<PublicOutcome, ExecutionError> {
    Ok(whole(public_context, &[], root(to), script)?.public)
}

fn private_part(
    public_context: PublicExecutionContext,
    witnesses: &[PrivateWitness],
    entry: TransactionEntry<MessageBody>,
    predicted_cross_messages: PredictedCrossMessages,
    script: &mut Script,
) -> Result<PrivatePartOutcome, ExecutionError> {
    PrivatePart::new(
        public_context,
        entry,
        Vec::new(),
        None,
        witnesses,
        predicted_cross_messages,
    )?
    .execute(script)
}

fn public_part(
    public_context: PublicExecutionContext,
    root: RootCall,
    boundary: Boundary,
    script: &mut Script,
) -> Result<PublicOutcome, ExecutionError> {
    PublicPart::new(public_context, Some(root), boundary)?.execute(script)
}

fn pipeline(
    actors: &[Actor],
    witnesses: &[PrivateWitness],
    to: Actor,
    scripted: impl Fn() -> Script,
) -> Pipeline {
    pipeline_in(&public_context(actors.to_vec()), witnesses, to, scripted)
}

fn pipeline_in(
    context: &PublicExecutionContext,
    witnesses: &[PrivateWitness],
    to: Actor,
    scripted: impl Fn() -> Script,
) -> Pipeline {
    let mut whole_script = scripted();
    let predicted_cross_messages = whole(context.clone(), witnesses, root(to), &mut whole_script)
        .unwrap()
        .predicted_cross_messages;
    let mut private_script = scripted();
    let boundary = private_part(
        context.clone(),
        witnesses,
        root(to),
        predicted_cross_messages.clone(),
        &mut private_script,
    )
    .unwrap()
    .boundary;
    let mut public_script = scripted();
    public_part(
        context.clone(),
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

fn seeded_to(to: Actor, seed: PdaSeed) -> SyncMessage {
    SyncMessage {
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

fn nested_public(script: Script, entry_sends: Vec<SyncMessage>) -> Script {
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
    entry_sends: Vec<SyncMessage>,
) -> (Result<PublicOutcome, ExecutionError>, Script) {
    let mut script = nested_public(Script::default(), entry_sends);
    let result = public_part(
        public_context(vec![ENTRY, CALLEE, BYSTANDER]),
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
    } = public_transaction(public_context(vec![receiver]), receiver, &mut script).unwrap();

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
        public_context(vec![parent, first, second, nested]),
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

    let result = public_transaction(public_context(vec![parent, sibling]), parent, &mut script);

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
        public_transaction(public_context(vec![receiver]), receiver, &mut script),
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

    public_transaction(public_context(vec![looping]), looping, &mut script).unwrap();

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
fn a_seed_grant_reaches_only_the_messages_it_is_attached_to() {
    let (owner, forwarder, relay) = (actor(1, 9), actor(2, 7), actor(3, 8));
    let seed = PdaSeed::new([5; 32]);
    let vault = public_pda(owner.program_account_id, seed);
    let mut script = Script::default()
        .on(
            owner,
            sending(vec![seeded_to(vault, seed), send_to(forwarder)]),
        )
        .on(
            vault,
            sending_when(Some(owner), vec![send_to(relay).with_grants([vault])]),
        )
        .on(
            relay,
            sending(vec![send_to(vault).with_grants([vault]), send_to(vault)]),
        )
        .on(forwarder, sending(vec![send_to(vault)]));

    public_transaction(
        public_context(vec![owner, forwarder, relay, vault]),
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
            (vault, false),
            (forwarder, false),
            (vault, false),
        ]
    );
}

#[test]
fn a_handler_sees_the_grants_its_delivery_carries() {
    let (owner, peer) = (actor(1, 9), actor(2, 7));
    let seed = PdaSeed::new([5; 32]);
    let vault = public_pda(owner.program_account_id, seed);
    let mut script = Script::default()
        .on(owner, sending(vec![seeded_to(vault, seed), send_to(peer)]))
        .on(vault, sending(vec![send_to(peer).with_grants([vault])]))
        .on(peer, sending(Vec::new()));

    public_transaction(public_context(vec![owner, vault, peer]), owner, &mut script).unwrap();

    let held: Vec<_> = script
        .log
        .iter()
        .map(|input| (input.receiver, input.grants.clone()))
        .collect();
    assert_eq!(
        held,
        vec![
            (owner, BTreeSet::new()),
            (vault, BTreeSet::from([vault])),
            (peer, BTreeSet::from([vault])),
            (peer, BTreeSet::new()),
        ]
    );
}

// `signer` signs the root call to `amm`; `feed` is a third party `amm` calls.
fn signed_amm_call(signer: Actor, amm: Actor, feed: Actor) -> PublicExecutionContext {
    PublicExecutionContext::new(
        vec![
            (signer, Authority::Signer),
            (amm, Authority::None),
            (feed, Authority::None),
        ],
        [signer.account_id],
    )
}

#[test]
fn a_grant_passes_along_a_chain_of_holders_that_each_attach_it() {
    let (signer, router, amm) = (actor(1, 9), actor(2, 7), actor(3, 8));
    let mut script = Script::default()
        .on(router, sending(vec![send_to(amm).with_grants([signer])]))
        .on(
            amm,
            sending(vec![send_to(signer).with_grants([signer]), send_to(signer)]),
        )
        .on(signer, sending(Vec::new()));

    public_transaction(signed_amm_call(signer, router, amm), router, &mut script).unwrap();

    assert_eq!(
        authorized(&script),
        vec![
            (router, false),
            (amm, false),
            (signer, true),
            (signer, false)
        ]
    );
}

#[test]
fn a_program_the_root_never_handed_a_grant_cannot_attach_it() {
    let (signer, amm, feed) = (actor(1, 9), actor(2, 7), actor(3, 8));
    let mut script = Script::default()
        .on(amm, sending(vec![send_to(feed)]))
        .on(feed, sending(vec![send_to(signer).with_grants([signer])]));

    let result = public_transaction(signed_amm_call(signer, amm, feed), amm, &mut script);

    assert!(matches!(
        result,
        Err(ExecutionError::UnheldGrant { actor }) if actor == signer
    ));
}

#[test]
fn an_async_root_to_a_signer_actor_carries_no_grant() {
    let (signer, sender) = (actor(1, 9), actor(2, 7));
    let mut script = Script::default().on(signer, sending(Vec::new()));

    whole(
        PublicExecutionContext::new(vec![(signer, Authority::Signer)], [signer.account_id]),
        &[],
        TransactionEntry::Async(stored(sender, signer, b"stored")),
        &mut script,
    )
    .unwrap();

    assert_eq!(authorized(&script), vec![(signer, false)]);
}

#[test]
fn a_private_root_grants_only_the_actors_its_witness_marks() {
    let keys = Keys::new(1);
    let (marked, unmarked) = (holder(&keys), Actor::new(keys.regular_id(), id(7)));
    let mut script = Script::default().on(
        marked,
        sending(vec![send_to(unmarked).with_grants([unmarked])]),
    );

    let result = private_part(
        PublicExecutionContext::default(),
        &[keys.regular(true)],
        root(marked),
        Vec::new(),
        &mut script,
    );

    assert!(matches!(
        result,
        Err(ExecutionError::UnheldGrant { actor }) if actor == unmarked
    ));
    assert_eq!(authorized(&script), vec![(marked, true)]);

    let mut root_script = Script::default().on(unmarked, sending(Vec::new()));
    private_part(
        PublicExecutionContext::default(),
        &[keys.regular(true)],
        root(unmarked),
        Vec::new(),
        &mut root_script,
    )
    .unwrap();
    assert_eq!(authorized(&root_script), vec![(unmarked, false)]);
}

fn blinded(actor: Actor) -> Actor {
    alias(actor, OPENING)
}

fn private_signers(
    actors: Vec<Actor>,
    signers: impl IntoIterator<Item = Actor>,
) -> PublicExecutionContext {
    PublicExecutionContext {
        private_signers: signers.into_iter().collect(),
        ..public_context(actors)
    }
}

// Forwards every grant it holds to `to`.
fn forwarding(to: Actor) -> impl Fn(&ReceiveInput) -> Transition {
    move |input| {
        echo(
            input,
            Response::keep_state().send(send_to(to).with_grants(input.grants.iter().copied())),
        )
    }
}

// Debits every actor whose grant it holds.
fn debiting(input: &ReceiveInput) -> Transition {
    let debits = input
        .grants
        .iter()
        .map(|&grant| send_to(grant).with_grants([grant]))
        .collect();
    echo(
        input,
        Response {
            sync_messages: debits,
            ..Response::keep_state()
        },
    )
}

// The public `router` root holds alice's grant under the alias its message names, hands it to
// `pool`, which debits alice: the chain a public signer's grant takes.
#[test]
fn a_private_signer_grant_passes_along_public_holders_under_its_alias() {
    let keys = Keys::new(1);
    let alice = holder(&keys);
    let (router, pool) = (actor(2, 9), actor(3, 7));
    let context = private_signers(vec![router, pool], [blinded(alice)]);
    let scripted = || {
        Script::default()
            .on(router, forwarding(pool))
            .on(pool, debiting)
            .on(alice, sending(Vec::new()))
    };

    let Pipeline {
        whole,
        private,
        boundary,
        public,
        ..
    } = pipeline_in(
        &context,
        &[opened(keys.regular(true), &[OPENING])],
        router,
        scripted,
    );

    assert_eq!(
        authorized(&whole),
        vec![(router, false), (pool, false), (alice, true)]
    );
    assert_eq!(authorized(&private), vec![(alice, true)]);
    assert_eq!(
        public
            .log
            .iter()
            .map(|input| input.grants.clone())
            .collect::<Vec<_>>(),
        vec![BTreeSet::from([blinded(alice)]); 2]
    );
    assert!(matches!(
        boundary.as_slice(),
        [PublicToPrivate(debit), EndPrivateSubtree]
            if debit.envelope.to == blinded(alice)
                && debit.grants == BTreeSet::from([blinded(alice)])
    ));
}

#[test]
fn a_public_root_holds_no_private_grant_it_does_not_declare() {
    let keys = Keys::new(1);
    let alice = holder(&keys);
    let (router, pool) = (actor(2, 9), actor(3, 7));
    let mut script = Script::default().on(
        router,
        sending(vec![send_to(pool).with_grants([blinded(alice)])]),
    );

    let result = whole(
        public_context(vec![router, pool]),
        &[opened(keys.regular(true), &[OPENING])],
        root(router),
        &mut script,
    );

    assert!(matches!(
        result,
        Err(ExecutionError::UnheldGrant { actor }) if actor == blinded(alice)
    ));
}

#[test]
fn a_declared_private_signer_must_be_an_actor_an_authorized_witness_marks() {
    let keys = Keys::new(1);
    let alice = holder(&keys);
    let router = actor(2, 9);
    let unmarked = Actor::new(alice.account_id, id(7));
    for (witness, signer) in [
        (opened(keys.regular(false), &[OPENING]), blinded(alice)),
        (opened(keys.regular(true), &[OPENING]), blinded(unmarked)),
        (keys.regular(true), blinded(alice)),
    ] {
        let context = private_signers(vec![router], [signer]);
        let witnesses = [witness];

        assert!(matches!(
            whole(context.clone(), &witnesses, root(router), &mut Script::default()),
            Err(ExecutionError::UnmarkedPrivateSigner { actor }) if actor == signer
        ));
        assert!(matches!(
            private_part(context, &witnesses, root(router), vec![Vec::new()], &mut Script::default()),
            Err(ExecutionError::UnmarkedPrivateSigner { actor }) if actor == signer
        ));
    }
}

// Alice's private root hands its grant to the public `router`, which hands it on to `pool`; the
// grant crosses under the address alice calls from, which `pool` debits.
#[test]
fn a_private_root_grant_crossing_out_passes_along_public_holders() {
    let keys = Keys::new(1);
    let alice = holder(&keys);
    let (router, pool) = (actor(2, 9), actor(3, 7));
    let scripted = || {
        Script::default()
            .presenting([SenderPresentation::Blinded(OPENING)])
            .on(
                alice,
                sending_when(None, vec![send_to(router).with_grants([alice])]),
            )
            .on(router, forwarding(pool))
            .on(pool, debiting)
    };

    let Pipeline {
        whole,
        private,
        boundary,
        ..
    } = pipeline(&[router, pool], &[keys.regular(true)], alice, scripted);

    let alice_authorized = vec![(alice, true), (alice, true)];
    assert_eq!(
        authorized(&whole)
            .into_iter()
            .filter(|(actor, _)| *actor == alice)
            .collect::<Vec<_>>(),
        alice_authorized
    );
    assert_eq!(authorized(&private), alice_authorized);
    assert!(boundary.iter().all(|step| match step {
        PrivateToPublic(delivery) | PublicToPrivate(delivery) => {
            delivery.grants == BTreeSet::from([blinded(alice)])
        }
        EndPrivateSubtree | EndPublicSubtree => true,
    }));
}

// A vault returns its sender's grant by `from` alone; a private vault runs the same code as a
// public one, seeing the grant under the address the sender calls from.
#[test]
fn a_private_and_a_public_receiver_see_a_senders_grant_under_its_address() {
    let (alice_keys, vault_keys) = (Keys::new(1), Keys::new(2));
    let alice = holder(&alice_keys);
    let public_vault = actor(3, 9);
    for vault in [holder(&vault_keys), public_vault] {
        let mut script = Script::default()
            .presenting([SenderPresentation::Blinded(OPENING)])
            .on(
                alice,
                sending_when(None, vec![send_to(vault).with_grants([alice])]),
            )
            .on(vault, |input| {
                let from = input.from.expect("the vault is called");
                echo(
                    input,
                    Response::keep_state().send(send_to(from).with_grants([from])),
                )
            });

        whole(
            public_context(vec![public_vault]),
            &[alice_keys.regular(true), vault_keys.regular(false)],
            root(alice),
            &mut script,
        )
        .unwrap();

        let received = &script.log[1];
        assert_eq!(received.from, Some(blinded(alice)), "vault {vault:?}");
        assert_eq!(
            received.grants,
            BTreeSet::from([blinded(alice)]),
            "vault {vault:?}"
        );
        assert_eq!(
            authorized(&script),
            vec![(alice, true), (vault, false), (alice, true)],
            "vault {vault:?}"
        );
    }
}

// An actor calls another actor of its own account with its grant; the callee sees the grant under
// `from`, on a private account as on a public one.
#[test]
fn a_call_within_an_account_shows_the_callee_the_callers_grant_under_from() {
    let keys = Keys::new(1);
    let private = (holder(&keys), Actor::new(keys.regular_id(), id(7)));
    let public = (actor(5, 8), actor(5, 7));
    for (caller, callee) in [private, public] {
        let mut script = Script::default()
            .presenting([SenderPresentation::Blinded(OPENING)])
            .on(
                caller,
                sending_when(None, vec![send_to(callee).with_grants([caller])]),
            )
            .on(callee, sending(Vec::new()));

        whole(
            PublicExecutionContext::new(
                vec![(public.0, Authority::Signer), (public.1, Authority::None)],
                [public.0.account_id],
            ),
            &[keys.regular(true)],
            root(caller),
            &mut script,
        )
        .unwrap();

        let received = &script.log[1];
        assert_eq!(received.from, Some(caller), "caller {caller:?}");
        assert_eq!(
            received.grants,
            BTreeSet::from([caller]),
            "caller {caller:?}"
        );
    }
}

// Alice's private root also hands the public `router` its grant over bob, which crosses out under
// bob's own presentation rather than alice's address.
#[test]
fn a_grant_over_another_private_account_crosses_out_under_its_own_presentation() {
    let (alice_keys, bob_keys) = (Keys::new(1), Keys::new(2));
    let (alice, bob) = (holder(&alice_keys), holder(&bob_keys));
    let (router, pool) = (actor(3, 9), actor(4, 7));
    let bob_opening = [43; 32];
    let scripted = || {
        Script::default()
            .presenting([
                SenderPresentation::Blinded(OPENING),
                SenderPresentation::Blinded(bob_opening),
            ])
            .on(
                alice,
                sending_when(None, vec![send_to(router).with_grants([alice, bob])]),
            )
            .on(router, forwarding(pool))
            .on(pool, debiting)
            .on(bob, sending(Vec::new()))
    };

    let Pipeline {
        private, boundary, ..
    } = pipeline(
        &[router, pool],
        &[alice_keys.regular(true), bob_keys.regular(true)],
        alice,
        scripted,
    );

    let mut debited = authorized(&private).split_off(1);
    debited.sort();
    let mut expected = vec![(alice, true), (bob, true)];
    expected.sort();
    assert_eq!(debited, expected);
    assert_eq!(
        public_calls(&boundary)[0].grants,
        BTreeSet::from([blinded(alice), alias(bob, bob_opening)])
    );
}

// A private PDA's seed grant crosses out under the address custody calls from; `peer` hands it to
// `relay`, whose debit of custody is authorized.
#[test]
fn a_private_pda_grant_crossing_out_passes_along_public_holders() {
    let (keys, pda_keys) = (Keys::new(1), Keys::new(2));
    let owner = holder(&keys);
    let seed = PdaSeed::new([5; 32]);
    let custody = Actor::new(pda_keys.pda_id(owner.program_account_id, seed), id(8));
    let (peer, relay) = (actor(3, 9), actor(4, 7));
    let scripted = || {
        Script::default()
            .presenting([
                SenderPresentation::Canonical,
                SenderPresentation::Blinded(OPENING),
            ])
            .on(owner, sending(vec![seeded_to(custody, seed)]))
            .on(
                custody,
                sending_when(Some(owner), vec![send_to(peer).with_grants([custody])]),
            )
            .on(peer, forwarding(relay))
            .on(relay, debiting)
    };

    let Pipeline {
        whole,
        private,
        boundary,
        ..
    } = pipeline(
        &[peer, relay],
        &[
            keys.regular(false),
            pda_keys.pda(owner.program_account_id, seed),
        ],
        owner,
        scripted,
    );

    let expected = vec![(owner, false), (custody, true), (custody, true)];
    assert_eq!(
        authorized(&whole)
            .into_iter()
            .filter(|(actor, _)| *actor == owner || *actor == custody)
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(authorized(&private), expected);
    assert!(boundary.iter().all(|step| match step {
        PrivateToPublic(delivery) | PublicToPrivate(delivery) => {
            delivery.grants == BTreeSet::from([blinded(custody)])
        }
        EndPrivateSubtree | EndPublicSubtree => true,
    }));
}

#[test]
fn a_seeded_program_cannot_debit_another_actor_of_the_pda() {
    let pool = actor(1, 9);
    let seed = PdaSeed::new([5; 32]);
    let (scam_token, token) = (id(6), id(7));
    let vault = AccountId::for_public_pda(&pool.program_account_id, &seed);
    let (scam_holding, holding) = (Actor::new(vault, scam_token), Actor::new(vault, token));
    let mut script = Script::default()
        .on(pool, sending(vec![seeded_to(scam_holding, seed)]))
        .on(
            scam_holding,
            sending(vec![send_to(holding).with_grants([holding])]),
        );

    let result = public_transaction(
        public_context(vec![pool, scam_holding, holding]),
        pool,
        &mut script,
    );

    assert!(matches!(
        result,
        Err(ExecutionError::UnheldGrant { actor }) if actor == holding
    ));
}

#[test]
fn a_seeded_program_cannot_debit_another_actor_of_a_private_pda() {
    let (keys, pda_keys) = (Keys::new(1), Keys::new(2));
    let owner = holder(&keys);
    let seed = PdaSeed::new([5; 32]);
    let custody = Actor::new(pda_keys.pda_id(owner.program_account_id, seed), id(8));
    let sibling = Actor::new(custody.account_id, id(7));
    let mut script = Script::default()
        .on(owner, sending(vec![seeded_to(custody, seed)]))
        .on(
            custody,
            sending(vec![send_to(sibling).with_grants([sibling])]),
        );

    let result = private_part(
        PublicExecutionContext::default(),
        &[
            keys.regular(false),
            pda_keys.pda(owner.program_account_id, seed),
        ],
        root(owner),
        Vec::new(),
        &mut script,
    );

    assert!(matches!(
        result,
        Err(ExecutionError::UnheldGrant { actor }) if actor == sibling
    ));
}

#[test]
fn a_program_seeds_each_actor_of_its_pda_it_needs() {
    let pool = actor(1, 9);
    let seed = PdaSeed::new([5; 32]);
    let vault = AccountId::for_public_pda(&pool.program_account_id, &seed);
    let (holding_a, holding_b) = (Actor::new(vault, id(6)), Actor::new(vault, id(7)));
    let mut script = Script::default()
        .on(
            pool,
            sending(vec![seeded_to(holding_a, seed), seeded_to(holding_b, seed)]),
        )
        .on(holding_a, sending(Vec::new()))
        .on(holding_b, sending(Vec::new()));

    public_transaction(
        public_context(vec![pool, holding_a, holding_b]),
        pool,
        &mut script,
    )
    .unwrap();

    assert_eq!(
        authorized(&script),
        vec![(pool, false), (holding_a, true), (holding_b, true)]
    );
}

#[test]
fn a_signer_grant_reaches_its_actor_only_where_attached() {
    let (signer, peer) = (actor(1, 9), actor(2, 9));
    let mut script = Script::default()
        .on(
            signer,
            sending_when(None, vec![send_to(peer).with_grants([signer])]),
        )
        .on(
            peer,
            sending(vec![send_to(signer).with_grants([signer]), send_to(signer)]),
        );

    public_transaction(
        PublicExecutionContext::new(
            vec![(signer, Authority::Signer), (peer, Authority::None)],
            [signer.account_id],
        ),
        signer,
        &mut script,
    )
    .unwrap();

    assert_eq!(
        authorized(&script),
        vec![
            (signer, true),
            (peer, false),
            (signer, true),
            (signer, false)
        ]
    );
}

#[test]
fn a_signature_authorizes_only_the_actors_marked_signer() {
    let (marked, unmarked) = (actor(1, 9), actor(1, 8));
    let mut script = Script::default().on(
        marked,
        sending(vec![send_to(unmarked).with_grants([unmarked])]),
    );

    let result = public_transaction(
        PublicExecutionContext::new(
            vec![(marked, Authority::Signer), (unmarked, Authority::None)],
            [marked.account_id],
        ),
        marked,
        &mut script,
    );

    assert!(matches!(
        result,
        Err(ExecutionError::UnheldGrant { actor }) if actor == unmarked
    ));
    assert_eq!(authorized(&script), vec![(marked, true)]);
}

#[test]
fn a_root_call_to_an_unmarked_actor_of_a_signer_is_not_authorized() {
    let (marked, unmarked) = (actor(1, 9), actor(1, 8));
    let mut script = Script::default().on(unmarked, sending(vec![]));

    public_transaction(
        PublicExecutionContext::new(
            vec![(marked, Authority::Signer), (unmarked, Authority::None)],
            [marked.account_id],
        ),
        unmarked,
        &mut script,
    )
    .unwrap();

    assert_eq!(authorized(&script), vec![(unmarked, false)]);
}

#[test]
fn a_signer_mark_without_a_signature_authorizes_nothing() {
    let marked = actor(1, 9);
    let mut script = Script::default().on(marked, sending(vec![]));

    public_transaction(
        PublicExecutionContext::new(vec![(marked, Authority::Signer)], []),
        marked,
        &mut script,
    )
    .unwrap();

    assert_eq!(authorized(&script), vec![(marked, false)]);
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
        |script: &mut Script| public_transaction(public_context(vec![outer, inner]), outer, script);

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

    let public = public_transaction(public_context(vec![clearing]), clearing, &mut script)
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
    let credit = SyncMessage {
        to: vault,
        message: b"credit".to_vec(),
        pda_seeds: BTreeSet::new(),
        grants: BTreeSet::new(),
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
        public_context(vec![vault]),
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
    let bystander = actor(6, 9);
    let run_private = |predicted_cross_messages: PredictedCrossMessages| {
        let mut script = Script::default().on(holder(&keys), sending(vec![send_to(vault)]));
        private_part(
            public_context(vec![vault, bystander]),
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
    // A prediction between two public actors would replay as a proven call.
    assert!(matches!(
        run_private(vec![vec![delivery(vault, bystander, &[])]]),
        Err(ExecutionError::UndeclaredActor { actor }) if actor == bystander
    ));
}

#[test]
fn a_private_signer_grant_returns_from_a_public_actor_beside_a_seed_grant() {
    let keys = Keys::new(1);
    let owner = holder(&keys);
    let vault = actor(2, 9);
    let seed = PdaSeed::new([5; 32]);
    let custody = Actor::new(keys.pda_id(vault.program_account_id, seed), id(8));
    let mut script = Script::default()
        .on(
            owner,
            sending_when(None, vec![send_to(vault).with_grants([owner])]),
        )
        .on(custody, sending(Vec::new()));
    let predicted = vec![vec![
        Delivery {
            grants: BTreeSet::from([owner]),
            ..delivery(vault, owner, &[])
        },
        Delivery {
            pda_seeds: BTreeSet::from([seed]),
            ..delivery(vault, custody, &[])
        },
    ]];

    let boundary = private_part(
        public_context(vec![vault]),
        &[keys.regular(true), keys.pda(vault.program_account_id, seed)],
        root(owner),
        predicted,
        &mut script,
    )
    .unwrap()
    .boundary;

    assert_eq!(
        authorized(&script),
        vec![(owner, true), (owner, true), (custody, true)]
    );
    assert_eq!(public_calls(&boundary)[0].grants, BTreeSet::from([owner]));
}

#[test]
fn a_public_part_rejects_public_behaviour_that_departs_from_the_boundary() {
    let boundary = nested_pipeline().boundary;
    let run_public = |sends: Vec<SyncMessage>| run_public_nested(boundary.clone(), sends).0;
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
        public_context(vec![ENTRY]),
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
        WholeExecution::new(
            public_context(public_actors),
            root(public_actor),
            Vec::new(),
            None,
            witnesses,
        )
        .err()
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
        public_context(vec![ENTRY, loader]),
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
        public_context(vec![loader]),
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
    predicted_authorizations: BTreeSet<Actor>,
) -> (Result<PublicOutcome, ExecutionError>, Script) {
    let keys = Keys::new(1);
    let relay = holder(&keys);
    let owner = ENTRY;
    let (seed, sibling_seed) = (PdaSeed::new([5; 32]), PdaSeed::new([6; 32]));
    let vault = public_pda(owner.program_account_id, seed);
    let sibling = public_pda(owner.program_account_id, sibling_seed);
    let actors = vec![owner, sibling, vault];

    let mut private_script = Script::default().on(relay, move |input| {
        let reply = send_to(vault).with_grants(input.grants.get(&vault).copied());
        echo(input, Response::keep_state().send(reply))
    });
    let private_outcome = private_part(
        public_context(actors.clone()),
        &[keys.regular(false)],
        root(owner),
        vec![
            vec![Delivery {
                grants: predicted_authorizations,
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
        .on(
            vault,
            sending_when(Some(owner), vec![enter(ENTER).with_grants([vault])]),
        );
    let result = public_part(
        public_context(actors),
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

    let (result, script) = relayed_grant(BTreeSet::from([vault]));

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

    for claimed in [BTreeSet::from([sibling]), BTreeSet::new()] {
        assert!(matches!(
            relayed_grant(claimed).0,
            Err(ExecutionError::CrossMessageMismatch { index: 0 })
        ));
    }
}

#[test]
fn a_private_pda_grant_authorizes_the_return_through_a_public_actor() {
    let (keys, pda_keys) = (Keys::new(1), Keys::new(2));
    let owner = holder(&keys);
    let seed = PdaSeed::new([5; 32]);
    let custody = Actor::new(pda_keys.pda_id(owner.program_account_id, seed), id(8));
    let peer = actor(3, 9);
    let peer_vault = public_pda(peer.program_account_id, seed);
    let mut private_script = Script::default()
        .on(owner, sending(vec![seeded_to(custody, seed)]))
        .on(
            custody,
            sending_when(Some(owner), vec![send_to(peer).with_grants([custody])]),
        );

    let private_outcome = private_part(
        public_context(vec![peer, peer_vault]),
        &[
            keys.regular(false),
            pda_keys.pda(owner.program_account_id, seed),
        ],
        root(owner),
        vec![vec![Delivery {
            grants: BTreeSet::from([custody]),
            ..delivery(peer, custody, &[])
        }]],
        &mut private_script,
    )
    .unwrap();

    assert_eq!(
        authorized(&private_script),
        vec![(owner, false), (custody, true), (custody, true)]
    );
    let boundary = private_outcome.boundary;
    assert_eq!(public_calls(&boundary)[0].grants, BTreeSet::from([custody]));

    let mut public_script = Script::default()
        .on(
            peer,
            sending(vec![
                send_to(custody).with_grants([custody]),
                seeded_to(peer_vault, seed),
            ]),
        )
        .on(peer_vault, sending(Vec::new()));
    assert!(
        public_part(
            public_context(vec![peer, peer_vault]),
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
fn a_private_seed_grant_reaches_only_the_messages_it_is_attached_to() {
    let (keys, pda_keys, relay_keys) = (Keys::new(1), Keys::new(2), Keys::new(3));
    let owner = holder(&keys);
    let seed = PdaSeed::new([5; 32]);
    let custody = Actor::new(pda_keys.pda_id(owner.program_account_id, seed), id(8));
    let relay = holder(&relay_keys);
    let mut visited = false;
    let mut script = Script::default()
        .on(
            owner,
            sending(vec![seeded_to(custody, seed), send_to(custody)]),
        )
        .on(custody, move |input| {
            let sync_messages = if std::mem::replace(&mut visited, true) {
                Vec::new()
            } else {
                vec![send_to(relay).with_grants([custody])]
            };
            echo(
                input,
                Response {
                    sync_messages,
                    ..Response::keep_state()
                },
            )
        })
        .on(
            relay,
            sending(vec![send_to(custody).with_grants([custody])]),
        );

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
                let sync_messages = if std::mem::replace(&mut detoured, true) {
                    Vec::new()
                } else {
                    vec![send_to(relay).with_grants([custody])]
                };
                echo(
                    input,
                    Response {
                        sync_messages,
                        ..Response::keep_state()
                    },
                )
            })
            .on(
                relay,
                sending(vec![send_to(custody).with_grants([custody])]),
            )
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
        ..
    } = pipeline(&[peer, relay], &witnesses, owner, script);
    let private_transitions: Vec<_> = authorized(&whole_script)
        .into_iter()
        .filter(|(actor, _)| *actor == owner || *actor == custody)
        .collect();
    assert_eq!(private_transitions, expected);
    assert_eq!(authorized(&private_script), expected);
}
// The proof may claim any grant on a cross message; settlement refuses one its sender never held.
#[test]
fn settlement_refuses_a_predicted_grant_its_public_sender_never_held() {
    let (keys, pda_keys) = (Keys::new(1), Keys::new(2));
    let owner = holder(&keys);
    let peer = actor(3, 9);
    let seed = PdaSeed::new([5; 32]);
    let custody = Actor::new(pda_keys.pda_id(peer.program_account_id, seed), id(8));
    let scripted = || {
        Script::default()
            .on(owner, sending(vec![send_to(peer)]))
            .on(peer, sending(vec![send_to(custody)]))
            .on(custody, sending(Vec::new()))
    };
    let mut private_script = scripted();

    let boundary = private_part(
        public_context(vec![peer]),
        &[
            keys.regular(false),
            pda_keys.pda(peer.program_account_id, seed),
        ],
        root(owner),
        vec![vec![Delivery {
            grants: BTreeSet::from([custody]),
            ..delivery(peer, custody, &[])
        }]],
        &mut private_script,
    )
    .unwrap()
    .boundary;

    assert_eq!(
        authorized(&private_script),
        vec![(owner, false), (custody, true)]
    );
    assert!(matches!(
        public_part(
            public_context(vec![peer]),
            root_call(owner),
            boundary,
            &mut scripted()
        ),
        Err(ExecutionError::CrossMessageMismatch { index: 1 })
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
        public_context(vec![public_member]),
        root(custody),
        Vec::new(),
        None,
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
        public_context(vec![ENTRY]),
        root_call(ENTRY),
        Boundary::new(),
        &mut public_script,
    )
    .unwrap()
    .events;

    assert_eq!(events, vec![(ENTRY, event)]);
}

// A public root asks a private account's native balance to pay, attaching the payer's declared
// signer grant; only a payer whose witness authorizes it can be declared.
#[test]
fn a_public_root_attaches_a_declared_private_signer_grant_to_a_private_debit() {
    let keys = Keys::new(1);
    let (requester, payee) = (actor(2, 9), Actor::native_balance(id(3)));
    let payer = Actor::native_balance(keys.regular_id());
    let run_private = |credential: bool| {
        let mut script = Script::default().on(payer, |input| {
            native_token::handle_message(input).unwrap_or_else(|error| panic!("{error}"))
        });
        private_part(
            private_signers(vec![requester, payee], [payer]),
            &[keys.regular(credential)],
            root(requester),
            vec![
                vec![Delivery {
                    grants: BTreeSet::from([payer]),
                    ..delivery(
                        requester,
                        payer,
                        &borsh::to_vec(&native_token::Message::Transfer {
                            to: payee.account_id,
                            amount: 0,
                        })
                        .unwrap(),
                    )
                }],
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
    assert!(matches!(
        run_private(false),
        Err(ExecutionError::UnmarkedPrivateSigner { actor }) if actor == payer
    ));
}

// Claims are entries before the root, run by the modes executing private roots; settlement
// replays nothing of them.
#[test]
fn claims_run_before_the_root_and_only_privately() {
    let keys = Keys::new(1);
    let claimant = Actor::native_balance(keys.regular_id());
    let sender = Actor::native_balance(id(5));
    let native = |input: &ReceiveInput| {
        native_token::handle_message(input).unwrap_or_else(|error| panic!("{error}"))
    };
    let scripted = || {
        Script::default()
            .on(ENTRY, |input| echo(input, Response::keep_state()))
            .on(claimant, native)
    };
    let claim = MessageBody {
        from: sender,
        to: claimant,
        message: borsh::to_vec(&native_token::Message::Credit(0)).unwrap(),
    };
    let actors = vec![ENTRY];
    let witnesses = [keys.regular(true)];

    let mut whole_script = scripted();
    let predicted = WholeExecution::new(
        public_context(actors.clone()),
        root(ENTRY),
        vec![claim.clone()],
        None,
        &witnesses,
    )
    .unwrap()
    .execute(&mut whole_script)
    .unwrap()
    .predicted_cross_messages;
    assert_eq!(
        order(&whole_script),
        vec![(claimant, Some(sender)), (ENTRY, None)]
    );

    let mut private_script = scripted();
    let boundary = PrivatePart::new(
        public_context(actors.clone()),
        root(ENTRY),
        vec![claim],
        None,
        &witnesses,
        predicted,
    )
    .unwrap()
    .execute(&mut private_script)
    .unwrap()
    .boundary;
    assert_eq!(order(&private_script), vec![(claimant, Some(sender))]);
    assert!(boundary.is_empty());

    let mut public_script = scripted();
    public_part(
        public_context(actors),
        root_call(ENTRY),
        boundary,
        &mut public_script,
    )
    .unwrap();
    assert_eq!(order(&public_script), vec![(ENTRY, None)]);
}

// The fee transfer is a second entry after the root: the payer's native actor debits the reserve
// and credits the inbox once the public root completes, and settlement replays that credit after
// the root.
#[test]
fn a_fee_transfer_runs_after_the_root_in_every_mode() {
    let keys = Keys::new(1);
    let payer = Actor::native_balance(keys.regular_id());
    let inbox = Actor::native_balance(id(5));
    let fee = FeeTransfer {
        payer: keys.regular_id(),
        recipient: inbox.account_id,
        amount: 0,
        refund_to: None,
        tip: 0,
    };
    let native = |input: &ReceiveInput| {
        native_token::handle_message(input).unwrap_or_else(|error| panic!("{error}"))
    };
    let scripted = || {
        Script::default()
            .on(ENTRY, |input| echo(input, Response::keep_state()))
            .on(payer, native)
            .on(inbox, native)
    };
    let credit = delivery(
        payer,
        inbox,
        &borsh::to_vec(&native_token::Message::Credit(0)).unwrap(),
    );
    let actors = vec![ENTRY, inbox];
    let witnesses = [keys.regular(true)];

    // Whole: the root's public segment, then the fee's empty one.
    let mut whole_script = scripted();
    let predicted = WholeExecution::new(
        public_context(actors.clone()),
        root(ENTRY),
        Vec::new(),
        Some(fee),
        &witnesses,
    )
    .unwrap()
    .execute(&mut whole_script)
    .unwrap()
    .predicted_cross_messages;
    assert_eq!(predicted, vec![Vec::new(), Vec::new()]);
    assert_eq!(
        order(&whole_script),
        vec![(ENTRY, None), (payer, None), (inbox, Some(payer))]
    );

    // Private: the public root is skipped and the fee's credit crosses after its segment.
    let mut private_script = scripted();
    let boundary = PrivatePart::new(
        public_context(actors.clone()),
        root(ENTRY),
        Vec::new(),
        Some(fee),
        &witnesses,
        predicted,
    )
    .unwrap()
    .execute(&mut private_script)
    .unwrap()
    .boundary;
    assert_eq!(boundary, vec![PrivateToPublic(credit), EndPublicSubtree]);

    // Public: the root runs, then the proven credit is replayed.
    let mut public_script = scripted();
    public_part(
        public_context(actors.clone()),
        root_call(ENTRY),
        boundary,
        &mut public_script,
    )
    .unwrap();
    assert_eq!(
        order(&public_script),
        vec![(ENTRY, None), (inbox, Some(payer))]
    );

    // The payer must be a witnessed private account.
    let unwitnessed = FeeTransfer {
        payer: id(6),
        ..fee
    };
    assert!(matches!(
        WholeExecution::new(
            public_context(actors),
            root(ENTRY),
            Vec::new(),
            Some(unwitnessed),
            &witnesses
        ),
        Err(ExecutionError::UnwitnessedFeePayer { account_id }) if account_id == id(6)
    ));
}

#[test]
fn a_fee_only_payer_authorizes_the_fee_entry_alone() {
    let keys = Keys::new(1);
    let payer = Actor::native_balance(keys.regular_id());
    let inbox = Actor::native_balance(id(5));
    let fee = FeeTransfer {
        payer: keys.regular_id(),
        recipient: inbox.account_id,
        amount: 0,
        refund_to: None,
        tip: 0,
    };
    let run = |kind: RegularKey| {
        let mut script = Script::default().on(payer, |input| echo(input, Response::keep_state()));
        WholeExecution::new(
            public_context(vec![inbox]),
            root(payer),
            Vec::new(),
            Some(fee),
            &[PrivateWitness {
                signer_programs: BTreeSet::from([native_token::NATIVE_TOKEN_PROGRAM_ID]),
                ..keys.witness(WitnessKind::Regular(kind))
            }],
        )?
        .execute(&mut script)?;
        Ok::<_, ExecutionError>(authorized(&script))
    };

    // The root reaches the payer unauthorized; only the fee entry is authorized over it.
    assert_eq!(
        run(RegularKey::FeeOnly(keys.ask)).unwrap(),
        vec![(payer, false), (payer, true)]
    );
    assert_eq!(
        run(RegularKey::Authorized(keys.ask)).unwrap(),
        vec![(payer, true), (payer, true)]
    );
    assert!(matches!(
        run(RegularKey::Nullifying(keys.nsk())),
        Err(ExecutionError::FeePayerWithoutAuthorization { account_id })
            if account_id == keys.regular_id()
    ));
}

#[test]
fn an_undeclared_actor_of_a_declared_public_account_is_refused() {
    let keys = Keys::new(1);
    let owner = holder(&keys);
    let stray = Actor::new(ENTRY.account_id, id(7));

    let mut private_script = Script::default().on(owner, sending(vec![send_to(stray)]));
    let private_result = private_part(
        public_context(vec![ENTRY]),
        &[keys.regular(false)],
        root(owner),
        Vec::new(),
        &mut private_script,
    );
    let mut public_script = Script::default().on(ENTRY, sending(vec![send_to(stray)]));
    let public_result = public_part(
        public_context(vec![ENTRY]),
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
        public_context(vec![ENTRY]),
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
        public_context(vec![ENTRY, CALLEE, BYSTANDER]),
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
fn a_parents_async_messages_precede_its_childrens_and_never_run_their_recipients() {
    let (outer_target, inner_target) = (actor(6, 7), actor(7, 7));
    let mut script = Script::default()
        .on(ENTRY, move |input| {
            echo(
                input,
                Response::keep_state()
                    .send(send_to(CALLEE))
                    .send(AsyncMessage {
                        to: outer_target,
                        message: b"x".to_vec(),
                    })
                    .send(send_to(BYSTANDER)),
            )
        })
        .on(CALLEE, move |input| {
            echo(
                input,
                Response::keep_state().send(AsyncMessage {
                    to: inner_target,
                    message: b"y".to_vec(),
                }),
            )
        })
        .on(BYSTANDER, sending(Vec::new()));

    let async_messages = public_transaction(
        public_context(vec![ENTRY, CALLEE, BYSTANDER]),
        ENTRY,
        &mut script,
    )
    .unwrap()
    .async_messages;

    assert_eq!(
        order(&script),
        vec![
            (ENTRY, None),
            (CALLEE, Some(ENTRY)),
            (BYSTANDER, Some(ENTRY)),
        ]
    );
    assert_eq!(
        async_messages,
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
        TransactionEntry::Async(record),
        Vec::new(),
        &mut script,
    )
    .unwrap();

    assert_eq!(order(&script), vec![(holder(&keys), Some(actor(4, 5)))]);
    assert_eq!(outcome.boundary, Boundary::default());
}

#[test]
fn a_private_part_keeps_its_async_messages_out_of_the_boundary_and_a_public_part_returns_only_live_async_messages()
 {
    let keys = Keys::new(1);
    let (private_target, public_target) = (actor(6, 7), actor(7, 7));
    let private_async_message = MessageBody {
        from: holder(&keys),
        to: private_target,
        message: b"x".to_vec(),
    };
    let mut private_script = Script::default().on(holder(&keys), move |input| {
        echo(
            input,
            Response::keep_state()
                .send(send_to(ENTRY))
                .send(AsyncMessage {
                    to: private_target,
                    message: b"x".to_vec(),
                }),
        )
    });
    let PrivatePartOutcome {
        boundary,
        async_messages: proven_async_messages,
        ..
    } = private_part(
        public_context(vec![ENTRY]),
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
    assert_eq!(proven_async_messages, vec![private_async_message]);

    let mut public_script = Script::default().on(ENTRY, move |input| {
        echo(
            input,
            Response::keep_state().send(AsyncMessage {
                to: public_target,
                message: b"y".to_vec(),
            }),
        )
    });
    let async_messages = public_part(
        public_context(vec![ENTRY]),
        root_call(holder(&keys)),
        boundary,
        &mut public_script,
    )
    .unwrap()
    .async_messages;

    assert_eq!(
        async_messages,
        vec![MessageBody {
            from: ENTRY,
            to: public_target,
            message: b"y".to_vec(),
        }]
    );
}

fn sync_message(to: Actor, message: &[u8]) -> SyncMessage {
    SyncMessage {
        to,
        message: message.to_vec(),
        pda_seeds: BTreeSet::new(),
        grants: BTreeSet::new(),
    }
}

// `B(C1)` stages 1 and calls `B(C1a)`, which stages 2; `B(C2)` keeps what it finds.
fn sibling_receiver(receiver: Actor) -> impl FnMut(&ReceiveInput) -> Transition {
    move |input| {
        let response = match input.message.as_slice() {
            b"c1" => Response::set_state(b"1".to_vec()).send(sync_message(receiver, b"c1a")),
            b"c1a" => Response::set_state(b"2".to_vec()),
            _ => Response::keep_state(),
        };
        echo(input, response)
    }
}

fn siblings(receiver: Actor) -> Vec<SyncMessage> {
    vec![sync_message(receiver, b"c1"), sync_message(receiver, b"c2")]
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

    public_transaction(public_context(vec![sender, receiver]), sender, &mut script).unwrap();

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
        public_context(vec![receiver]),
        &[keys.regular(false)],
        root(holder(&keys)),
        vec![Vec::new(), Vec::new()],
        &mut private_script,
    )
    .unwrap()
    .boundary;
    let mut public_script = Script::default().on(receiver, sibling_receiver(receiver));

    public_part(
        public_context(vec![receiver]),
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
        public_context(vec![sender]),
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
        public_context(vec![sender]),
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
                    .send(AsyncMessage {
                        to: stranger,
                        message: b"x".to_vec(),
                    })
                    .send(send_to(stranger))
            } else {
                Response::keep_state()
            };
            echo(input, response)
        });

    let result = public_transaction(public_context(vec![sender, receiver]), sender, &mut script);

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
            .on(replying, sending(vec![sync_message(owner, b"back")]))
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
        address_openings: factors.iter().copied().collect(),
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
        public_context(vec![declared]),
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
                    Response::keep_state().send(sync_message(caller, b"reply")),
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
                        .send(sync_message(aliased, b"query"))
                        .send(sync_message(owner, b"query"))
                } else {
                    Response::keep_state()
                };
                echo(input, response)
            })
            .on(owner, |input| {
                let sender = input.from.expect("a query has a sender");
                echo(
                    input,
                    Response::keep_state().send(sync_message(sender, b"answer")),
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
fn an_async_reply_to_a_private_call_can_blind_its_sender() {
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
                Response::keep_state().send(AsyncMessage {
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
        outcome.async_messages,
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
        public_context(vec![ENTRY]),
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
                    .send(AsyncMessage {
                        to: target,
                        message: Vec::new(),
                    })
                    .send(send_to(BYSTANDER)),
            )
        });

    let outcome = private_part(
        public_context(vec![ENTRY, BYSTANDER]),
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
        outcome.async_messages,
        vec![MessageBody {
            from: alias(owner, [2; 32]),
            to: target,
            message: Vec::new(),
        }]
    );
}

#[test]
fn an_async_message_at_an_opened_alias_is_received_privately_by_the_account() {
    let keys = Keys::new(1);
    let owner = holder(&keys);
    let record = stored(ENTRY, alias(owner, [7; 32]), b"stored");
    let mut script = Script::default().on(owner, sending(Vec::new()));

    let outcome = private_part(
        PublicExecutionContext::default(),
        &[opened(keys.regular(false), &[[7; 32]])],
        TransactionEntry::Async(record),
        Vec::new(),
        &mut script,
    )
    .unwrap();

    assert_eq!(order(&script), vec![(owner, Some(ENTRY))]);
    assert_eq!(outcome.boundary, Boundary::default());
}

fn async_message(to: Actor, message: &[u8]) -> AsyncMessage {
    AsyncMessage {
        to,
        message: message.to_vec(),
    }
}

#[test]
fn async_messages_to_declared_public_actors_run_after_their_emitters_calls_and_publish_nothing() {
    let (parent, first, second) = (actor(1, 9), actor(2, 9), actor(3, 9));
    let (third, fourth, nested) = (actor(4, 9), actor(5, 9), actor(6, 9));
    let mut script = Script::default()
        .on(parent, move |input| {
            echo(
                input,
                Response::keep_state()
                    .send(send_to(first))
                    .send(async_message(third, &[]))
                    .send(send_to(second))
                    .send(async_message(fourth, &[])),
            )
        })
        .on(first, sending(Vec::new()))
        .on(second, sending(Vec::new()))
        .on(third, move |input| {
            echo(
                input,
                Response::keep_state().send(async_message(nested, &[])),
            )
        })
        .on(fourth, sending(Vec::new()))
        .on(nested, sending(Vec::new()));

    let outcome = public_transaction(
        public_context(vec![parent, first, second, third, fourth, nested]),
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
    assert!(outcome.async_messages.is_empty());
}

#[test]
fn an_async_message_to_a_declared_but_unadmitted_account_is_refused() {
    let (parent, target) = (actor(1, 9), actor(2, 9));
    let scripted = || {
        Script::default()
            .on(parent, move |input| {
                echo(
                    input,
                    Response::keep_state().send(async_message(target, &[])),
                )
            })
            .on(target, sending(Vec::new()))
    };

    let mut refused = scripted().refusing(target);
    let result = public_transaction(public_context(vec![parent, target]), parent, &mut refused);
    let mut promoted = scripted();
    public_transaction(public_context(vec![parent, target]), parent, &mut promoted).unwrap();

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

// `owner` seeds `vault`, whose sibling call keeps the grant; vault's promoted async message reaches
// `relay`, whose call back does not, though relay's own seed grants afresh. The signer keeps its
// credential.
#[test]
fn a_promoted_async_message_carries_no_grant_not_even_a_signers() {
    let (owner, sibling, relay, signer) = (actor(1, 9), actor(2, 7), actor(3, 8), actor(4, 7));
    let (seed, relay_seed) = (PdaSeed::new([5; 32]), PdaSeed::new([6; 32]));
    let vault = public_pda(owner.program_account_id, seed);
    let relay_vault = public_pda(relay.program_account_id, relay_seed);
    let mut script = Script::default()
        .on(owner, move |input| {
            echo(
                input,
                Response::keep_state()
                    .send(SyncMessage {
                        message: b"seeded".to_vec(),
                        ..seeded_to(vault, seed)
                    })
                    .send(async_message(vault, &[]))
                    .send(async_message(signer, &[])),
            )
        })
        .on(vault, move |input| {
            let response = if input.message == b"seeded" {
                Response::keep_state()
                    .send(send_to(sibling).with_grants([vault]))
                    .send(async_message(relay, &[]))
            } else {
                Response::keep_state()
            };
            echo(input, response)
        })
        .on(sibling, sending(vec![send_to(vault).with_grants([vault])]))
        .on(
            relay,
            sending(vec![send_to(vault), seeded_to(relay_vault, relay_seed)]),
        )
        .on(relay_vault, sending(Vec::new()))
        .on(signer, sending(Vec::new()));

    public_transaction(
        PublicExecutionContext::new(
            [owner, vault, sibling, relay, relay_vault]
                .into_iter()
                .map(|actor| (actor, Authority::None))
                .chain([(signer, Authority::Signer)]),
            [signer.account_id],
        ),
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
            (signer, false),
        ]
    );
}

// The private `owner` seeds its PDA `custody`, which calls public `peer` with its grant; peer
// calls custody back with it and reaches public `relay`, asynchronously when `asynchronous` and
// otherwise by a call, whose call back reseeds custody when `regrant` and otherwise carries no
// grant, as relay never held custody's. `forge` flips whether the proof claims custody's grant for
// that callback.
fn custody_callbacks(
    asynchronous: bool,
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
            .on(
                custody,
                sending_when(Some(owner), vec![send_to(peer).with_grants([custody])]),
            )
            .on(peer, move |input| {
                let response = Response::keep_state().send(send_to(custody).with_grants([custody]));
                echo(
                    input,
                    if asynchronous {
                        response.send_async(relay, &())
                    } else {
                        response.send_sync(relay, &())
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
        public_context(vec![peer, relay]),
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
        if !forged.grants.remove(&custody) {
            forged.grants.insert(custody);
        }
    }
    let mut private_script = script();
    let boundary = private_part(
        public_context(vec![peer, relay]),
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
            PublicToPrivate(delivery) => Some(delivery.grants.contains(&custody)),
            PrivateToPublic(_) | EndPrivateSubtree | EndPublicSubtree => None,
        })
        .collect();
    let settled = public_part(
        public_context(vec![peer, relay]),
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
fn a_private_grant_returns_only_from_a_public_actor_that_holds_it() {
    for (asynchronous, regrant, expected) in [
        (false, false, [true, true, false]),
        (true, false, [true, true, false]),
        (false, true, [true, true, true]),
        (true, true, [true, true, true]),
    ] {
        let (in_whole, in_private, inheritance, settled) =
            custody_callbacks(asynchronous, regrant, false);

        assert_eq!(
            in_whole, expected,
            "asynchronous {asynchronous}, regrant {regrant}"
        );
        assert_eq!(
            in_private, expected,
            "asynchronous {asynchronous}, regrant {regrant}"
        );
        assert_eq!(inheritance, [true, false], "asynchronous {asynchronous}");
        settled.unwrap_or_else(|error| {
            panic!("asynchronous {asynchronous}, regrant {regrant}: {error:?}")
        });
    }
}

#[test]
fn settlement_refuses_a_forged_private_grant() {
    for asynchronous in [false, true] {
        let (_, in_private, inheritance, settled) = custody_callbacks(asynchronous, false, true);

        assert!(in_private[2], "asynchronous {asynchronous}");
        assert_eq!(inheritance, [true, true], "asynchronous {asynchronous}");
        assert!(
            matches!(
                settled,
                Err(ExecutionError::CrossMessageMismatch { index: 3 })
            ),
            "asynchronous {asynchronous}"
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

// Custody's first call from `peer` detours through public `relay`, whose promoted async message
// reaches `back`, which calls custody without the grant; peer's later call still carries it.
#[test]
fn a_promoted_async_message_inside_a_detour_carries_no_grant() {
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
                let sync_messages = if input.from == Some(owner) {
                    vec![send_to(peer).with_grants([custody])]
                } else if input.message == ENTER {
                    vec![send_to(relay).with_grants([custody])]
                } else {
                    Vec::new()
                };
                echo(
                    input,
                    Response {
                        sync_messages,
                        ..Response::keep_state()
                    },
                )
            })
            .on(
                peer,
                sending(vec![
                    SyncMessage {
                        message: ENTER.to_vec(),
                        ..send_to(custody).with_grants([custody])
                    },
                    send_to(custody).with_grants([custody]),
                ]),
            )
            .on(relay, move |input| {
                echo(input, Response::keep_state().send(async_message(back, &[])))
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

// `owner` sends an async message to itself, then seeds `custody`, whose detour through public
// `peer` starts a new entry: peer's call back restores custody's grant although the path began with
// a promoted async message.
#[test]
fn a_public_detour_after_a_promoted_async_message_returns_an_attached_grant() {
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
                    Response::keep_state().send(async_message(owner, ENTER))
                } else {
                    Response::keep_state().send(seeded_to(custody, seed))
                };
                echo(input, response)
            })
            .on(
                custody,
                sending_when(Some(owner), vec![send_to(peer).with_grants([custody])]),
            )
            .on(peer, sending(vec![send_to(custody).with_grants([custody])]))
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
fn a_promoted_private_async_message_keeps_its_own_presentation_and_crosses_after_the_calls() {
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
                    .send(async_message(ENTRY, &[]))
                    .send(send_to(BYSTANDER)),
            )
        });

    let outcome = private_part(
        public_context(vec![ENTRY, BYSTANDER]),
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
    assert!(outcome.async_messages.is_empty());
}

#[test]
fn a_selected_async_message_between_witnessed_private_accounts_runs_inside_the_private_part() {
    let (keys, other) = (Keys::new(1), Keys::new(2));
    let (owner, recipient) = (holder(&keys), holder(&other));
    let mut script = Script::default()
        .promoting(Placement::Private, 0)
        .on(owner, move |input| {
            echo(
                input,
                Response::keep_state().send(async_message(recipient, b"x")),
            )
        })
        .on(recipient, sending(Vec::new()));

    let outcome = private_part(
        public_context(Vec::new()),
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
    assert!(outcome.async_messages.is_empty());
}

#[test]
fn a_selected_public_async_message_into_a_private_account_is_a_predicted_cross_message() {
    let keys = Keys::new(1);
    let owner = holder(&keys);
    let scripted = |message: &'static [u8]| {
        Script::default()
            .promoting(Placement::Public, 0)
            .on(ENTRY, move |input| {
                echo(
                    input,
                    Response::keep_state().send(async_message(owner, message)),
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
        vec![vec![delivery(ENTRY, owner, b"m")]]
    );
    assert!(matches!(
        public_part(
            public_context(vec![ENTRY]),
            root_call(ENTRY),
            boundary,
            &mut scripted(b"n")
        ),
        Err(ExecutionError::CrossMessageMismatch { .. })
    ));
}

// The private root sends `p` asynchronously to `other` and calls ENTRY, which sends `x`
// asynchronously back to the root and calls CALLEE, which sends `y` asynchronously to `other`:
// ENTRY's async message is numbered before CALLEE's and runs after it.
#[test]
fn every_part_numbers_the_same_candidates_and_a_parents_async_message_runs_after_its_childs() {
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
                        .send(async_message(other, b"p"))
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
                        .send(async_message(owner, b"x"))
                        .send(send_to(CALLEE)),
                )
            })
            .on(CALLEE, move |input| {
                echo(
                    input,
                    Response::keep_state().send(async_message(other, b"y")),
                )
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

// ENTRY sends `m` asynchronously to the private root's account, then CALLEE has it send `m`
// asynchronously again before setting BYSTANDER, whose state the root's callback, when there is
// one, reads back.
fn identical_async_messages(callback: bool, selected: u64) -> Script {
    let owner = holder(&Keys::new(1));
    Script::default()
        .promoting(Placement::Public, selected)
        .on(ENTRY, move |input| {
            let response = Response::keep_state().send(async_message(owner, b"m"));
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
                SyncMessage {
                    message: b"set".to_vec(),
                    ..send_to(BYSTANDER)
                },
            ]),
        )
        .on(BYSTANDER, move |input| {
            let response = if input.message == b"set" {
                Response::set_state(data(b"set"))
            } else {
                Response::keep_state().send(SyncMessage {
                    message: input.pre_state.to_vec(),
                    ..send_to(owner)
                })
            };
            echo(input, response)
        })
        .on(owner, move |input| {
            let response = if callback && input.message == b"m" {
                Response::keep_state().send(SyncMessage {
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
fn identical_async_messages_on_either_side_of_public_work_are_selected_by_index() {
    let witnesses = [Keys::new(1).regular(false)];
    for callback in [false, true] {
        for proven in [0, 1] {
            let Pipeline {
                predicted_cross_messages,
                boundary,
                ..
            } = pipeline(&[ENTRY, CALLEE, BYSTANDER], &witnesses, ENTRY, || {
                identical_async_messages(callback, proven)
            });
            if callback {
                let read: &[u8] = if proven == 0 { b"set" } else { b"" };
                assert_eq!(predicted_cross_messages[1][0].envelope.message, read);
            }
            let settled = 1 - proven;
            let result = public_part(
                public_context(vec![ENTRY, CALLEE, BYSTANDER]),
                root_call(ENTRY),
                boundary,
                &mut identical_async_messages(callback, settled),
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
fn a_selected_async_message_to_an_undeclared_actor_of_a_declared_account_is_refused_like_a_call() {
    let undeclared = Actor::new(CALLEE.account_id, id(7));
    let scripted = |selected: bool| {
        let script = Script::default().on(ENTRY, move |input| {
            echo(
                input,
                Response::keep_state().send(async_message(undeclared, b"m")),
            )
        });
        if selected {
            script.promoting(Placement::Public, 0)
        } else {
            script
        }
    };

    let published = public_transaction(
        public_context(vec![ENTRY, CALLEE]),
        ENTRY,
        &mut scripted(false),
    )
    .unwrap()
    .async_messages;
    let in_whole = public_transaction(
        public_context(vec![ENTRY, CALLEE]),
        ENTRY,
        &mut scripted(true),
    );
    let in_public_part = public_part(
        public_context(vec![ENTRY, CALLEE]),
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
fn a_root_a_call_and_a_promoted_async_message_reaching_a_refused_account_are_unadmitted() {
    let scripted = |refused: Actor| {
        Script::default()
            .refusing(refused)
            .on(ENTRY, move |input| {
                echo(
                    input,
                    Response::keep_state()
                        .send(send_to(CALLEE))
                        .send(async_message(BYSTANDER, &[])),
                )
            })
            .on(CALLEE, sending(Vec::new()))
            .on(BYSTANDER, sending(Vec::new()))
    };
    let actors = || public_context(vec![ENTRY, CALLEE, BYSTANDER]);

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
    let scripted = |entry_sends: Vec<SyncMessage>| {
        Script::default()
            .refusing(vault)
            .on(ENTRY, sending(entry_sends))
            .on(CALLEE, sending(vec![send_to(vault)]))
            .on(vault, sending(Vec::new()))
    };
    let actors = || public_context(vec![ENTRY, CALLEE, vault]);

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
        public_context(vec![ENTRY]),
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
        TransactionEntry::Async(stored(actor(4, 5), custody, b"stored")),
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
            grants: BTreeSet::new(),
            pre_state: ActorState::empty(),
            message: b"stored".to_vec(),
        }]
    );
}

// An async message carries no grant, so a private PDA's program acts on its own PDA in the
// claiming turn by seeding again.
#[test]
fn a_private_pda_acts_on_an_async_message_by_reseeding_in_the_claiming_turn() {
    let (keys, seed) = (Keys::new(1), PdaSeed::new([5; 32]));
    let custody = Actor::new(keys.pda_id(id(5), seed), id(5));
    let sender = actor(4, 5);
    let mut script = Script::default().on(
        custody,
        sending_when(Some(sender), vec![seeded_to(custody, seed)]),
    );

    private_part(
        PublicExecutionContext::default(),
        &[keys.pda(id(5), seed)],
        TransactionEntry::Async(stored(sender, custody, b"stored")),
        Vec::new(),
        &mut script,
    )
    .unwrap();

    assert_eq!(authorized(&script), vec![(custody, false), (custody, true)]);
}

// The root hands the signer's grant to a counterparty for a round trip: it comes back on the
// callback only if the counterparty attaches it, and the counterparty could have used it meanwhile.
#[test]
fn a_grant_handed_to_a_counterparty_returns_only_if_the_counterparty_attaches_it() {
    let (signer, amm, lender) = (actor(1, 9), actor(2, 7), actor(3, 8));
    for (returns, expected) in [(true, true), (false, false)] {
        let mut script = Script::default()
            .on(amm, move |input| {
                let response = if input.from.is_none() {
                    Response::keep_state().send(send_to(lender).with_grants([signer]))
                } else {
                    Response::keep_state()
                        .send(send_to(signer).with_grants(input.grants.get(&signer).copied()))
                };
                echo(input, response)
            })
            .on(lender, move |input| {
                let callback = send_to(amm);
                let callback = if returns {
                    callback.with_grants([signer])
                } else {
                    callback
                };
                echo(input, Response::keep_state().send(callback))
            })
            .on(signer, sending(Vec::new()));

        public_transaction(signed_amm_call(signer, amm, lender), amm, &mut script).unwrap();

        assert_eq!(
            authorized(&script).last(),
            Some(&(signer, expected)),
            "returns {returns}"
        );
    }
}

#[test]
fn a_selected_async_message_whose_boundary_step_misstates_its_sender_destination_or_grants_is_refused()
 {
    let keys = Keys::new(1);
    let owner = holder(&keys);
    let scripted = || {
        Script::default()
            .promoting(Placement::Public, 0)
            .on(ENTRY, move |input| {
                echo(
                    input,
                    Response::keep_state().send(async_message(owner, b"m")),
                )
            })
            .on(owner, sending(Vec::new()))
    };
    let boundary = pipeline(&[ENTRY], &[keys.regular(false)], ENTRY, scripted).boundary;
    let Some(PublicToPrivate(selected)) = boundary.first() else {
        panic!("the selected async message is the first crossing");
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
            grants: BTreeSet::from([ENTRY]),
            ..selected.clone()
        },
    ] {
        let mut forged_boundary = boundary.clone();
        forged_boundary[0] = PublicToPrivate(forged);

        assert!(matches!(
            public_part(
                public_context(vec![ENTRY]),
                root_call(ENTRY),
                forged_boundary,
                &mut scripted()
            ),
            Err(ExecutionError::CrossMessageMismatch { .. })
        ));
    }
}

// The private root calls ENTRY, which sends `e` asynchronously to `other` and calls the root back;
// the callback sends `q` asynchronously to `other` and calls CALLEE, which sends `z` asynchronously
// to `other`: a private emission after re-entry, and a public one in the subtree a private callback
// entered, numbered after ENTRY's.
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
                        .send(async_message(other, b"q"))
                        .send(send_to(CALLEE))
                };
                echo(input, response)
            })
            .on(ENTRY, move |input| {
                echo(
                    input,
                    Response::keep_state()
                        .send(async_message(other, b"e"))
                        .send(send_to(owner)),
                )
            })
            .on(CALLEE, move |input| {
                echo(
                    input,
                    Response::keep_state().send(async_message(other, b"z")),
                )
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
            public_context(graph.public.clone()),
            &witnesses,
            TransactionEntry::Sync(entry.clone()),
            &mut whole_script,
        )
        .unwrap_or_else(|error| panic!("seed {seed}: the whole run failed: {error:?}"));
        let mut private_script = graph.script();
        let private_outcome = private_part(
            public_context(graph.public.clone()),
            &witnesses,
            TransactionEntry::Sync(entry.clone()),
            whole_outcome.predicted_cross_messages,
            &mut private_script,
        )
        .unwrap_or_else(|error| panic!("seed {seed}: the private part failed: {error:?}"));
        let mut public_script = graph.script();
        let public_outcome = public_part(
            public_context(graph.public.clone()),
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
