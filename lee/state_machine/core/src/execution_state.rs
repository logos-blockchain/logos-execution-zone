use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, hash_map::Entry};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::{
    NullifierPublicKey, NullifierSecretKey, NullifierWitness, PrivateWitness, WitnessKind,
    account::{AccountData, AccountId, Actor, ActorState},
    program::{
        BlockValidityWindow, Call, Cast, InvalidWindow, MessageBody, MessageData, MessageEnvelope,
        PROGRAM_LOADER_ACCOUNT_ID, PdaSeed, ProgramEvent, ReceiveInput, StoredMessage,
        TimestampValidityWindow, Transition,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum TransactionEntry<R> {
    Call { to: Actor, message: MessageData },
    Cast(R),
}

impl<R> TransactionEntry<R> {
    #[must_use]
    pub const fn call(&self) -> Option<(Actor, &[u8])> {
        match self {
            Self::Call { to, message } => Some((*to, message.as_slice())),
            Self::Cast(_) => None,
        }
    }
}

impl TransactionEntry<StoredMessage> {
    #[must_use]
    pub const fn destination(&self) -> Actor {
        match self {
            Self::Call { to, .. } => *to,
            Self::Cast(record) => record.body.to,
        }
    }

    #[must_use]
    pub const fn cast(&self) -> Option<&StoredMessage> {
        match self {
            Self::Call { .. } => None,
            Self::Cast(record) => Some(record),
        }
    }
}

#[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
pub struct PublicExecutionContext {
    pub actors: Vec<Actor>,
    pub authorized_accounts: BTreeSet<AccountId>,
}

impl PublicExecutionContext {
    pub fn new(
        actors: Vec<Actor>,
        authorized_accounts: impl IntoIterator<Item = AccountId>,
    ) -> Self {
        Self {
            actors,
            authorized_accounts: authorized_accounts.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn runs_publicly(&self, actor: Actor) -> bool {
        self.actors.contains(&actor)
    }
}

pub struct WholeTransaction<'witnesses> {
    execution: Execution<'witnesses, WholeScope>,
    scope: WholeScope,
}

pub struct PrivatePart<'witnesses> {
    execution: Execution<'witnesses, PrivateScope>,
    scope: PrivateScope,
}

pub struct PublicPart {
    execution: Execution<'static, PublicScope>,
    scope: PublicScope,
}

pub struct PublicOutcome {
    pub block_validity_window: BlockValidityWindow,
    pub timestamp_validity_window: TimestampValidityWindow,
    pub accounts: Vec<(AccountId, AccountData)>,
    pub events: Vec<(Actor, ProgramEvent)>,
    pub casts: Vec<MessageBody>,
}

pub struct WholeTransactionOutcome {
    pub public: PublicOutcome,
    pub predicted_cross_messages: PredictedCrossMessages,
}

pub struct PrivatePartOutcome {
    pub block_validity_window: BlockValidityWindow,
    pub timestamp_validity_window: TimestampValidityWindow,
    pub private_accounts: HashMap<AccountId, AccountData>,
    pub boundary: Boundary,
    pub casts: Vec<MessageBody>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Delivery<S> {
    pub envelope: MessageEnvelope<S>,
    pub grants: BTreeSet<AccountId>,
    pub pda_seeds: Vec<PdaSeed>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum BoundaryStep {
    EnterPublic(Delivery<AccountId>),
    EnterPrivate(Delivery<Actor>),
    ExitPrivate,
    ExitPublic,
}

pub type Boundary = Vec<BoundaryStep>;

pub type PredictedCrossMessages = Vec<Vec<Delivery<Actor>>>;

pub trait ExecutionEnvironment {
    type Error: From<ExecutionError>;

    fn receive(
        &mut self,
        input: &ReceiveInput,
        view: &TransitionView<'_>,
    ) -> Result<Transition, Self::Error>;

    /// Returns [`ExecutionError::PublicActorStateUnavailable`] by default.
    fn public_actor_state(&mut self, actor: Actor) -> Result<ActorState, Self::Error> {
        Err(ExecutionError::PublicActorStateUnavailable { actor }.into())
    }
}

pub struct TransitionView<'execution> {
    accounts: &'execution HashMap<AccountId, AccountEntry>,
    at_root: bool,
}

impl TransitionView<'_> {
    #[must_use]
    pub const fn at_root(&self) -> bool {
        self.at_root
    }

    #[must_use]
    pub fn runs_privately(&self, account_id: AccountId) -> bool {
        self.accounts
            .get(&account_id)
            .is_some_and(AccountEntry::is_private)
    }

    #[must_use]
    pub fn staged_state(&self, actor: Actor) -> Option<&ActorState> {
        self.accounts
            .get(&actor.account_id)?
            .staged(actor.program_account_id)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    #[error("No public actor state was supplied for {actor:?}")]
    PublicActorStateUnavailable { actor: Actor },

    #[error("Two witnesses derive the same private account {account_id}")]
    DuplicateWitness { account_id: AccountId },

    #[error("Authorization secret key does not derive the nullifier key of {account_id}")]
    InvalidAuthorizationKey { account_id: AccountId },

    #[error(
        "Two different accounts resolved under the same (program, seed) in one transaction: existing {existing}, new {account_id}"
    )]
    FamilyBindingConflict {
        existing: AccountId,
        account_id: AccountId,
    },

    #[error("The public member {account_id} of a private PDA family is declared")]
    PublicFamilyMemberDeclared { account_id: AccountId },

    #[error(
        "The program loader runs only in a wholly public execution, but {actor:?} was reached in a private or mixed one"
    )]
    LoaderOutsidePublicExecution { actor: Actor },

    #[error("A delivery named {actor:?}, which is neither a declared public actor nor private")]
    UndeclaredActor { actor: Actor },

    #[error(
        "Program {program_account_id} echoed an input it was not given: expected {expected:?}, actual {actual:?}"
    )]
    TransitionInputMismatch {
        program_account_id: AccountId,
        expected: Box<ReceiveInput>,
        actual: Box<ReceiveInput>,
    },

    #[error("There should be non empty intersection in the program output block validity windows")]
    EmptyBlockWindowIntersection,

    #[error(
        "There should be non empty intersection in the program output timestamp validity windows"
    )]
    EmptyTimestampWindowIntersection,

    #[error("Account {account_id} is declared public but has a private witness")]
    PublicAndPrivate { account_id: AccountId },

    #[error("Public actor {actor:?} is declared twice")]
    DuplicatePublicActor { actor: Actor },

    #[error("No predicted cross messages were supplied for public delivery {index}")]
    MissingPredictedCrossMessages { index: usize },

    #[error(
        "Predicted cross messages were supplied for public deliveries the execution never produced"
    )]
    UnusedPredictedCrossMessages,

    #[error("Predicted cross message sender {actor:?} is not a declared public actor")]
    UndeclaredCrossMessageSender { actor: Actor },

    #[error("Boundary step {index} does not match the execution")]
    BoundaryMismatch { index: usize },

    #[error("The cross message at boundary step {index} does not match the executed delivery")]
    CrossMessageMismatch { index: usize },

    #[error("Boundary was not consumed exactly by the execution")]
    IncompleteBoundary,
}

enum AccountEntry {
    Public {
        is_authorized: bool,
        loaded: BTreeMap<AccountId, ActorState>,
    },
    Private {
        witness_index: usize,
        data: AccountData,
    },
}

impl AccountEntry {
    const fn is_private(&self) -> bool {
        matches!(self, Self::Private { .. })
    }

    fn staged(&self, program_account_id: AccountId) -> Option<&ActorState> {
        match self {
            Self::Public { loaded, .. } => loaded.get(&program_account_id),
            Self::Private { data, .. } => Some(data.actor_state(program_account_id)),
        }
    }

    fn stage(&mut self, program_account_id: AccountId, state: ActorState) {
        match self {
            Self::Public { loaded, .. } => {
                loaded.insert(program_account_id, state);
            }
            Self::Private { data, .. } => data.set_actor_state(program_account_id, state),
        }
    }
}

enum Item<C> {
    Deliver(Box<Delivery<Sender>>),
    Resume(C),
}

#[derive(Clone, Copy)]
enum Sender {
    Root { origin: Option<AccountId> },
    Call(Actor),
    ProvenCall(AccountId),
}

impl Sender {
    const fn actor(self) -> Option<Actor> {
        match self {
            Self::Call(actor) => Some(actor),
            Self::Root { .. } | Self::ProvenCall(_) => None,
        }
    }

    const fn origin(self) -> Option<AccountId> {
        match self {
            Self::Root { origin } => origin,
            Self::Call(actor) => Some(actor.program_account_id),
            Self::ProvenCall(program) => Some(program),
        }
    }

    const fn issuer(self) -> Option<AccountId> {
        match self {
            Self::Call(actor) => Some(actor.program_account_id),
            Self::ProvenCall(program) => Some(program),
            Self::Root { .. } => None,
        }
    }
}

impl<S> Delivery<S> {
    fn with_source<T>(&self, source: T) -> Delivery<T> {
        Delivery {
            envelope: MessageEnvelope {
                source,
                to: self.envelope.to,
                message: self.envelope.message.clone(),
            },
            grants: self.grants.clone(),
            pda_seeds: self.pda_seeds.clone(),
        }
    }
}

impl Delivery<Sender> {
    const fn entry(envelope: MessageEnvelope<Sender>) -> Self {
        Self {
            envelope,
            grants: BTreeSet::new(),
            pda_seeds: Vec::new(),
        }
    }

    const fn sent(
        from: Actor,
        to: Actor,
        message: MessageData,
        grants: BTreeSet<AccountId>,
        pda_seeds: Vec<PdaSeed>,
    ) -> Self {
        Self {
            envelope: MessageEnvelope {
                source: Sender::Call(from),
                to,
                message,
            },
            grants,
            pda_seeds,
        }
    }
}

struct Execution<'witnesses, S: Scope> {
    witnesses: &'witnesses [PrivateWitness],
    context: PublicExecutionContext,
    public_actors: HashSet<Actor>,
    accounts: HashMap<AccountId, AccountEntry>,
    pda_family_binding: HashMap<(AccountId, PdaSeed), AccountId>,
    pending: Vec<Item<S::Continuation>>,
    block_validity_window: BlockValidityWindow,
    timestamp_validity_window: TimestampValidityWindow,
    events: Vec<(Actor, ProgramEvent)>,
    casts: Vec<MessageBody>,
}

trait Scope: Sized {
    type Continuation;
    type Outcome;

    const EMITS_EVENTS: bool;

    fn executes_transaction_root(runs_publicly: bool) -> bool;

    fn admits_loader(execution: &Execution<'_, Self>) -> bool;

    fn start_without_transaction_root(
        &mut self,
        execution: &mut Execution<'_, Self>,
    ) -> Result<(), ExecutionError>;

    fn deliver_to_public<E: ExecutionEnvironment>(
        &mut self,
        execution: &mut Execution<'_, Self>,
        delivery: Delivery<Sender>,
        environment: &mut E,
    ) -> Result<(), E::Error>;

    fn deliver_to_private<E: ExecutionEnvironment>(
        &mut self,
        execution: &mut Execution<'_, Self>,
        delivery: Delivery<Sender>,
        environment: &mut E,
    ) -> Result<(), E::Error>;

    fn resume(
        &mut self,
        execution: &mut Execution<'_, Self>,
        continuation: Self::Continuation,
    ) -> Result<(), ExecutionError>;

    fn finish(self, finished: Finished) -> Result<Self::Outcome, ExecutionError>;
}

#[derive(Default)]
struct WholeScope {
    predicted_cross_messages: PredictedCrossMessages,
    open: Vec<usize>,
}

enum WholeContinuation {
    ExitPublic,
}

struct PrivateScope {
    predicted_cross_messages: PredictedCrossMessages,
    next_group: usize,
    boundary: Boundary,
}

enum PrivateContinuation {
    ExitPublic,
    ExitPrivate,
}

struct PublicScope {
    boundary: Boundary,
    cursor: usize,
}

enum PublicContinuation {
    ExitPublic,
    ExitPrivate,
    ReplayProvenCalls { at_root: bool },
}

struct Finished {
    context: PublicExecutionContext,
    accounts: HashMap<AccountId, AccountEntry>,
    events: Vec<(Actor, ProgramEvent)>,
    casts: Vec<MessageBody>,
    block_validity_window: BlockValidityWindow,
    timestamp_validity_window: TimestampValidityWindow,
}

impl<'witnesses> WholeTransaction<'witnesses> {
    pub fn new(
        context: PublicExecutionContext,
        root: TransactionEntry<StoredMessage>,
        witnesses: &'witnesses [PrivateWitness],
    ) -> Result<Self, ExecutionError> {
        let mut scope = WholeScope::default();
        let execution = Execution::start(context, witnesses, Some(root), &mut scope)?;
        Ok(Self { execution, scope })
    }

    pub fn execute<E: ExecutionEnvironment>(
        self,
        environment: &mut E,
    ) -> Result<WholeTransactionOutcome, E::Error> {
        self.execution.run(self.scope, environment)
    }
}

impl<'witnesses> PrivatePart<'witnesses> {
    pub fn new(
        context: PublicExecutionContext,
        root: TransactionEntry<StoredMessage>,
        witnesses: &'witnesses [PrivateWitness],
        predicted_cross_messages: PredictedCrossMessages,
    ) -> Result<Self, ExecutionError> {
        let mut scope = PrivateScope {
            predicted_cross_messages,
            next_group: 0,
            boundary: Boundary::new(),
        };
        let execution = Execution::start(context, witnesses, Some(root), &mut scope)?;
        Ok(Self { execution, scope })
    }

    pub fn execute<E: ExecutionEnvironment>(
        self,
        environment: &mut E,
    ) -> Result<PrivatePartOutcome, E::Error> {
        self.execution.run(self.scope, environment)
    }
}

impl PublicPart {
    pub fn new(
        context: PublicExecutionContext,
        root: Option<TransactionEntry<StoredMessage>>,
        boundary: Boundary,
    ) -> Result<Self, ExecutionError> {
        let mut scope = PublicScope {
            boundary,
            cursor: 0,
        };
        let execution = Execution::start(context, &[], root, &mut scope)?;
        Ok(Self { execution, scope })
    }

    pub fn execute<E: ExecutionEnvironment>(
        self,
        environment: &mut E,
    ) -> Result<PublicOutcome, E::Error> {
        self.execution.run(self.scope, environment)
    }
}

impl Scope for WholeScope {
    type Continuation = WholeContinuation;
    type Outcome = WholeTransactionOutcome;

    const EMITS_EVENTS: bool = true;

    fn executes_transaction_root(_runs_publicly: bool) -> bool {
        true
    }

    fn admits_loader(execution: &Execution<'_, Self>) -> bool {
        execution.witnesses.is_empty()
    }

    fn start_without_transaction_root(
        &mut self,
        _execution: &mut Execution<'_, Self>,
    ) -> Result<(), ExecutionError> {
        Ok(())
    }

    // The root and each Call from a private transition start a public subtree, whose deliveries
    // into private actors form one group of predicted cross messages.
    fn deliver_to_public<E: ExecutionEnvironment>(
        &mut self,
        execution: &mut Execution<'_, Self>,
        delivery: Delivery<Sender>,
        environment: &mut E,
    ) -> Result<(), E::Error> {
        if delivery
            .envelope
            .source
            .actor()
            .is_none_or(|sender| !execution.public_actors.contains(&sender))
        {
            self.open.push(self.predicted_cross_messages.len());
            self.predicted_cross_messages.push(Vec::new());
            execution
                .pending
                .push(Item::Resume(WholeContinuation::ExitPublic));
        }
        execution.process_actor_message(delivery, environment)
    }

    fn deliver_to_private<E: ExecutionEnvironment>(
        &mut self,
        execution: &mut Execution<'_, Self>,
        delivery: Delivery<Sender>,
        environment: &mut E,
    ) -> Result<(), E::Error> {
        execution.require_private(delivery.envelope.to)?;
        if let Some(cross_message) = execution.cross_message(&delivery) {
            let group = *self
                .open
                .last()
                .expect("a public sender runs within an open call");
            self.predicted_cross_messages[group].push(cross_message);
        }
        execution.process_actor_message(delivery, environment)
    }

    fn resume(
        &mut self,
        _execution: &mut Execution<'_, Self>,
        continuation: WholeContinuation,
    ) -> Result<(), ExecutionError> {
        match continuation {
            WholeContinuation::ExitPublic => {
                self.open.pop();
            }
        }
        Ok(())
    }

    fn finish(self, finished: Finished) -> Result<WholeTransactionOutcome, ExecutionError> {
        Ok(WholeTransactionOutcome {
            public: finished.public(),
            predicted_cross_messages: self.predicted_cross_messages,
        })
    }
}

impl PrivateScope {
    // Each cross message re-enters with the private grants withheld from the public call it
    // answers; a predicted grant over a private account is never authority.
    fn deliver_predicted_cross_messages(
        &mut self,
        execution: &mut Execution<'_, Self>,
        withheld: &BTreeSet<AccountId>,
    ) -> Result<(), ExecutionError> {
        let index = self.next_group;
        let cross_messages = self
            .predicted_cross_messages
            .get(index)
            .ok_or(ExecutionError::MissingPredictedCrossMessages { index })?;
        step_past(&mut self.next_group);
        for cross_message in cross_messages.iter().rev() {
            let sender = cross_message.envelope.source;
            if !execution.public_actors.contains(&sender) {
                return Err(ExecutionError::UndeclaredCrossMessageSender { actor: sender });
            }
            let mut delivery = execution.disclose(cross_message, Sender::Call(sender));
            delivery.grants.extend(withheld);
            execution.pending.push(Item::Deliver(Box::new(delivery)));
        }
        Ok(())
    }
}

impl Scope for PrivateScope {
    type Continuation = PrivateContinuation;
    type Outcome = PrivatePartOutcome;

    const EMITS_EVENTS: bool = false;

    fn executes_transaction_root(runs_publicly: bool) -> bool {
        !runs_publicly
    }

    fn admits_loader(_execution: &Execution<'_, Self>) -> bool {
        false
    }

    fn start_without_transaction_root(
        &mut self,
        execution: &mut Execution<'_, Self>,
    ) -> Result<(), ExecutionError> {
        self.deliver_predicted_cross_messages(execution, &BTreeSet::new())
    }

    fn deliver_to_public<E: ExecutionEnvironment>(
        &mut self,
        execution: &mut Execution<'_, Self>,
        delivery: Delivery<Sender>,
        _environment: &mut E,
    ) -> Result<(), E::Error> {
        let program = delivery
            .envelope
            .source
            .issuer()
            .expect("only a Call from a private transition crosses into public execution");
        self.boundary.push(BoundaryStep::EnterPublic(
            execution.disclose(&delivery, program),
        ));
        execution
            .pending
            .push(Item::Resume(PrivateContinuation::ExitPublic));
        let withheld = delivery
            .grants
            .iter()
            .copied()
            .filter(|account_id| execution.is_private(account_id))
            .collect();
        Ok(self.deliver_predicted_cross_messages(execution, &withheld)?)
    }

    fn deliver_to_private<E: ExecutionEnvironment>(
        &mut self,
        execution: &mut Execution<'_, Self>,
        delivery: Delivery<Sender>,
        environment: &mut E,
    ) -> Result<(), E::Error> {
        execution.require_private(delivery.envelope.to)?;
        if let Some(cross_message) = execution.cross_message(&delivery) {
            self.boundary
                .push(BoundaryStep::EnterPrivate(cross_message));
            execution
                .pending
                .push(Item::Resume(PrivateContinuation::ExitPrivate));
        }
        execution.process_actor_message(delivery, environment)
    }

    fn resume(
        &mut self,
        _execution: &mut Execution<'_, Self>,
        continuation: PrivateContinuation,
    ) -> Result<(), ExecutionError> {
        self.boundary.push(match continuation {
            PrivateContinuation::ExitPublic => BoundaryStep::ExitPublic,
            PrivateContinuation::ExitPrivate => BoundaryStep::ExitPrivate,
        });
        Ok(())
    }

    fn finish(self, finished: Finished) -> Result<PrivatePartOutcome, ExecutionError> {
        if self.predicted_cross_messages.len() > self.next_group {
            return Err(ExecutionError::UnusedPredictedCrossMessages);
        }
        Ok(finished.private_part(self.boundary))
    }
}

impl PublicScope {
    fn exit(&mut self, marker: &BoundaryStep) -> Result<(), ExecutionError> {
        if self.boundary.get(self.cursor) != Some(marker) {
            return Err(ExecutionError::BoundaryMismatch { index: self.cursor });
        }
        step_past(&mut self.cursor);
        Ok(())
    }

    fn replay_proven_calls(
        &mut self,
        execution: &mut Execution<'_, Self>,
        at_root: bool,
    ) -> Result<(), ExecutionError> {
        match (self.boundary.get(self.cursor), at_root) {
            (Some(BoundaryStep::EnterPublic(proven)), _) => {
                let delivery = proven.with_source(Sender::ProvenCall(proven.envelope.source));
                step_past(&mut self.cursor);
                execution
                    .pending
                    .push(Item::Resume(PublicContinuation::ReplayProvenCalls {
                        at_root,
                    }));
                execution
                    .pending
                    .push(Item::Resume(PublicContinuation::ExitPublic));
                execution.pending.push(Item::Deliver(Box::new(delivery)));
                Ok(())
            }
            (None, true) | (Some(BoundaryStep::ExitPrivate), false) => Ok(()),
            (
                None
                | Some(
                    BoundaryStep::EnterPrivate(_)
                    | BoundaryStep::ExitPrivate
                    | BoundaryStep::ExitPublic,
                ),
                _,
            ) => Err(ExecutionError::BoundaryMismatch { index: self.cursor }),
        }
    }
}

impl Scope for PublicScope {
    type Continuation = PublicContinuation;
    type Outcome = PublicOutcome;

    const EMITS_EVENTS: bool = true;

    fn executes_transaction_root(runs_publicly: bool) -> bool {
        runs_publicly
    }

    fn admits_loader(_execution: &Execution<'_, Self>) -> bool {
        false
    }

    fn start_without_transaction_root(
        &mut self,
        execution: &mut Execution<'_, Self>,
    ) -> Result<(), ExecutionError> {
        execution
            .pending
            .push(Item::Resume(PublicContinuation::ReplayProvenCalls {
                at_root: true,
            }));
        Ok(())
    }

    fn deliver_to_public<E: ExecutionEnvironment>(
        &mut self,
        execution: &mut Execution<'_, Self>,
        delivery: Delivery<Sender>,
        environment: &mut E,
    ) -> Result<(), E::Error> {
        execution.process_actor_message(delivery, environment)
    }

    fn deliver_to_private<E: ExecutionEnvironment>(
        &mut self,
        execution: &mut Execution<'_, Self>,
        delivery: Delivery<Sender>,
        _environment: &mut E,
    ) -> Result<(), E::Error> {
        let to = delivery.envelope.to;
        if execution.accounts.contains_key(&to.account_id) {
            return Err(ExecutionError::UndeclaredActor { actor: to }.into());
        }
        let index = self.cursor;
        let Some(BoundaryStep::EnterPrivate(predicted)) = self.boundary.get(index) else {
            return Err(ExecutionError::BoundaryMismatch { index }.into());
        };
        // The live grants are the disclosed part of the authority the proven transition ran under.
        let live = delivery
            .envelope
            .source
            .actor()
            .map(|sender| delivery.with_source(sender));
        if live.as_ref() != Some(predicted) {
            return Err(ExecutionError::CrossMessageMismatch { index }.into());
        }
        step_past(&mut self.cursor);
        execution
            .pending
            .push(Item::Resume(PublicContinuation::ExitPrivate));
        execution
            .pending
            .push(Item::Resume(PublicContinuation::ReplayProvenCalls {
                at_root: false,
            }));
        Ok(())
    }

    fn resume(
        &mut self,
        execution: &mut Execution<'_, Self>,
        continuation: PublicContinuation,
    ) -> Result<(), ExecutionError> {
        match continuation {
            PublicContinuation::ExitPublic => self.exit(&BoundaryStep::ExitPublic),
            PublicContinuation::ExitPrivate => self.exit(&BoundaryStep::ExitPrivate),
            PublicContinuation::ReplayProvenCalls { at_root } => {
                self.replay_proven_calls(execution, at_root)
            }
        }
    }

    fn finish(self, finished: Finished) -> Result<PublicOutcome, ExecutionError> {
        if self.cursor != self.boundary.len() {
            return Err(ExecutionError::IncompleteBoundary);
        }
        Ok(finished.public())
    }
}

impl<'witnesses, S: Scope> Execution<'witnesses, S> {
    fn start(
        context: PublicExecutionContext,
        witnesses: &'witnesses [PrivateWitness],
        root: Option<TransactionEntry<StoredMessage>>,
        scope: &mut S,
    ) -> Result<Self, ExecutionError> {
        let mut witness_index = HashMap::with_capacity(witnesses.len());
        let mut pda_family_binding = HashMap::new();
        for (index, witness) in witnesses.iter().enumerate() {
            let account_id = witness.account_id();
            if witness_index.insert(account_id, index).is_some() {
                return Err(ExecutionError::DuplicateWitness { account_id });
            }
            match &witness.kind {
                WitnessKind::Pda {
                    binding: (program, seed),
                } => bind_family(&mut pda_family_binding, *program, *seed, account_id)?,
                WitnessKind::Regular { ask: Some(ask) } => {
                    let derived = NullifierSecretKey::from(ask);
                    let linked = match &witness.nullifier {
                        NullifierWitness::Update { nsk, .. } => derived == *nsk,
                        NullifierWitness::Init { npk, .. } => {
                            NullifierPublicKey::from(&derived) == *npk
                        }
                    };
                    if !linked {
                        return Err(ExecutionError::InvalidAuthorizationKey { account_id });
                    }
                }
                WitnessKind::Regular { ask: None } => {}
            }
        }

        let mut accounts: HashMap<AccountId, AccountEntry> = witness_index
            .iter()
            .map(|(&account_id, &index)| {
                let data = match &witnesses[index].nullifier {
                    NullifierWitness::Init { .. } => AccountData::default(),
                    NullifierWitness::Update { account, .. } => account.data.clone(),
                };
                (
                    account_id,
                    AccountEntry::Private {
                        witness_index: index,
                        data,
                    },
                )
            })
            .collect();
        let mut public_actors = HashSet::with_capacity(context.actors.len());
        for actor in &context.actors {
            let account_id = actor.account_id;
            if witness_index.contains_key(&account_id) {
                return Err(ExecutionError::PublicAndPrivate { account_id });
            }
            if !public_actors.insert(*actor) {
                return Err(ExecutionError::DuplicatePublicActor { actor: *actor });
            }
            accounts
                .entry(account_id)
                .or_insert_with(|| AccountEntry::Public {
                    is_authorized: context.authorized_accounts.contains(&account_id),
                    loaded: BTreeMap::new(),
                });
        }
        // Public seed grants land only at declared, proof-bound addresses, so none can conflict.
        if let Some(account_id) = pda_family_binding
            .keys()
            .map(|(program, seed)| AccountId::for_public_pda(program, seed))
            .find(|account_id| {
                public_actors
                    .iter()
                    .any(|actor| actor.account_id == *account_id)
            })
        {
            return Err(ExecutionError::PublicFamilyMemberDeclared { account_id });
        }

        let root = root
            .filter(|root| S::executes_transaction_root(context.runs_publicly(root.destination())));

        let mut execution = Self {
            witnesses,
            context,
            public_actors,
            accounts,
            pda_family_binding,
            pending: Vec::new(),
            block_validity_window: BlockValidityWindow::new_unbounded(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
            events: Vec::new(),
            casts: Vec::new(),
        };
        match root {
            Some(root) => {
                let (origin, to, message) = match root {
                    TransactionEntry::Call { to, message } => (None, to, message),
                    TransactionEntry::Cast(StoredMessage {
                        body:
                            MessageBody {
                                source,
                                to,
                                message,
                            },
                        ..
                    }) => (Some(source), to, message),
                };
                execution
                    .pending
                    .push(Item::Deliver(Box::new(Delivery::entry(MessageEnvelope {
                        source: Sender::Root { origin },
                        to,
                        message,
                    }))));
            }
            None => scope.start_without_transaction_root(&mut execution)?,
        }
        Ok(execution)
    }

    fn run<E: ExecutionEnvironment>(
        mut self,
        mut scope: S,
        environment: &mut E,
    ) -> Result<S::Outcome, E::Error> {
        while let Some(item) = self.pending.pop() {
            match item {
                Item::Deliver(delivery) => self.deliver(&mut scope, *delivery, environment)?,
                Item::Resume(continuation) => scope.resume(&mut self, continuation)?,
            }
        }
        Ok(scope.finish(self.finish())?)
    }

    // Placement is positive: a declared public actor runs publicly, a private witness's account
    // runs privately, and in a public part any other destination must be the next predicted
    // cross message.
    fn deliver<E: ExecutionEnvironment>(
        &mut self,
        scope: &mut S,
        delivery: Delivery<Sender>,
        environment: &mut E,
    ) -> Result<(), E::Error> {
        let to = delivery.envelope.to;
        // No code upgrade may land between a proof's image claims and the transitions it covers.
        if to.program_account_id == PROGRAM_LOADER_ACCOUNT_ID && !S::admits_loader(self) {
            return Err(ExecutionError::LoaderOutsidePublicExecution { actor: to }.into());
        }
        if self.public_actors.contains(&to) {
            scope.deliver_to_public(self, delivery, environment)
        } else {
            scope.deliver_to_private(self, delivery, environment)
        }
    }

    fn is_private(&self, account_id: &AccountId) -> bool {
        self.accounts
            .get(account_id)
            .is_some_and(AccountEntry::is_private)
    }

    fn require_private(&self, actor: Actor) -> Result<(), ExecutionError> {
        if self.is_private(&actor.account_id) {
            Ok(())
        } else {
            Err(ExecutionError::UndeclaredActor { actor })
        }
    }

    // No public handler can observe a grant over a private account, so a boundary or prediction
    // discloses only the other grants; the private part restores the withheld ones on re-entry.
    fn disclose<F, T>(&self, delivery: &Delivery<F>, source: T) -> Delivery<T> {
        let mut disclosed = delivery.with_source(source);
        disclosed
            .grants
            .retain(|account_id| !self.is_private(account_id));
        disclosed
    }

    // A private delivery from a declared public actor is where the execution crosses into a proven
    // transition: a whole transaction collects it into the innermost open public Call's predicted
    // cross messages, a private part records it.
    fn cross_message(&self, delivery: &Delivery<Sender>) -> Option<Delivery<Actor>> {
        delivery
            .envelope
            .source
            .actor()
            .filter(|sender| self.public_actors.contains(sender))
            .map(|sender| self.disclose(delivery, sender))
    }

    fn process_actor_message<E: ExecutionEnvironment>(
        &mut self,
        delivery: Delivery<Sender>,
        environment: &mut E,
    ) -> Result<(), E::Error> {
        let actor = delivery.envelope.to;
        let (is_authorized, grants) = self.authorize(&delivery)?;
        let entry = self
            .accounts
            .get_mut(&actor.account_id)
            .expect("an authorized actor has an entry");
        if let AccountEntry::Public { loaded, .. } = entry
            && !loaded.contains_key(&actor.program_account_id)
        {
            loaded.insert(
                actor.program_account_id,
                environment.public_actor_state(actor)?,
            );
        }
        let input = ReceiveInput {
            receiver: actor,
            origin: delivery.envelope.source.origin(),
            is_authorized,
            pre_state: entry
                .staged(actor.program_account_id)
                .expect("a delivered actor's state is loaded")
                .clone(),
            message: delivery.envelope.message,
        };

        let view = TransitionView {
            accounts: &self.accounts,
            at_root: matches!(delivery.envelope.source, Sender::Root { .. }),
        };
        let transition = environment.receive(&input, &view)?;
        if transition.input != input {
            return Err(ExecutionError::TransitionInputMismatch {
                program_account_id: actor.program_account_id,
                expected: Box::new(input),
                actual: Box::new(transition.input),
            }
            .into());
        }
        let block = self
            .block_validity_window
            .intersect(transition.response.block_validity_window)
            .map_err(|InvalidWindow| ExecutionError::EmptyBlockWindowIntersection)?;
        let timestamp = self
            .timestamp_validity_window
            .intersect(transition.response.timestamp_validity_window)
            .map_err(|InvalidWindow| ExecutionError::EmptyTimestampWindowIntersection)?;
        self.block_validity_window = block;
        self.timestamp_validity_window = timestamp;

        if let Some(data) = transition.response.post_state {
            self.accounts
                .get_mut(&actor.account_id)
                .expect("an authorized actor has an entry")
                .stage(actor.program_account_id, data);
        }
        if S::EMITS_EVENTS {
            self.events.extend(
                transition
                    .response
                    .events
                    .into_iter()
                    .map(|event| (actor, event)),
            );
        }
        self.casts.extend(
            transition
                .response
                .casts
                .into_iter()
                .map(|Cast { to, message }| MessageBody {
                    source: actor.program_account_id,
                    to,
                    message,
                }),
        );
        for Call {
            to,
            message,
            pda_seeds,
        } in transition.response.calls.into_iter().rev()
        {
            self.pending.push(Item::Deliver(Box::new(Delivery::sent(
                actor,
                to,
                message,
                grants.clone(),
                pda_seeds,
            ))));
        }
        Ok(())
    }

    fn authorize(
        &mut self,
        delivery: &Delivery<Sender>,
    ) -> Result<(bool, BTreeSet<AccountId>), ExecutionError> {
        let actor = delivery.envelope.to;
        let account_id = actor.account_id;
        let issuer = delivery.envelope.source.issuer();
        let entry = self
            .accounts
            .get(&account_id)
            .ok_or(ExecutionError::UndeclaredActor { actor })?;
        let (credential, granted) = match entry {
            AccountEntry::Public { is_authorized, .. } => (
                *is_authorized,
                issuer.and_then(|issuer| {
                    delivery
                        .pda_seeds
                        .iter()
                        .find(|seed| AccountId::for_public_pda(&issuer, seed) == account_id)
                        .map(|seed| (issuer, *seed))
                }),
            ),
            AccountEntry::Private { witness_index, .. } => {
                let witness = &self.witnesses[*witness_index];
                (
                    matches!(witness.kind, WitnessKind::Regular { ask: Some(_) }),
                    private_seed_grant(issuer, &delivery.pda_seeds, witness),
                )
            }
        };
        let mut grants = delivery.grants.clone();
        if let Some((program, seed)) = granted {
            bind_family(&mut self.pda_family_binding, program, seed, account_id)?;
            grants.insert(account_id);
        }
        Ok((credential || grants.contains(&account_id), grants))
    }

    fn finish(self) -> Finished {
        let Self {
            context,
            accounts,
            block_validity_window,
            timestamp_validity_window,
            events,
            casts,
            ..
        } = self;
        Finished {
            context,
            accounts,
            events,
            casts,
            block_validity_window,
            timestamp_validity_window,
        }
    }
}

impl Finished {
    fn public(self) -> PublicOutcome {
        let Self {
            context,
            mut accounts,
            events,
            casts,
            block_validity_window,
            timestamp_validity_window,
        } = self;
        let mut public = Vec::new();
        for actor in context.actors {
            let Some(AccountEntry::Public { loaded, .. }) = accounts.remove(&actor.account_id)
            else {
                continue;
            };
            public.push((
                actor.account_id,
                AccountData {
                    actor_states: loaded,
                },
            ));
        }
        PublicOutcome {
            block_validity_window,
            timestamp_validity_window,
            accounts: public,
            events,
            casts,
        }
    }

    fn private_part(self, boundary: Boundary) -> PrivatePartOutcome {
        PrivatePartOutcome {
            block_validity_window: self.block_validity_window,
            timestamp_validity_window: self.timestamp_validity_window,
            private_accounts: self
                .accounts
                .into_iter()
                .filter_map(|(account_id, entry)| match entry {
                    AccountEntry::Private { data, .. } => Some((account_id, data)),
                    AccountEntry::Public { .. } => None,
                })
                .collect(),
            boundary,
            casts: self.casts,
        }
    }
}

const fn step_past(position: &mut usize) {
    *position = position
        .checked_add(1)
        .expect("bounded by the length of what it indexes");
}

fn private_seed_grant(
    issuer: Option<AccountId>,
    pda_seeds: &[PdaSeed],
    witness: &PrivateWitness,
) -> Option<(AccountId, PdaSeed)> {
    witness
        .pda_binding()
        .filter(|&(program, seed)| Some(program) == issuer && pda_seeds.contains(&seed))
}

fn bind_family(
    bindings: &mut HashMap<(AccountId, PdaSeed), AccountId>,
    program_account_id: AccountId,
    seed: PdaSeed,
    account_id: AccountId,
) -> Result<(), ExecutionError> {
    match bindings.entry((program_account_id, seed)) {
        Entry::Vacant(vacant) => {
            vacant.insert(account_id);
            Ok(())
        }
        Entry::Occupied(occupied) if *occupied.get() == account_id => Ok(()),
        Entry::Occupied(occupied) => Err(ExecutionError::FamilyBindingConflict {
            existing: *occupied.get(),
            account_id,
        }),
    }
}

#[cfg(test)]
mod tests;
