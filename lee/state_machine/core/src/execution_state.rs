use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, hash_map::Entry};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::{
    PrivateWitness, RootCall, SenderPresentation,
    account::{AccountData, AccountId, Actor, ActorState},
    program::{
        Call, Cast, InvalidWindow, MessageBody, MessageData, MessageEnvelope,
        PROGRAM_LOADER_ACCOUNT_ID, PdaSeed, ProgramEvent, ReceiveInput, Transition,
        ValidityWindows,
    },
};

/// The wrapper carrying metadata of the top-level message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum TransactionEntry<R> {
    Call(RootCall),
    Cast(R),
}

impl<R> TransactionEntry<R> {
    #[must_use]
    pub fn map<T>(self, cast: impl FnOnce(R) -> T) -> TransactionEntry<T> {
        match self {
            Self::Call(call) => TransactionEntry::Call(call),
            Self::Cast(record) => TransactionEntry::Cast(cast(record)),
        }
    }
}

impl TransactionEntry<MessageBody> {
    #[must_use]
    pub const fn destination(&self) -> Actor {
        match self {
            Self::Call(call) => call.to,
            Self::Cast(body) => body.to,
        }
    }
}

/// The public context representation of the private transaction part proof.
#[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
pub struct PublicExecutionContext {
    pub actors: BTreeSet<Actor>,
    pub authorized_accounts: BTreeSet<AccountId>,
    pub cast_promotions: BTreeSet<u64>,
}

impl PublicExecutionContext {
    pub fn new(
        actors: impl IntoIterator<Item = Actor>,
        authorized_accounts: impl IntoIterator<Item = AccountId>,
    ) -> Self {
        Self {
            actors: actors.into_iter().collect(),
            authorized_accounts: authorized_accounts.into_iter().collect(),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn runs_publicly(&self, actor: Actor) -> bool {
        self.actors.contains(&actor)
    }
}

/// An execution environment running the entire message passing through
/// public and private actors.
pub struct WholeTransaction<'witnesses> {
    execution: Execution<'witnesses, WholeScope>,
    scope: WholeScope,
}

/// An execution environment running only the private message passings
/// given the assumed public context.
pub struct PrivatePart<'witnesses> {
    execution: Execution<'witnesses, PrivateScope>,
    scope: PrivateScope,
}

/// An execution environment running only the public message passings
/// given the assumed private deliveries.
pub struct PublicPart {
    execution: Execution<'static, PublicScope>,
    scope: PublicScope,
}

/// The outcome of public actor message-passing.
pub struct PublicOutcome {
    pub validity: ValidityWindows,
    /// Resulting public account post-states.
    pub accounts: BTreeMap<AccountId, AccountData>,
    /// Emitted events in the course of execution.
    pub events: Vec<(Actor, ProgramEvent)>,
    /// Emitted casts in the course of execution.
    pub casts: Vec<MessageBody>,
}

/// Outcome for proving a private or hybrid transaction.
pub struct WholeTransactionOutcome {
    pub public: PublicOutcome,
    /// Predicted messages between private and public actors.
    pub predicted_cross_messages: PredictedCrossMessages,
}

/// Outcomes of private message-passing.
pub struct PrivatePartOutcome {
    pub validity: ValidityWindows,
    /// Resulting private account post-states.
    pub private_accounts: HashMap<AccountId, AccountData>,
    /// Recording of passing messages between private and public actors.
    pub boundary: Boundary,
    /// Emitted casts in the course of execution.
    pub casts: Vec<MessageBody>,
}

/// A message envelope with an authorization context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Delivery<S> {
    pub envelope: MessageEnvelope<S>,
    pub inherited_authorizations: BTreeSet<AccountId>,
    pub inherits_entry_authorizations: bool,
    pub pda_seeds: BTreeSet<PdaSeed>,
}

/// A record of message passing context between private and public actors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum BoundaryStep {
    PrivateToPublic(Delivery<Actor>),
    PublicToPrivate(Delivery<Actor>),
    EndPrivateSubtree,
    EndPublicSubtree,
}

pub type Boundary = Vec<BoundaryStep>;

pub type PredictedCrossMessages = Vec<Vec<Delivery<Actor>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    Public,
    Private,
}

pub trait ExecutionEnvironment {
    type Error: From<ExecutionError>;

    fn handle_message(
        &mut self,
        input: &ReceiveInput,
        view: &TransitionView<'_>,
    ) -> Result<Transition, Self::Error>;

    /// Returns [`ExecutionError::PublicActorStateUnavailable`] by default.
    fn public_actor_state(&mut self, actor: Actor) -> Result<ActorState, Self::Error> {
        Err(ExecutionError::PublicActorStateUnavailable { actor }.into())
    }

    /// Returns [`ExecutionError::MissingSenderPresentation`] by default.
    fn present(&mut self, sender: Actor) -> Result<SenderPresentation, Self::Error> {
        Err(ExecutionError::MissingSenderPresentation { sender }.into())
    }

    /// Admits no account by default.
    fn admits(&mut self, _account_id: AccountId) -> Result<bool, Self::Error> {
        Ok(false)
    }

    /// Publishes every candidate Cast by default.
    fn promote(
        &mut self,
        _placement: Placement,
        _index: u64,
        _body: &MessageBody,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }
}

/// A view of accounts at the point of message handling by the execution environment.
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

    #[error(
        "Two different accounts resolved under the same (program, seed) in one transaction: existing {existing}, new {account_id}"
    )]
    FamilyBindingConflict {
        existing: AccountId,
        account_id: AccountId,
    },

    #[error("The public member {account_id} of a private PDA family is declared")]
    PublicFamilyMemberDeclared { account_id: AccountId },

    #[error("Alias {alias} is a declared account or names two different accounts")]
    AliasCollision { alias: AccountId },

    #[error("No presentation was supplied for a message from {sender:?}")]
    MissingSenderPresentation { sender: Actor },

    #[error(
        "The program loader runs only in a wholly public execution, but {actor:?} was reached in a private or mixed one"
    )]
    LoaderOutsidePublicExecution { actor: Actor },

    #[error("A delivery named {actor:?}, which is neither a declared public actor nor private")]
    UndeclaredActor { actor: Actor },

    #[error("A delivery named {actor:?}, whose account is declared public but not admitted")]
    UnadmittedPublicActor { actor: Actor },

    #[error("Cast promotion {index} selects a candidate the execution never emitted")]
    UnreachedCastPromotion { index: u64 },

    #[error(
        "Program {program_account_id} echoed an input it was not given: expected {expected:?}, actual {actual:?}"
    )]
    TransitionInputMismatch {
        program_account_id: AccountId,
        expected: Box<ReceiveInput>,
        actual: Box<ReceiveInput>,
    },

    #[error("There should be non empty intersection in the program output validity windows")]
    EmptyValidityWindowIntersection,

    #[error("Account {account_id} is declared public but has a private witness")]
    PublicAndPrivate { account_id: AccountId },

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

/// Designates the work the executor is tasked with.
enum Item<C> {
    /// Process a delivered message.
    Deliver(Box<Delivery<Sender>>),
    /// Finalize an execution subtree and resume the next branch.
    Resume(C),
}

#[derive(Clone, Copy)]
enum Sender {
    Root { from: Option<Actor> },
    Call(Actor),
}

impl Sender {
    const fn actor(self) -> Option<Actor> {
        match self {
            Self::Call(actor) => Some(actor),
            Self::Root { .. } => None,
        }
    }

    const fn source(self) -> Option<Actor> {
        match self {
            Self::Root { from } => from,
            Self::Call(actor) => Some(actor),
        }
    }

    const fn issuer(self) -> Option<AccountId> {
        match self {
            Self::Call(actor) => Some(actor.program_account_id),
            Self::Root { .. } => None,
        }
    }
}

impl<S> Delivery<S> {
    fn with_from<T>(&self, from: T) -> Delivery<T> {
        Delivery {
            envelope: MessageEnvelope {
                from,
                to: self.envelope.to,
                message: self.envelope.message.clone(),
            },
            inherited_authorizations: self.inherited_authorizations.clone(),
            inherits_entry_authorizations: self.inherits_entry_authorizations,
            pda_seeds: self.pda_seeds.clone(),
        }
    }
}

impl Delivery<Sender> {
    const fn entry(envelope: MessageEnvelope<Sender>) -> Self {
        Self {
            envelope,
            inherited_authorizations: BTreeSet::new(),
            inherits_entry_authorizations: true,
            pda_seeds: BTreeSet::new(),
        }
    }

    const fn sent(
        from: Actor,
        to: Actor,
        message: MessageData,
        inherited_authorizations: BTreeSet<AccountId>,
        inherits_entry_authorizations: bool,
        pda_seeds: BTreeSet<PdaSeed>,
    ) -> Self {
        Self {
            envelope: MessageEnvelope {
                from: Sender::Call(from),
                to,
                message,
            },
            inherited_authorizations,
            inherits_entry_authorizations,
            pda_seeds,
        }
    }
}

/// An engine running scoped execution.
struct Execution<'witnesses, S: Scope> {
    witnesses: &'witnesses [PrivateWitness],
    context: PublicExecutionContext,
    accounts: HashMap<AccountId, AccountEntry>,
    /// The hidden private addresses.
    aliases: HashMap<AccountId, AccountId>,
    pda_family_binding: HashMap<(AccountId, PdaSeed), AccountId>,
    /// Pending items of execution tasks.
    pending: Vec<Item<S::Continuation>>,
    validity: ValidityWindows,
    events: Vec<(Actor, ProgramEvent)>,
    casts: Vec<MessageBody>,
    /// Indices of casts to be executed as calls.
    candidates: Candidates,
    /// Established public accounts.
    admitted: HashSet<AccountId>,
}

/// Positions of casts to be executed in the given transaction.
#[derive(Default)]
struct Candidates {
    public: u64,
    private: u64,
}

impl Candidates {
    const fn next(&mut self, placement: Placement) -> u64 {
        let counter = match placement {
            Placement::Public => &mut self.public,
            Placement::Private => &mut self.private,
        };
        let index = *counter;
        *counter = index
            .checked_add(1)
            .expect("bounded by the Casts one transaction emits");
        index
    }
}

trait Scope: Sized {
    type Continuation;
    type Outcome;

    const EMITS_EVENTS: bool;
    const CHECKS_ADMISSION: bool;

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

    fn finish(self, execution: Execution<'_, Self>) -> Result<Self::Outcome, ExecutionError>;
}

/// The scope for the whole transaction includes predicted messages between private and
/// public actors as well as indexing of message groups processed publicly.
#[derive(Default)]
struct WholeScope {
    /// Messages delivered between public and private actors.
    predicted_cross_messages: PredictedCrossMessages,
    /// Recorded entrances into public message-passing environment.
    open: Vec<usize>,
}

enum WholeContinuation {
    EndPublicSubtree,
}

/// The scope for private executions includes the prediced messages coming into
/// the private environment, alongside the next grouping to be processed and the
/// emitted boundary for the public side to consume.
struct PrivateScope {
    /// Messages coming into the private environment.
    predicted_cross_messages: PredictedCrossMessages,
    /// The index of the execution group to process.
    next_group: usize,
    /// The emitted boundary constructed in the process.
    boundary: Boundary,
}

enum PrivateContinuation {
    EndPublicSubtree,
    EndPrivateSubtree,
}

/// The scope for public execution has the entire boundary between private and public
/// actors and the cursor which boundary step to process.
struct PublicScope {
    /// The public-private boundary communication.
    boundary: Boundary,
    /// Which boundary to process.
    cursor: usize,
}

enum PublicContinuation {
    EndPublicSubtree,
    EndPrivateSubtree,
    ReplayProvenCalls { at_root: bool },
}

impl<'witnesses> WholeTransaction<'witnesses> {
    pub fn new(
        context: PublicExecutionContext,
        root: TransactionEntry<MessageBody>,
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
        root: TransactionEntry<MessageBody>,
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
        root: Option<RootCall>,
        boundary: Boundary,
    ) -> Result<Self, ExecutionError> {
        let mut scope = PublicScope {
            boundary,
            cursor: 0,
        };
        let execution =
            Execution::start(context, &[], root.map(TransactionEntry::Call), &mut scope)?;
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

    const CHECKS_ADMISSION: bool = true;
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
        if execution.opens_public_subtree(&delivery) {
            self.open.push(self.predicted_cross_messages.len());
            self.predicted_cross_messages.push(Vec::new());
            execution
                .pending
                .push(Item::Resume(WholeContinuation::EndPublicSubtree));
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
            WholeContinuation::EndPublicSubtree => {
                self.open.pop();
            }
        }
        Ok(())
    }

    fn finish(
        self,
        execution: Execution<'_, Self>,
    ) -> Result<WholeTransactionOutcome, ExecutionError> {
        Ok(WholeTransactionOutcome {
            public: execution.public(),
            predicted_cross_messages: self.predicted_cross_messages,
        })
    }
}

impl PrivateScope {
    // Each cross message still inheriting its entry's authorizations re-enters with the private
    // grants withheld from the public call it answers; a predicted grant over a private account is
    // never authority.
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
            let sender = cross_message.envelope.from;
            if !execution.context.runs_publicly(sender) {
                return Err(ExecutionError::UndeclaredCrossMessageSender { actor: sender });
            }
            let mut delivery = execution.disclose(cross_message, Sender::Call(sender));
            if delivery.inherits_entry_authorizations {
                delivery.inherited_authorizations.extend(withheld);
            }
            execution.pending.push(Item::Deliver(Box::new(delivery)));
        }
        Ok(())
    }
}

impl Scope for PrivateScope {
    type Continuation = PrivateContinuation;
    type Outcome = PrivatePartOutcome;

    const CHECKS_ADMISSION: bool = false;
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
        let sender = delivery
            .envelope
            .from
            .actor()
            .expect("only a Call from a private transition crosses into public execution");
        self.boundary.push(BoundaryStep::PrivateToPublic(
            execution.disclose(&delivery, sender),
        ));
        execution
            .pending
            .push(Item::Resume(PrivateContinuation::EndPublicSubtree));
        let withheld = delivery
            .inherited_authorizations
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
                .push(BoundaryStep::PublicToPrivate(cross_message));
            execution
                .pending
                .push(Item::Resume(PrivateContinuation::EndPrivateSubtree));
        }
        execution.process_actor_message(delivery, environment)
    }

    fn resume(
        &mut self,
        _execution: &mut Execution<'_, Self>,
        continuation: PrivateContinuation,
    ) -> Result<(), ExecutionError> {
        self.boundary.push(match continuation {
            PrivateContinuation::EndPublicSubtree => BoundaryStep::EndPublicSubtree,
            PrivateContinuation::EndPrivateSubtree => BoundaryStep::EndPrivateSubtree,
        });
        Ok(())
    }

    fn finish(self, execution: Execution<'_, Self>) -> Result<PrivatePartOutcome, ExecutionError> {
        if self.predicted_cross_messages.len() > self.next_group {
            return Err(ExecutionError::UnusedPredictedCrossMessages);
        }
        Ok(execution.private_part(self.boundary))
    }
}

impl PublicScope {
    fn end_subtree(&mut self, marker: &BoundaryStep) -> Result<(), ExecutionError> {
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
            (Some(BoundaryStep::PrivateToPublic(proven)), _) => {
                let delivery = proven.with_from(Sender::Call(proven.envelope.from));
                step_past(&mut self.cursor);
                execution
                    .pending
                    .push(Item::Resume(PublicContinuation::ReplayProvenCalls {
                        at_root,
                    }));
                execution
                    .pending
                    .push(Item::Resume(PublicContinuation::EndPublicSubtree));
                execution.pending.push(Item::Deliver(Box::new(delivery)));
                Ok(())
            }
            (None, true) | (Some(BoundaryStep::EndPrivateSubtree), false) => Ok(()),
            (
                None
                | Some(
                    BoundaryStep::PublicToPrivate(_)
                    | BoundaryStep::EndPrivateSubtree
                    | BoundaryStep::EndPublicSubtree,
                ),
                _,
            ) => Err(ExecutionError::BoundaryMismatch { index: self.cursor }),
        }
    }
}

impl Scope for PublicScope {
    type Continuation = PublicContinuation;
    type Outcome = PublicOutcome;

    const CHECKS_ADMISSION: bool = true;
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
        let Some(BoundaryStep::PublicToPrivate(predicted)) = self.boundary.get(index) else {
            return Err(ExecutionError::BoundaryMismatch { index }.into());
        };
        // The live grants are the disclosed part of the authority the proven transition ran under.
        let live = delivery
            .envelope
            .from
            .actor()
            .map(|sender| delivery.with_from(sender));
        if live.as_ref() != Some(predicted) {
            return Err(ExecutionError::CrossMessageMismatch { index }.into());
        }
        step_past(&mut self.cursor);
        execution
            .pending
            .push(Item::Resume(PublicContinuation::EndPrivateSubtree));
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
            PublicContinuation::EndPublicSubtree => {
                self.end_subtree(&BoundaryStep::EndPublicSubtree)
            }
            PublicContinuation::EndPrivateSubtree => {
                self.end_subtree(&BoundaryStep::EndPrivateSubtree)
            }
            PublicContinuation::ReplayProvenCalls { at_root } => {
                self.replay_proven_calls(execution, at_root)
            }
        }
    }

    fn finish(self, execution: Execution<'_, Self>) -> Result<PublicOutcome, ExecutionError> {
        if self.cursor != self.boundary.len() {
            return Err(ExecutionError::IncompleteBoundary);
        }
        Ok(execution.public())
    }
}

impl<'witnesses, S: Scope> Execution<'witnesses, S> {
    fn start(
        context: PublicExecutionContext,
        witnesses: &'witnesses [PrivateWitness],
        root: Option<TransactionEntry<MessageBody>>,
        scope: &mut S,
    ) -> Result<Self, ExecutionError> {
        let mut witness_index = HashMap::with_capacity(witnesses.len());
        let mut pda_family_binding = HashMap::new();
        let mut openings = Vec::new();
        for (index, witness) in witnesses.iter().enumerate() {
            let account_id = witness.account_id();
            if witness_index.insert(account_id, index).is_some() {
                return Err(ExecutionError::DuplicateWitness { account_id });
            }
            openings.extend(
                witness
                    .openings
                    .iter()
                    .map(|factor| (account_id.blinded(factor), account_id)),
            );
            if let Some((program, seed)) = witness.pda_binding() {
                bind_family(&mut pda_family_binding, program, seed, account_id)?;
            }
        }

        let mut accounts: HashMap<AccountId, AccountEntry> = witness_index
            .iter()
            .map(|(&account_id, &index)| {
                (
                    account_id,
                    AccountEntry::Private {
                        witness_index: index,
                        data: witnesses[index].predecessor().data.clone(),
                    },
                )
            })
            .collect();
        for actor in &context.actors {
            let account_id = actor.account_id;
            if witness_index.contains_key(&account_id) {
                return Err(ExecutionError::PublicAndPrivate { account_id });
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
                context
                    .actors
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
            accounts,
            aliases: HashMap::new(),
            pda_family_binding,
            pending: Vec::new(),
            validity: ValidityWindows::new_unbounded(),
            events: Vec::new(),
            casts: Vec::new(),
            candidates: Candidates::default(),
            admitted: HashSet::new(),
        };
        for (alias, account_id) in openings {
            execution.register_alias(alias, account_id)?;
        }
        match root {
            Some(root) => {
                let (from, to, message) = match root {
                    TransactionEntry::Call(RootCall { to, message }) => (None, to, message),
                    TransactionEntry::Cast(MessageBody { from, to, message }) => {
                        (Some(from), to, message)
                    }
                };
                execution
                    .pending
                    .push(Item::Deliver(Box::new(Delivery::entry(MessageEnvelope {
                        from: Sender::Root { from },
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
        Ok(scope.finish(self)?)
    }

    // Placement is positive: a declared public actor runs publicly, a private witness's account
    // runs privately, and in a public part any other destination must be the next predicted
    // cross message.
    fn deliver<E: ExecutionEnvironment>(
        &mut self,
        scope: &mut S,
        mut delivery: Delivery<Sender>,
        environment: &mut E,
    ) -> Result<(), E::Error> {
        let to = delivery.envelope.to;
        // No code upgrade may land between a proof's image claims and the transitions it covers.
        if to.program_account_id == PROGRAM_LOADER_ACCOUNT_ID && !S::admits_loader(self) {
            return Err(ExecutionError::LoaderOutsidePublicExecution { actor: to }.into());
        }
        if self.context.runs_publicly(to) {
            if S::CHECKS_ADMISSION {
                self.admit(&delivery, environment)?;
            }
            // Each public subtree's private callbacks start out inheriting what its entry withheld.
            if self.opens_public_subtree(&delivery) {
                delivery.inherits_entry_authorizations = true;
            }
            scope.deliver_to_public(self, delivery, environment)
        } else {
            scope.deliver_to_private(self, delivery, environment)
        }
    }

    fn admit<E: ExecutionEnvironment>(
        &mut self,
        delivery: &Delivery<Sender>,
        environment: &mut E,
    ) -> Result<(), E::Error> {
        let to = delivery.envelope.to;
        let seeded = delivery.envelope.from.issuer().is_some_and(|issuer| {
            delivery
                .pda_seeds
                .iter()
                .any(|seed| AccountId::for_public_pda(&issuer, seed) == to.account_id)
        });
        if self.admitted.contains(&to.account_id) || seeded || environment.admits(to.account_id)? {
            self.admitted.insert(to.account_id);
            return Ok(());
        }
        Err(ExecutionError::UnadmittedPublicActor { actor: to }.into())
    }

    fn opens_public_subtree(&self, delivery: &Delivery<Sender>) -> bool {
        delivery
            .envelope
            .from
            .actor()
            .is_none_or(|sender| !self.context.runs_publicly(sender))
    }

    fn is_private(&self, account_id: &AccountId) -> bool {
        self.accounts
            .get(account_id)
            .is_some_and(AccountEntry::is_private)
    }

    fn resolve(&self, actor: Actor) -> Actor {
        self.aliases
            .get(&actor.account_id)
            .map_or(actor, |&account_id| {
                Actor::new(account_id, actor.program_account_id)
            })
    }

    fn register_alias(
        &mut self,
        alias: AccountId,
        account_id: AccountId,
    ) -> Result<(), ExecutionError> {
        if self.accounts.contains_key(&alias)
            || *self.aliases.entry(alias).or_insert(account_id) != account_id
        {
            return Err(ExecutionError::AliasCollision { alias });
        }
        Ok(())
    }

    fn require_private(&self, actor: Actor) -> Result<(), ExecutionError> {
        if self.is_private(&self.resolve(actor).account_id) {
            Ok(())
        } else {
            Err(ExecutionError::UndeclaredActor { actor })
        }
    }

    // No public handler can observe a grant over a private account, so a boundary or prediction
    // discloses only the other grants; the private part restores the withheld ones on re-entry.
    fn disclose<F, T>(&self, delivery: &Delivery<F>, from: T) -> Delivery<T> {
        let mut disclosed = delivery.with_from(from);
        disclosed
            .inherited_authorizations
            .retain(|account_id| !self.is_private(account_id));
        disclosed
    }

    // A private delivery from a declared public actor is where the execution crosses into a proven
    // transition: a whole transaction collects it into the innermost open public Call's predicted
    // cross messages, a private part records it.
    fn cross_message(&self, delivery: &Delivery<Sender>) -> Option<Delivery<Actor>> {
        delivery
            .envelope
            .from
            .actor()
            .filter(|&sender| self.context.runs_publicly(sender))
            .map(|sender| self.disclose(delivery, sender))
    }

    fn process_actor_message<E: ExecutionEnvironment>(
        &mut self,
        delivery: Delivery<Sender>,
        environment: &mut E,
    ) -> Result<(), E::Error> {
        let actor = self.resolve(delivery.envelope.to);
        let (is_authorized, authorizations) = self.authorize(actor, &delivery)?;
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
            from: delivery.envelope.from.source(),
            is_authorized,
            pre_state: entry
                .staged(actor.program_account_id)
                .expect("a delivered actor's state is loaded")
                .clone(),
            message: delivery.envelope.message,
        };

        let view = TransitionView {
            accounts: &self.accounts,
            at_root: matches!(delivery.envelope.from, Sender::Root { .. }),
        };
        let transition = environment.handle_message(&input, &view)?;
        if transition.input != input {
            return Err(ExecutionError::TransitionInputMismatch {
                program_account_id: actor.program_account_id,
                expected: Box::new(input),
                actual: Box::new(transition.input),
            }
            .into());
        }
        self.validity = self
            .validity
            .intersect(transition.response.validity)
            .map_err(|InvalidWindow| ExecutionError::EmptyValidityWindowIntersection)?;

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
        let reached = delivery.envelope.to;
        let call_reply = |to: Actor| (input.from == Some(to)).then_some(reached);
        let mut sent = transition
            .response
            .calls
            .into_iter()
            .map(
                |Call {
                     to,
                     message,
                     pda_seeds,
                 }| {
                    Ok(Delivery::sent(
                        self.sender(actor, call_reply(to), environment)?,
                        to,
                        message,
                        authorizations.clone(),
                        delivery.inherits_entry_authorizations,
                        pda_seeds,
                    ))
                },
            )
            .collect::<Result<Vec<_>, E::Error>>()?;
        for Cast { to, message } in transition.response.casts {
            let body = MessageBody {
                from: self.sender(actor, None, environment)?,
                to,
                message,
            };
            let promoted = self.context.runs_publicly(to) || {
                let placement = if self.is_private(&actor.account_id) {
                    Placement::Private
                } else {
                    Placement::Public
                };
                environment.promote(placement, self.candidates.next(placement), &body)?
            };
            if promoted {
                // A promoted Cast keeps transaction credentials but inherits no authorization.
                sent.push(Delivery::sent(
                    body.from,
                    body.to,
                    body.message,
                    BTreeSet::new(),
                    false,
                    BTreeSet::new(),
                ));
            } else {
                self.casts.push(body);
            }
        }
        self.pending
            .extend(sent.into_iter().rev().map(Box::new).map(Item::Deliver));
        Ok(())
    }

    // A private Call back to its sender preserves the reached address for authentication.
    // Every private Cast uses the prover's presentation: the reached address may have been
    // confined to a private Call and must not be published implicitly by a Cast reply.
    fn sender<E: ExecutionEnvironment>(
        &mut self,
        actor: Actor,
        call_reply: Option<Actor>,
        environment: &mut E,
    ) -> Result<Actor, E::Error> {
        if !self.is_private(&actor.account_id) {
            return Ok(actor);
        }
        if let Some(reached) = call_reply {
            return Ok(reached);
        }
        match environment.present(actor)? {
            SenderPresentation::Canonical => Ok(actor),
            SenderPresentation::Blinded(factor) => {
                let alias = actor.account_id.blinded(&factor);
                self.register_alias(alias, actor.account_id)?;
                Ok(Actor::new(alias, actor.program_account_id))
            }
        }
    }

    fn authorize(
        &mut self,
        actor: Actor,
        delivery: &Delivery<Sender>,
    ) -> Result<(bool, BTreeSet<AccountId>), ExecutionError> {
        let account_id = actor.account_id;
        let issuer = delivery.envelope.from.issuer();
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
                    witness.kind.is_authorized(),
                    private_seed_grant(issuer, &delivery.pda_seeds, witness),
                )
            }
        };
        let mut authorizations = delivery.inherited_authorizations.clone();
        if let Some((program, seed)) = granted {
            bind_family(&mut self.pda_family_binding, program, seed, account_id)?;
            authorizations.insert(account_id);
        }
        Ok((
            credential || authorizations.contains(&account_id),
            authorizations,
        ))
    }

    fn public(self) -> PublicOutcome {
        PublicOutcome {
            validity: self.validity,
            accounts: self
                .accounts
                .into_iter()
                .filter_map(|(account_id, entry)| match entry {
                    AccountEntry::Public { loaded, .. } => Some((
                        account_id,
                        AccountData {
                            actor_states: loaded,
                        },
                    )),
                    AccountEntry::Private { .. } => None,
                })
                .collect(),
            events: self.events,
            casts: self.casts,
        }
    }

    fn private_part(self, boundary: Boundary) -> PrivatePartOutcome {
        PrivatePartOutcome {
            validity: self.validity,
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
    pda_seeds: &BTreeSet<PdaSeed>,
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
