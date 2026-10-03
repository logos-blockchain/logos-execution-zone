use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, hash_map::Entry};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::{
    NullifierPublicKey, NullifierSecretKey, NullifierWitness, PrivateWitness, WitnessKind,
    account::{AccountData, AccountId, Actor, ActorState},
    program::{
        BlockValidityWindow, Call, Cast, ExecutionValidationError, InvalidWindow, MessageBody,
        MessageData, MessageEnvelope, PROGRAM_LOADER_ACCOUNT_ID, PdaSeed, ProgramEvent,
        ReceiveInput, StoredMessage, TimestampValidityWindow, Transition, validate_transition,
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
}

pub struct WholeTransaction<'witnesses>(Execution<'witnesses>);

pub struct PrivatePart<'witnesses>(Execution<'witnesses>);

pub struct PublicPart(Execution<'static>);

pub struct PublicOutcome {
    pub block_validity_window: BlockValidityWindow,
    pub timestamp_validity_window: TimestampValidityWindow,
    pub accounts: Vec<(AccountId, AccountData)>,
    pub events: Vec<(Actor, ProgramEvent)>,
    pub casts: Vec<MessageBody>,
}

pub struct WholeTransactionOutcome {
    pub public: PublicOutcome,
    pub predicted_cross_messages: Vec<Vec<Delivery<Actor>>>,
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
        view: &TurnView<'_>,
    ) -> Result<Transition, Self::Error>;

    /// Returns [`ExecutionError::PublicShardUnavailable`] by default.
    fn public_actor_state(&mut self, actor: Actor) -> Result<ActorState, Self::Error> {
        Err(ExecutionError::PublicShardUnavailable { actor }.into())
    }
}

pub struct TurnView<'execution> {
    accounts: &'execution HashMap<AccountId, AccountEntry>,
    at_root: bool,
}

impl TurnView<'_> {
    #[must_use]
    pub const fn at_root(&self) -> bool {
        self.at_root
    }

    #[must_use]
    pub fn runs_privately(&self, account_id: AccountId) -> bool {
        matches!(
            self.accounts.get(&account_id),
            Some(AccountEntry::Private { .. })
        )
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
    #[error("No public shard was supplied for {actor:?}")]
    PublicShardUnavailable { actor: Actor },

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

    #[error("The root delivery to {actor:?} does not execute in this part of the transaction")]
    MisplacedRoot { actor: Actor },

    #[error("Invalid program behavior in program {program_account_id}: {source}")]
    ExecutionValidation {
        program_account_id: AccountId,
        #[source]
        source: ExecutionValidationError,
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
    fn staged(&self, program_account_id: AccountId) -> Option<&ActorState> {
        match self {
            Self::Public { loaded, .. } => loaded.get(&program_account_id),
            Self::Private { data, .. } => Some(data.shard(program_account_id)),
        }
    }

    fn stage(&mut self, program_account_id: AccountId, state: ActorState) {
        match self {
            Self::Public { loaded, .. } => {
                loaded.insert(program_account_id, state);
            }
            Self::Private { data, .. } => data.set_shard(program_account_id, state),
        }
    }
}

enum Item {
    Deliver(Box<Delivery<Sender>>),
    ExitPublic,
    ExitPrivate,
    Continue { root: bool },
}

#[derive(Clone, Copy)]
enum Sender {
    Root,
    Cast(AccountId),
    Call(Actor),
    ProvenCall(AccountId),
}

impl Sender {
    const fn actor(self) -> Option<Actor> {
        match self {
            Self::Call(actor) => Some(actor),
            Self::Root | Self::Cast(_) | Self::ProvenCall(_) => None,
        }
    }

    const fn origin(self) -> Option<AccountId> {
        match self {
            Self::Root => None,
            Self::Call(actor) => Some(actor.program_account_id),
            Self::Cast(program) | Self::ProvenCall(program) => Some(program),
        }
    }

    const fn issuer(self) -> Option<AccountId> {
        match self {
            Self::Call(actor) => Some(actor.program_account_id),
            Self::ProvenCall(program) => Some(program),
            Self::Root | Self::Cast(_) => None,
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

enum Scope {
    WholeTransaction {
        predicted_cross_messages: PredictedCrossMessages,
        open: Vec<usize>,
    },
    PrivatePart {
        predicted_cross_messages: PredictedCrossMessages,
        next_group: usize,
        boundary: Boundary,
    },
    PublicPart {
        boundary: Boundary,
        cursor: usize,
    },
}

struct Execution<'witnesses> {
    witnesses: &'witnesses [PrivateWitness],
    context: PublicExecutionContext,
    public_actors: HashSet<Actor>,
    accounts: HashMap<AccountId, AccountEntry>,
    pda_family_binding: HashMap<(AccountId, PdaSeed), AccountId>,
    pending: Vec<Item>,
    block_validity_window: BlockValidityWindow,
    timestamp_validity_window: TimestampValidityWindow,
    scope: Scope,
    events: Vec<(Actor, ProgramEvent)>,
    casts: Vec<MessageBody>,
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
        let scope = Scope::WholeTransaction {
            predicted_cross_messages: Vec::new(),
            open: Vec::new(),
        };
        Execution::start(context, witnesses, Some(root), scope).map(Self)
    }

    pub fn execute<E: ExecutionEnvironment>(
        self,
        environment: &mut E,
    ) -> Result<WholeTransactionOutcome, E::Error> {
        let (scope, finished) = self.0.run(environment)?;
        let Scope::WholeTransaction {
            predicted_cross_messages,
            ..
        } = scope
        else {
            unreachable!("a whole transaction ends in its own scope")
        };
        Ok(WholeTransactionOutcome {
            public: finished.public(),
            predicted_cross_messages,
        })
    }
}

impl<'witnesses> PrivatePart<'witnesses> {
    pub fn new(
        context: PublicExecutionContext,
        root: Option<TransactionEntry<StoredMessage>>,
        witnesses: &'witnesses [PrivateWitness],
        predicted_cross_messages: PredictedCrossMessages,
    ) -> Result<Self, ExecutionError> {
        let scope = Scope::PrivatePart {
            predicted_cross_messages,
            next_group: 0,
            boundary: Boundary::new(),
        };
        Execution::start(context, witnesses, root, scope).map(Self)
    }

    pub fn execute<E: ExecutionEnvironment>(
        self,
        environment: &mut E,
    ) -> Result<PrivatePartOutcome, E::Error> {
        let (scope, finished) = self.0.run(environment)?;
        let Scope::PrivatePart { boundary, .. } = scope else {
            unreachable!("a private part ends in its own scope")
        };
        Ok(finished.private_part(boundary))
    }
}

impl PublicPart {
    pub fn new(
        context: PublicExecutionContext,
        root: Option<TransactionEntry<StoredMessage>>,
        boundary: Boundary,
    ) -> Result<Self, ExecutionError> {
        let scope = Scope::PublicPart {
            boundary,
            cursor: 0,
        };
        Execution::start(context, &[], root, scope).map(Self)
    }

    pub fn execute<E: ExecutionEnvironment>(
        self,
        environment: &mut E,
    ) -> Result<PublicOutcome, E::Error> {
        let (_, finished) = self.0.run(environment)?;
        Ok(finished.public())
    }
}

impl<'witnesses> Execution<'witnesses> {
    fn start(
        context: PublicExecutionContext,
        witnesses: &'witnesses [PrivateWitness],
        root: Option<TransactionEntry<StoredMessage>>,
        scope: Scope,
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

        if let Some(root) = &root {
            let actor = root.destination();
            let runs_publicly = public_actors.contains(&actor);
            let misplaced = match scope {
                Scope::WholeTransaction { .. } => false,
                Scope::PrivatePart { .. } => runs_publicly,
                Scope::PublicPart { .. } => !runs_publicly,
            };
            if misplaced {
                return Err(ExecutionError::MisplacedRoot { actor });
            }
        }

        let mut execution = Self {
            witnesses,
            context,
            public_actors,
            accounts,
            pda_family_binding,
            pending: Vec::new(),
            block_validity_window: BlockValidityWindow::new_unbounded(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
            scope,
            events: Vec::new(),
            casts: Vec::new(),
        };
        match root {
            Some(TransactionEntry::Call { to, message }) => {
                execution
                    .pending
                    .push(Item::Deliver(Box::new(Delivery::entry(MessageEnvelope {
                        source: Sender::Root,
                        to,
                        message,
                    }))));
            }
            Some(TransactionEntry::Cast(StoredMessage {
                body:
                    MessageBody {
                        source,
                        to,
                        message,
                    },
                ..
            })) => {
                execution
                    .pending
                    .push(Item::Deliver(Box::new(Delivery::entry(MessageEnvelope {
                        source: Sender::Cast(source),
                        to,
                        message,
                    }))));
            }
            None if matches!(execution.scope, Scope::PublicPart { .. }) => {
                execution.pending.push(Item::Continue { root: true });
            }
            None => execution.deliver_predicted_cross_messages()?,
        }
        Ok(execution)
    }

    fn run<E: ExecutionEnvironment>(
        mut self,
        environment: &mut E,
    ) -> Result<(Scope, Finished), E::Error> {
        while let Some(item) = self.pending.pop() {
            match item {
                Item::Deliver(delivery) => self.deliver(*delivery, environment)?,
                Item::ExitPublic => self.exit(BoundaryStep::ExitPublic)?,
                Item::ExitPrivate => self.exit(BoundaryStep::ExitPrivate)?,
                Item::Continue { root } => self.resume(root)?,
            }
        }
        match &self.scope {
            Scope::WholeTransaction { .. } => {}
            Scope::PrivatePart {
                predicted_cross_messages,
                next_group,
                ..
            } => {
                if predicted_cross_messages.len() > *next_group {
                    return Err(ExecutionError::UnusedPredictedCrossMessages.into());
                }
            }
            Scope::PublicPart { boundary, cursor } => {
                if *cursor != boundary.len() {
                    return Err(ExecutionError::IncompleteBoundary.into());
                }
            }
        }
        Ok(self.finish())
    }

    fn exit(&mut self, marker: BoundaryStep) -> Result<(), ExecutionError> {
        match &mut self.scope {
            Scope::WholeTransaction { open, .. } => {
                open.pop();
                Ok(())
            }
            Scope::PrivatePart { boundary, .. } => {
                boundary.push(marker);
                Ok(())
            }
            Scope::PublicPart { boundary, cursor } => {
                if boundary.get(*cursor) != Some(&marker) {
                    return Err(ExecutionError::BoundaryMismatch { index: *cursor });
                }
                step_past(cursor);
                Ok(())
            }
        }
    }

    fn resume(&mut self, root: bool) -> Result<(), ExecutionError> {
        let Scope::PublicPart { boundary, cursor } = &mut self.scope else {
            unreachable!("only a public part resumes a proven continuation");
        };
        match (boundary.get(*cursor), root) {
            (Some(BoundaryStep::EnterPublic(proven)), _) => {
                let delivery = proven.with_source(Sender::ProvenCall(proven.envelope.source));
                step_past(cursor);
                self.pending.push(Item::Continue { root });
                self.pending.push(Item::ExitPublic);
                self.pending.push(Item::Deliver(Box::new(delivery)));
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
            ) => Err(ExecutionError::BoundaryMismatch { index: *cursor }),
        }
    }

    // Placement is positive: a declared public actor runs publicly, a private witness's account
    // runs privately, and in a public part any other destination must be the next predicted
    // cross message.
    fn deliver<E: ExecutionEnvironment>(
        &mut self,
        delivery: Delivery<Sender>,
        environment: &mut E,
    ) -> Result<(), E::Error> {
        let to = delivery.envelope.to;
        // No code upgrade may land between a proof's image claims and the turns it covers.
        if to.program_account_id == PROGRAM_LOADER_ACCOUNT_ID
            && !(matches!(self.scope, Scope::WholeTransaction { .. }) && self.witnesses.is_empty())
        {
            return Err(ExecutionError::LoaderOutsidePublicExecution { actor: to }.into());
        }
        if self.public_actors.contains(&to) {
            return self.deliver_public(delivery, environment);
        }
        match (&self.scope, self.accounts.get(&to.account_id)) {
            (
                Scope::WholeTransaction { .. } | Scope::PrivatePart { .. },
                Some(AccountEntry::Private { .. }),
            ) => self.deliver_private(delivery, environment),
            (Scope::PublicPart { .. }, None) => Ok(self.check_cross_message(&delivery)?),
            _ => Err(ExecutionError::UndeclaredActor { actor: to }.into()),
        }
    }

    // A private delivery from a declared public actor is where the execution crosses into a proven
    // turn: a whole transaction collects it into the innermost open public Call's predicted
    // cross messages, a private part records it.
    fn deliver_private<E: ExecutionEnvironment>(
        &mut self,
        delivery: Delivery<Sender>,
        environment: &mut E,
    ) -> Result<(), E::Error> {
        if let Some(sender) = delivery.envelope.source.actor()
            && self.public_actors.contains(&sender)
        {
            let cross_message = delivery.with_source(sender);
            match &mut self.scope {
                Scope::WholeTransaction {
                    predicted_cross_messages,
                    open,
                } => {
                    let group = *open
                        .last()
                        .expect("a public sender runs within an open call");
                    predicted_cross_messages[group].push(cross_message);
                }
                Scope::PrivatePart { boundary, .. } => {
                    boundary.push(BoundaryStep::EnterPrivate(cross_message));
                    self.pending.push(Item::ExitPrivate);
                }
                Scope::PublicPart { .. } => {
                    unreachable!(
                        "only a whole transaction or a private part executes private turns"
                    )
                }
            }
        }
        self.execute(delivery, environment)
    }

    fn check_cross_message(&mut self, delivery: &Delivery<Sender>) -> Result<(), ExecutionError> {
        let Scope::PublicPart { boundary, cursor } = &mut self.scope else {
            unreachable!("only a public part matches predicted cross messages");
        };
        let index = *cursor;
        let Some(BoundaryStep::EnterPrivate(predicted)) = boundary.get(index) else {
            return Err(ExecutionError::BoundaryMismatch { index });
        };
        // A proven turn ran under exactly the authority the live delivery carries.
        let live = delivery
            .envelope
            .source
            .actor()
            .map(|sender| delivery.with_source(sender));
        if live.as_ref() != Some(predicted) {
            return Err(ExecutionError::CrossMessageMismatch { index });
        }
        step_past(cursor);
        self.pending.push(Item::ExitPrivate);
        self.pending.push(Item::Continue { root: false });
        Ok(())
    }

    fn deliver_public<E: ExecutionEnvironment>(
        &mut self,
        delivery: Delivery<Sender>,
        environment: &mut E,
    ) -> Result<(), E::Error> {
        match &mut self.scope {
            // The root and each Call from a private turn start a public subtree, whose deliveries
            // into private actors form one group of predicted cross messages.
            Scope::WholeTransaction {
                predicted_cross_messages,
                open,
            } => {
                if delivery
                    .envelope
                    .source
                    .actor()
                    .is_none_or(|sender| !self.public_actors.contains(&sender))
                {
                    open.push(predicted_cross_messages.len());
                    predicted_cross_messages.push(Vec::new());
                    self.pending.push(Item::ExitPublic);
                }
                self.execute(delivery, environment)
            }
            Scope::PublicPart { .. } => self.execute(delivery, environment),
            Scope::PrivatePart { boundary, .. } => {
                let program = delivery
                    .envelope
                    .source
                    .issuer()
                    .expect("only a Call from a private turn crosses into public execution");
                boundary.push(BoundaryStep::EnterPublic(delivery.with_source(program)));
                self.pending.push(Item::ExitPublic);
                Ok(self.deliver_predicted_cross_messages()?)
            }
        }
    }

    fn deliver_predicted_cross_messages(&mut self) -> Result<(), ExecutionError> {
        let Scope::PrivatePart {
            predicted_cross_messages,
            next_group,
            ..
        } = &mut self.scope
        else {
            unreachable!("only a private part predicts cross messages");
        };
        let index = *next_group;
        let cross_messages = predicted_cross_messages
            .get(index)
            .ok_or(ExecutionError::MissingPredictedCrossMessages { index })?;
        step_past(next_group);
        for cross_message in cross_messages.iter().rev() {
            let sender = cross_message.envelope.source;
            if !self.public_actors.contains(&sender) {
                return Err(ExecutionError::UndeclaredCrossMessageSender { actor: sender });
            }
            self.pending.push(Item::Deliver(Box::new(
                cross_message.with_source(Sender::Call(sender)),
            )));
        }
        Ok(())
    }

    fn execute<E: ExecutionEnvironment>(
        &mut self,
        delivery: Delivery<Sender>,
        environment: &mut E,
    ) -> Result<(), E::Error> {
        let actor = delivery.envelope.to;
        let (is_authorized, grants) = self.authorize(&delivery, actor)?;
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

        let view = TurnView {
            accounts: &self.accounts,
            at_root: matches!(delivery.envelope.source, Sender::Root | Sender::Cast(_)),
        };
        let transition = environment.receive(&input, &view)?;
        validate_transition(&input, &transition).map_err(|source| {
            ExecutionError::ExecutionValidation {
                program_account_id: actor.program_account_id,
                source,
            }
        })?;
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
        if !matches!(self.scope, Scope::PrivatePart { .. }) {
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
        actor: Actor,
    ) -> Result<(bool, BTreeSet<AccountId>), ExecutionError> {
        let account_id = actor.account_id;
        let caller_account_id = delivery.envelope.source.issuer();
        let entry = self
            .accounts
            .get(&account_id)
            .ok_or(ExecutionError::UndeclaredActor { actor })?;
        let (credential, granted) = match entry {
            AccountEntry::Public { is_authorized, .. } => (
                *is_authorized,
                caller_account_id.and_then(|caller| {
                    delivery
                        .pda_seeds
                        .iter()
                        .find(|seed| AccountId::for_public_pda(&caller, seed) == account_id)
                        .map(|seed| (caller, *seed))
                }),
            ),
            AccountEntry::Private { witness_index, .. } => {
                let witness = &self.witnesses[*witness_index];
                (
                    matches!(witness.kind, WitnessKind::Regular { ask: Some(_) }),
                    private_seed_grant(caller_account_id, &delivery.pda_seeds, witness),
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

    fn finish(self) -> (Scope, Finished) {
        let Self {
            context,
            accounts,
            block_validity_window,
            timestamp_validity_window,
            scope,
            events,
            casts,
            ..
        } = self;
        (
            scope,
            Finished {
                context,
                accounts,
                events,
                casts,
                block_validity_window,
                timestamp_validity_window,
            },
        )
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
            public.push((actor.account_id, AccountData { shards: loaded }));
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
    caller_account_id: Option<AccountId>,
    pda_seeds: &[PdaSeed],
    witness: &PrivateWitness,
) -> Option<(AccountId, PdaSeed)> {
    witness
        .pda_binding()
        .filter(|&(program, seed)| Some(program) == caller_account_id && pda_seeds.contains(&seed))
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
