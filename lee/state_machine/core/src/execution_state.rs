use std::collections::{BTreeSet, HashMap, HashSet, VecDeque, hash_map::Entry};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::{
    NullifierPublicKey, NullifierSecretKey, NullifierWitness, PrivateWitness, WitnessKind,
    account::{AccountData, AccountId, Actor, ActorState},
    program::{
        Action, BlockValidityWindow, Call, ExecutionValidationError, InvalidWindow, MessageBody,
        MessageData, MessageEnvelope, Origin, PROGRAM_LOADER_ACCOUNT_ID, PdaSeed, ProgramEvent,
        ReceiveInput, StoredMessage, TimestampValidityWindow, Transition, validate_transition,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum TransactionEntry<R> {
    Call { to: Actor, message: MessageData },
    Receive(R),
}

impl TransactionEntry<StoredMessage> {
    #[must_use]
    pub const fn destination(&self) -> Actor {
        match self {
            Self::Call { to, .. } => *to,
            Self::Receive(record) => record.body.to,
        }
    }

    #[must_use]
    pub const fn receipt(&self) -> Option<&StoredMessage> {
        match self {
            Self::Call { .. } => None,
            Self::Receive(record) => Some(record),
        }
    }
}

#[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
pub struct Declared {
    pub public_actors: Vec<Actor>,
    pub authorized_accounts: Vec<AccountId>,
}

impl Declared {
    pub fn new(
        public_actors: Vec<Actor>,
        authorized_accounts: impl IntoIterator<Item = AccountId>,
    ) -> Self {
        Self {
            public_actors,
            authorized_accounts: authorized_accounts
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        }
    }
}

pub enum Mode {
    Live(TransactionEntry<StoredMessage>),
    Derive(TransactionEntry<StoredMessage>),
    Record {
        root: TransactionEntry<StoredMessage>,
        assumed: Vec<Vec<Assumption>>,
    },
    Check(Boundary),
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum DeliverySource {
    Root,
    Call(AccountId),
    Cast(AccountId),
}

impl DeliverySource {
    #[must_use]
    pub const fn origin(self) -> Origin {
        match self {
            Self::Root => Origin::Root,
            Self::Call(program) | Self::Cast(program) => Origin::Program(program),
        }
    }

    #[must_use]
    pub const fn issuer(self) -> Option<AccountId> {
        match self {
            Self::Call(program) => Some(program),
            Self::Root | Self::Cast(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct PublicDelivery {
    pub envelope: MessageEnvelope<DeliverySource>,
    pub grants: Vec<AccountId>,
    pub pda_seeds: Vec<PdaSeed>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Assumption {
    pub envelope: MessageEnvelope<Actor>,
    pub grants: Vec<AccountId>,
    pub pda_seeds: Vec<PdaSeed>,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum ScheduleOp {
    CallPublic,
    EnterPrivate,
    LeavePrivate,
    ReturnPublic,
    Cast,
}

#[derive(
    Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct Boundary {
    pub public_deliveries: Vec<PublicDelivery>,
    pub assumptions: Vec<Assumption>,
    pub casts: Vec<MessageBody>,
    pub schedule: Vec<ScheduleOp>,
}

pub trait Backend {
    type Error: From<ExecutionError>;

    fn receive(
        &mut self,
        input: &ReceiveInput,
        execution: &ExecutionState<'_>,
    ) -> Result<Transition, Self::Error>;

    /// Returns [`ExecutionError::PublicShardUnavailable`] by default.
    fn public_shard(&mut self, actor: Actor) -> Result<ActorState, Self::Error> {
        Err(ExecutionError::PublicShardUnavailable { actor }.into())
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
    LoaderOutsideLiveExecution { actor: Actor },

    #[error("A delivery named {actor:?}, which is neither a declared public actor nor private")]
    UndeclaredActor { actor: Actor },

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

    #[error("No assumed deliveries were supplied for public delivery {index}")]
    MissingAssumedDeliveries { index: usize },

    #[error("Assumed deliveries were supplied for public deliveries the execution never produced")]
    UnusedAssumedDeliveries,

    #[error("Assumed delivery sender {actor:?} is not a declared public actor")]
    UndeclaredAssumedSender { actor: Actor },

    #[error("Boundary schedule does not have {expected:?} at {index}")]
    ScheduleMismatch { index: usize, expected: ScheduleOp },

    #[error("Boundary assumption {index} does not match the executed delivery")]
    AssumptionMismatch { index: usize },

    #[error("Boundary was not consumed exactly by the execution")]
    IncompleteBoundary,
}

pub struct ExecutionOutcome {
    pub block_validity_window: BlockValidityWindow,
    pub timestamp_validity_window: TimestampValidityWindow,
    pub result: ExecutionResult,
}

pub enum ExecutionResult {
    Derived {
        assumed: Vec<Vec<Assumption>>,
    },
    Recorded {
        private_accounts: HashMap<AccountId, AccountData>,
        boundary: Boundary,
    },
    Settled {
        public: Vec<(AccountId, AccountData)>,
        events: Vec<(Actor, ProgramEvent)>,
        casts: Vec<MessageBody>,
    },
}

enum Visibility {
    Public {
        is_authorized: bool,
        observed: BTreeSet<AccountId>,
    },
    Private(usize),
}

struct AccountEntry {
    data: AccountData,
    visibility: Visibility,
}

enum Item {
    Deliver(Box<Delivery>),
    Cast(MessageBody),
    ClosePublic,
    ClosePrivate,
    Continue { root: bool },
}

// The sender is the internal sending actor: `None` for the root and for a proven public delivery,
// whose source publishes only the sending program.
struct Delivery {
    envelope: MessageEnvelope<DeliverySource>,
    sender: Option<Actor>,
    grants: BTreeSet<AccountId>,
    pda_seeds: Vec<PdaSeed>,
}

impl Delivery {
    const fn entry(envelope: MessageEnvelope<DeliverySource>) -> Self {
        Self {
            envelope,
            sender: None,
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
                source: DeliverySource::Call(from.program_account_id),
                to,
                message,
            },
            sender: Some(from),
            grants,
            pda_seeds,
        }
    }
}

enum ModeState {
    Live,
    Derive {
        groups: Vec<Vec<Assumption>>,
        open: Vec<usize>,
    },
    Record {
        assumed: Vec<Vec<Assumption>>,
        boundary: Boundary,
    },
    Check {
        boundary: Boundary,
        cursor: usize,
        public_deliveries_consumed: usize,
        assumptions_consumed: usize,
        casts_consumed: usize,
    },
}

pub struct ExecutionState<'witnesses> {
    witnesses: &'witnesses [PrivateWitness],
    declared: Declared,
    public_actors: HashSet<Actor>,
    accounts: HashMap<AccountId, AccountEntry>,
    pda_family_binding: HashMap<(AccountId, PdaSeed), AccountId>,
    pending: VecDeque<Item>,
    block_validity_window: BlockValidityWindow,
    timestamp_validity_window: TimestampValidityWindow,
    mode: ModeState,
    at_root: bool,
    events: Vec<(Actor, ProgramEvent)>,
    casts: Vec<MessageBody>,
}

impl<'witnesses> ExecutionState<'witnesses> {
    pub fn initialize(
        declared: Declared,
        witnesses: &'witnesses [PrivateWitness],
        mode: Mode,
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
                    AccountEntry {
                        data,
                        visibility: Visibility::Private(index),
                    },
                )
            })
            .collect();
        let mut public_actors = HashSet::with_capacity(declared.public_actors.len());
        for actor in &declared.public_actors {
            let account_id = actor.account_id;
            if witness_index.contains_key(&account_id) {
                return Err(ExecutionError::PublicAndPrivate { account_id });
            }
            if !public_actors.insert(*actor) {
                return Err(ExecutionError::DuplicatePublicActor { actor: *actor });
            }
            accounts.entry(account_id).or_insert_with(|| AccountEntry {
                data: AccountData::default(),
                visibility: Visibility::Public {
                    is_authorized: declared.authorized_accounts.contains(&account_id),
                    observed: BTreeSet::new(),
                },
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

        let (entry, mode) = match mode {
            Mode::Live(entry) => (Some(entry), ModeState::Live),
            Mode::Derive(entry) => (
                Some(entry),
                ModeState::Derive {
                    groups: Vec::new(),
                    open: Vec::new(),
                },
            ),
            Mode::Record { root, assumed } => (
                Some(root),
                ModeState::Record {
                    assumed,
                    boundary: Boundary::default(),
                },
            ),
            Mode::Check(boundary) => (
                None,
                ModeState::Check {
                    boundary,
                    cursor: 0,
                    public_deliveries_consumed: 0,
                    assumptions_consumed: 0,
                    casts_consumed: 0,
                },
            ),
        };
        let first = match entry {
            Some(TransactionEntry::Call { to, message }) => {
                Item::Deliver(Box::new(Delivery::entry(MessageEnvelope {
                    source: DeliverySource::Root,
                    to,
                    message,
                })))
            }
            Some(TransactionEntry::Receive(StoredMessage {
                body:
                    MessageBody {
                        source,
                        to,
                        message,
                    },
                ..
            })) => Item::Deliver(Box::new(Delivery::entry(MessageEnvelope {
                source: DeliverySource::Cast(source),
                to,
                message,
            }))),
            None => Item::Continue { root: true },
        };

        Ok(Self {
            witnesses,
            declared,
            public_actors,
            accounts,
            pda_family_binding,
            pending: VecDeque::from([first]),
            block_validity_window: BlockValidityWindow::new_unbounded(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
            mode,
            at_root: false,
            events: Vec::new(),
            casts: Vec::new(),
        })
    }

    pub fn run<B: Backend>(mut self, backend: &mut B) -> Result<ExecutionOutcome, B::Error> {
        while let Some(item) = self.pending.pop_front() {
            match item {
                Item::Deliver(delivery) => self.deliver(*delivery, backend)?,
                Item::Cast(body) => self.cast(body),
                Item::ClosePublic => self.close(ScheduleOp::ReturnPublic)?,
                Item::ClosePrivate => self.close(ScheduleOp::LeavePrivate)?,
                Item::Continue { root } => self.resume(root)?,
            }
        }
        match &self.mode {
            ModeState::Live | ModeState::Derive { .. } => {}
            ModeState::Record { assumed, boundary } => {
                if assumed.len() > boundary.public_deliveries.len() {
                    return Err(ExecutionError::UnusedAssumedDeliveries.into());
                }
            }
            ModeState::Check {
                boundary,
                cursor,
                public_deliveries_consumed,
                assumptions_consumed,
                casts_consumed,
            } => {
                if *cursor != boundary.schedule.len()
                    || *public_deliveries_consumed != boundary.public_deliveries.len()
                    || *assumptions_consumed != boundary.assumptions.len()
                    || *casts_consumed != boundary.casts.len()
                {
                    return Err(ExecutionError::IncompleteBoundary.into());
                }
            }
        }
        Ok(self.finish())
    }

    fn close(&mut self, op: ScheduleOp) -> Result<(), ExecutionError> {
        match &mut self.mode {
            ModeState::Live => unreachable!("a live execution crosses no boundary"),
            ModeState::Derive { open, .. } => {
                open.pop();
                Ok(())
            }
            ModeState::Record { boundary, .. } => {
                boundary.schedule.push(op);
                Ok(())
            }
            ModeState::Check {
                boundary, cursor, ..
            } => expect_op(&boundary.schedule, cursor, op),
        }
    }

    fn resume(&mut self, root: bool) -> Result<(), ExecutionError> {
        let ModeState::Check {
            boundary,
            cursor,
            public_deliveries_consumed,
            casts_consumed,
            ..
        } = &mut self.mode
        else {
            unreachable!("only a check resumes a proven continuation");
        };
        match (boundary.schedule.get(*cursor), root) {
            (Some(ScheduleOp::CallPublic), _) => {
                let PublicDelivery {
                    envelope,
                    grants,
                    pda_seeds,
                } = boundary
                    .public_deliveries
                    .get(*public_deliveries_consumed)
                    .ok_or(ExecutionError::IncompleteBoundary)?
                    .clone();
                expect_op(&boundary.schedule, cursor, ScheduleOp::CallPublic)?;
                *public_deliveries_consumed = public_deliveries_consumed
                    .checked_add(1)
                    .expect("bounded by the public delivery count");
                self.pending.push_front(Item::Continue { root });
                self.pending.push_front(Item::ClosePublic);
                self.pending.push_front(Item::Deliver(Box::new(Delivery {
                    envelope,
                    sender: None,
                    grants: grants.into_iter().collect(),
                    pda_seeds,
                })));
                Ok(())
            }
            (Some(ScheduleOp::Cast), _) => {
                let cast = boundary
                    .casts
                    .get(*casts_consumed)
                    .ok_or(ExecutionError::IncompleteBoundary)?
                    .clone();
                expect_op(&boundary.schedule, cursor, ScheduleOp::Cast)?;
                *casts_consumed = casts_consumed
                    .checked_add(1)
                    .expect("bounded by the cast count");
                self.casts.push(cast);
                self.pending.push_front(Item::Continue { root });
                Ok(())
            }
            (None, true) | (Some(ScheduleOp::LeavePrivate), false) => Ok(()),
            (
                None
                | Some(
                    ScheduleOp::EnterPrivate | ScheduleOp::LeavePrivate | ScheduleOp::ReturnPublic,
                ),
                _,
            ) => Err(ExecutionError::ScheduleMismatch {
                index: *cursor,
                expected: ScheduleOp::CallPublic,
            }),
        }
    }

    fn cast(&mut self, body: MessageBody) {
        match &mut self.mode {
            ModeState::Live | ModeState::Check { .. } => self.casts.push(body),
            ModeState::Record { boundary, .. } => {
                boundary.schedule.push(ScheduleOp::Cast);
                boundary.casts.push(body);
            }
            ModeState::Derive { .. } => {}
        }
    }

    // Placement is positive: a declared public actor runs publicly, a private witness's account
    // runs privately, and while checking any other destination must be the next assumed
    // delivery.
    fn deliver<B: Backend>(&mut self, delivery: Delivery, backend: &mut B) -> Result<(), B::Error> {
        let to = delivery.envelope.to;
        // No code upgrade may land between a proof's image claims and the turns it covers.
        if to.program_account_id == PROGRAM_LOADER_ACCOUNT_ID
            && !matches!(self.mode, ModeState::Live)
        {
            return Err(ExecutionError::LoaderOutsideLiveExecution { actor: to }.into());
        }
        if self.public_actors.contains(&to) {
            return self.deliver_public(delivery, backend);
        }
        match (
            &self.mode,
            self.accounts
                .get(&to.account_id)
                .map(|entry| &entry.visibility),
        ) {
            (ModeState::Derive { .. } | ModeState::Record { .. }, Some(Visibility::Private(_))) => {
                self.deliver_private(delivery, backend)
            }
            (ModeState::Check { .. }, None) => Ok(self.check_assumption(&delivery)?),
            _ => Err(ExecutionError::UndeclaredActor { actor: to }.into()),
        }
    }

    // A private delivery from a declared public actor is where the execution crosses into a proven
    // turn: a derivation assumes it within the innermost open public call, a record replays it.
    fn deliver_private<B: Backend>(
        &mut self,
        delivery: Delivery,
        backend: &mut B,
    ) -> Result<(), B::Error> {
        let crossing = delivery
            .sender
            .filter(|sender| self.public_actors.contains(sender));
        if let Some(from) = crossing {
            let assumption = Assumption {
                envelope: MessageEnvelope {
                    source: from,
                    to: delivery.envelope.to,
                    message: delivery.envelope.message.clone(),
                },
                grants: delivery.grants.iter().copied().collect(),
                pda_seeds: delivery.pda_seeds.clone(),
            };
            match &mut self.mode {
                ModeState::Derive { groups, open } => {
                    let group = *open
                        .last()
                        .expect("a public sender runs within an open call");
                    groups[group].push(assumption);
                }
                ModeState::Record { boundary, .. } => {
                    boundary.schedule.push(ScheduleOp::EnterPrivate);
                    boundary.assumptions.push(assumption);
                    self.pending.push_front(Item::ClosePrivate);
                }
                ModeState::Live | ModeState::Check { .. } => {
                    unreachable!("only a derivation or a record executes private turns")
                }
            }
        }
        self.execute(delivery, backend)
    }

    fn check_assumption(&mut self, delivery: &Delivery) -> Result<(), ExecutionError> {
        let ModeState::Check {
            boundary,
            cursor,
            assumptions_consumed,
            ..
        } = &mut self.mode
        else {
            unreachable!("only a check matches assumed deliveries");
        };
        expect_op(&boundary.schedule, cursor, ScheduleOp::EnterPrivate)?;
        let index = *assumptions_consumed;
        let assumed = boundary
            .assumptions
            .get(index)
            .ok_or(ExecutionError::IncompleteBoundary)?;
        // A proven turn ran under exactly the authority the live delivery carries.
        if Some(assumed.envelope.source) != delivery.sender
            || assumed.envelope.to != delivery.envelope.to
            || assumed.envelope.message != delivery.envelope.message
            || assumed.pda_seeds != delivery.pda_seeds
            || assumed.grants.iter().copied().collect::<BTreeSet<_>>() != delivery.grants
        {
            return Err(ExecutionError::AssumptionMismatch { index });
        }
        *assumptions_consumed = index
            .checked_add(1)
            .expect("bounded by the assumption count");
        self.pending.push_front(Item::ClosePrivate);
        self.pending.push_front(Item::Continue { root: false });
        Ok(())
    }

    fn deliver_public<B: Backend>(
        &mut self,
        delivery: Delivery,
        backend: &mut B,
    ) -> Result<(), B::Error> {
        let (assumed, boundary) = match &mut self.mode {
            ModeState::Record { assumed, boundary } => (assumed, boundary),
            // A call from the root or a private turn is what a record publishes as a public
            // delivery.
            ModeState::Derive { groups, open } => {
                if delivery
                    .sender
                    .is_none_or(|sender| !self.public_actors.contains(&sender))
                {
                    open.push(groups.len());
                    groups.push(Vec::new());
                    self.pending.push_front(Item::ClosePublic);
                }
                return self.execute(delivery, backend);
            }
            ModeState::Live | ModeState::Check { .. } => return self.execute(delivery, backend),
        };
        let index = boundary.public_deliveries.len();
        boundary.public_deliveries.push(public_delivery(&delivery));
        boundary.schedule.push(ScheduleOp::CallPublic);
        let deliveries = assumed
            .get(index)
            .ok_or(ExecutionError::MissingAssumedDeliveries { index })?;
        self.pending.push_front(Item::ClosePublic);
        for Assumption {
            envelope,
            grants,
            pda_seeds,
        } in deliveries.iter().rev()
        {
            if !self.public_actors.contains(&envelope.source) {
                return Err(ExecutionError::UndeclaredAssumedSender {
                    actor: envelope.source,
                }
                .into());
            }
            self.pending
                .push_front(Item::Deliver(Box::new(Delivery::sent(
                    envelope.source,
                    envelope.to,
                    envelope.message.clone(),
                    grants.iter().copied().collect(),
                    pda_seeds.clone(),
                ))));
        }
        Ok(())
    }

    fn execute<B: Backend>(&mut self, delivery: Delivery, backend: &mut B) -> Result<(), B::Error> {
        let actor = delivery.envelope.to;
        let (is_authorized, grants) = self.authorize(&delivery, actor)?;
        let entry = self
            .accounts
            .get_mut(&actor.account_id)
            .expect("an authorized actor has an entry");
        if let Visibility::Public { observed, .. } = &mut entry.visibility
            && !observed.contains(&actor.program_account_id)
        {
            let shard = backend.public_shard(actor)?;
            observed.insert(actor.program_account_id);
            entry.data.set_shard(actor.program_account_id, shard);
        }
        let input = ReceiveInput {
            receiver: actor,
            origin: delivery.envelope.source.origin(),
            is_authorized,
            pre_state: entry.data.shard(actor.program_account_id).clone(),
            message: delivery.envelope.message,
        };

        self.at_root = !matches!(delivery.envelope.source, DeliverySource::Call(_));
        let transition = backend.receive(&input, self)?;
        validate_transition(&input, &transition).map_err(|source| {
            ExecutionError::ExecutionValidation {
                program_account_id: actor.program_account_id,
                source,
            }
        })?;
        let block = self
            .block_validity_window
            .intersect(transition.block_validity_window)
            .map_err(|InvalidWindow| ExecutionError::EmptyBlockWindowIntersection)?;
        let timestamp = self
            .timestamp_validity_window
            .intersect(transition.timestamp_validity_window)
            .map_err(|InvalidWindow| ExecutionError::EmptyTimestampWindowIntersection)?;
        self.block_validity_window = block;
        self.timestamp_validity_window = timestamp;

        if let Some(data) = transition.post_state {
            self.accounts
                .get_mut(&actor.account_id)
                .expect("an authorized actor has an entry")
                .data
                .set_shard(actor.program_account_id, data);
        }
        if matches!(self.mode, ModeState::Live | ModeState::Check { .. }) {
            self.events
                .extend(transition.events.into_iter().map(|event| (actor, event)));
        }
        for action in transition.sends.into_iter().rev() {
            self.pending.push_front(match action {
                Action::Call(Call {
                    to,
                    message,
                    pda_seeds,
                }) => Item::Deliver(Box::new(Delivery::sent(
                    actor,
                    to,
                    message,
                    grants.clone(),
                    pda_seeds,
                ))),
                Action::Cast(cast) => Item::Cast(MessageBody {
                    source: actor.program_account_id,
                    to: cast.to,
                    message: cast.message,
                }),
            });
        }
        Ok(())
    }

    fn authorize(
        &mut self,
        delivery: &Delivery,
        actor: Actor,
    ) -> Result<(bool, BTreeSet<AccountId>), ExecutionError> {
        let account_id = actor.account_id;
        let caller_account_id = delivery.envelope.source.issuer();
        let entry = self
            .accounts
            .get(&account_id)
            .ok_or(ExecutionError::UndeclaredActor { actor })?;
        let (credential, granted) = match entry.visibility {
            Visibility::Public { is_authorized, .. } => (
                is_authorized,
                caller_account_id.and_then(|caller| {
                    delivery
                        .pda_seeds
                        .iter()
                        .find(|seed| AccountId::for_public_pda(&caller, seed) == account_id)
                        .map(|seed| (caller, *seed))
                }),
            ),
            Visibility::Private(index) => {
                let witness = &self.witnesses[index];
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

    #[must_use]
    pub const fn block_validity_window(&self) -> BlockValidityWindow {
        self.block_validity_window
    }

    #[must_use]
    pub const fn timestamp_validity_window(&self) -> TimestampValidityWindow {
        self.timestamp_validity_window
    }

    #[must_use]
    pub fn runs_privately(&self, account_id: AccountId) -> bool {
        self.accounts
            .get(&account_id)
            .is_some_and(|entry| matches!(entry.visibility, Visibility::Private(_)))
    }

    #[must_use]
    pub const fn at_root(&self) -> bool {
        self.at_root
    }

    #[must_use]
    pub fn pending_shard(
        &self,
        account_id: AccountId,
        program_account_id: AccountId,
    ) -> Option<&ActorState> {
        let entry = self.accounts.get(&account_id)?;
        match &entry.visibility {
            Visibility::Public { observed, .. } if !observed.contains(&program_account_id) => None,
            Visibility::Public { .. } | Visibility::Private(_) => {
                Some(entry.data.shard(program_account_id))
            }
        }
    }

    fn finish(self) -> ExecutionOutcome {
        let Self {
            declared,
            mut accounts,
            block_validity_window,
            timestamp_validity_window,
            mode,
            events,
            casts,
            ..
        } = self;

        let result = match mode {
            ModeState::Derive { groups, .. } => ExecutionResult::Derived { assumed: groups },
            ModeState::Record { boundary, .. } => ExecutionResult::Recorded {
                private_accounts: accounts
                    .into_iter()
                    .filter_map(|(account_id, AccountEntry { data, visibility })| {
                        matches!(visibility, Visibility::Private(_)).then_some((account_id, data))
                    })
                    .collect(),
                boundary,
            },
            ModeState::Live | ModeState::Check { .. } => {
                let mut public = Vec::new();
                for actor in declared.public_actors {
                    let Some(AccountEntry {
                        mut data,
                        visibility: Visibility::Public { observed, .. },
                    }) = accounts.remove(&actor.account_id)
                    else {
                        continue;
                    };
                    for program in observed {
                        data.shards.entry(program).or_default();
                    }
                    public.push((actor.account_id, data));
                }
                ExecutionResult::Settled {
                    public,
                    events,
                    casts,
                }
            }
        };

        ExecutionOutcome {
            block_validity_window,
            timestamp_validity_window,
            result,
        }
    }
}

fn expect_op(
    schedule: &[ScheduleOp],
    cursor: &mut usize,
    op: ScheduleOp,
) -> Result<(), ExecutionError> {
    if schedule.get(*cursor) != Some(&op) {
        return Err(ExecutionError::ScheduleMismatch {
            index: *cursor,
            expected: op,
        });
    }
    *cursor = cursor
        .checked_add(1)
        .expect("bounded by the schedule length");
    Ok(())
}

fn public_delivery(delivery: &Delivery) -> PublicDelivery {
    PublicDelivery {
        envelope: delivery.envelope.clone(),
        grants: delivery.grants.iter().copied().collect(),
        pda_seeds: delivery.pda_seeds.clone(),
    }
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
