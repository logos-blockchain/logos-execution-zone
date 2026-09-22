use std::collections::{BTreeSet, HashMap, HashSet, VecDeque, hash_map::Entry};

use borsh::{BorshDeserialize, BorshSerialize};

use crate::{
    NullifierPublicKey, NullifierSecretKey, NullifierWitness, PrivateWitness, PublicAction,
    WitnessKind,
    account::{AccountData, AccountId, ProgramShardSelector, ShardData},
    program::{
        AccountMeta, BlockValidityWindow, ChainedCall, ExecutionValidationError, InstructionData,
        InvalidWindow, MAX_NUMBER_CHAINED_CALLS, PdaSeed, ProgramEvent, ProgramInput,
        ProgramOutput, ResolveInput, ResolveOutput, ShardEffect, TimestampValidityWindow,
        validate_execution, validate_resolution,
    },
};

#[derive(Clone, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
pub struct RootCall {
    pub program_account_id: AccountId,
    pub shard_selectors: Vec<ProgramShardSelector>,
    pub instruction_data: InstructionData,
    pub authorized_accounts: Vec<AccountId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicEffects {
    Resolve,
    Defer,
}

#[derive(Debug, Clone, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub enum PublicResolution {
    Apply {
        program_account_id: AccountId,
        shard_program_account_id: AccountId,
        data: InstructionData,
    },
}

pub trait PublicSource {
    type Error: From<ExecutionError>;

    fn shard(
        &mut self,
        account_id: AccountId,
        program_account_id: AccountId,
    ) -> Result<ShardData, Self::Error>;
}

/// A traversal with no public state to read.
///
/// Only an authenticated private account can raise a local obligation under one, and its shard
/// comes from its own witness, so a request here means the traversal went somewhere it must not.
/// That is an error, never empty data.
pub struct NoPublicFacts;

impl PublicSource for NoPublicFacts {
    type Error = ExecutionError;

    fn shard(
        &mut self,
        account_id: AccountId,
        program_account_id: AccountId,
    ) -> Result<ShardData, ExecutionError> {
        Err(ExecutionError::MissingPublicFact {
            shard_selector: ProgramShardSelector::new(account_id, program_account_id),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    #[error("No public fact was supplied for {shard_selector:?}")]
    MissingPublicFact {
        shard_selector: ProgramShardSelector,
    },

    #[error("Two witnesses derive the same private account {account_id}")]
    DuplicateWitness { account_id: AccountId },

    #[error("Private witness {account_id} is not an input of the root call")]
    WitnessNotInRoot { account_id: AccountId },

    #[error("Authorization secret key does not derive the nullifier key of {account_id}")]
    InvalidAuthorizationKey { account_id: AccountId },

    #[error(
        "Two different accounts resolved under the same (program, seed) in one transaction: existing {existing}, new {account_id}"
    )]
    FamilyBindingConflict {
        existing: AccountId,
        account_id: AccountId,
    },

    #[error("Chain of calls is too long")]
    MaxChainedCallsExceeded,

    #[error("Chained call named account {account_id}, which is not an input of the root call")]
    UnknownAccount { account_id: AccountId },

    #[error("Program {program_account_id} returned {actual} account rows for {expected} inputs")]
    RowCountMismatch {
        program_account_id: AccountId,
        expected: usize,
        actual: usize,
    },

    #[error(
        "Program {program_account_id} echoed a handle it was not given: expected {expected:?}, actual {actual:?}"
    )]
    InputEchoMismatch {
        program_account_id: AccountId,
        expected: Box<AccountMeta>,
        actual: Box<AccountMeta>,
    },

    #[error("Program {program_account_id} left {remaining} emitted effects unresolved")]
    UnresolvedEffects {
        program_account_id: AccountId,
        remaining: usize,
    },

    #[error("Program account ID mismatch: expected {expected}, actual {actual}")]
    MismatchedProgramId {
        expected: AccountId,
        actual: AccountId,
    },

    #[error("Caller program account ID mismatch: expected {expected:?}, actual {actual:?}")]
    MismatchedCallerProgramId {
        expected: Option<AccountId>,
        actual: Option<AccountId>,
    },

    #[error("Program {program_account_id} did not echo the instruction it was handed")]
    MismatchedInstruction { program_account_id: AccountId },

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

    #[error("Execution finished with calls still pending")]
    IncompleteExecution,

    #[error("A call failed, so the execution cannot continue")]
    Aborted,
}

enum Origin {
    Public {
        is_authorized: bool,
        observed: BTreeSet<AccountId>,
        deferred: Vec<PublicResolution>,
    },
    Private(usize),
}

struct AccountEntry {
    data: AccountData,
    origin: Origin,
}

struct PendingCall {
    call: ChainedCall,
    caller_account_id: Option<AccountId>,
    grants: HashSet<AccountId>,
}

struct BoundPlan {
    effects: VecDeque<ShardEffect>,
    obligation: Option<ResolveInput>,
    chained_calls: Vec<ChainedCall>,
    events: Vec<ProgramEvent>,
}

struct ActiveCall {
    input: ProgramInput<InstructionData>,
    grants: HashSet<AccountId>,
    plan: Option<BoundPlan>,
}

/// What the traversal made of the transaction's public accounts, fixed by the
/// [`PublicEffects`] mode chosen at [`ExecutionState::initialize`].
pub enum PublicOutcome {
    /// [`PublicEffects::Resolve`]: each public account's touched shards after resolution, in
    /// first-observation order. A shard observed and then cleared is present and empty.
    Resolved(Vec<(AccountId, AccountData)>),
    /// [`PublicEffects::Defer`]: the journal rows settlement must fold, in first-observation
    /// order, each carrying its effects in traversal order.
    Deferred(Vec<PublicAction>),
}

pub struct FinalState {
    pub block_validity_window: BlockValidityWindow,
    pub timestamp_validity_window: TimestampValidityWindow,
    pub public: PublicOutcome,
    pub private_accounts: HashMap<AccountId, AccountData>,
}

pub struct ExecutionState<'witnesses> {
    witnesses: &'witnesses [PrivateWitness],
    public_effects: PublicEffects,
    root_order: Vec<AccountId>,
    accounts: HashMap<AccountId, AccountEntry>,
    pda_family_binding: HashMap<(AccountId, PdaSeed), AccountId>,
    pending: VecDeque<PendingCall>,
    active: Option<ActiveCall>,
    prepared_calls: usize,
    failed: bool,
    block_validity_window: BlockValidityWindow,
    timestamp_validity_window: TimestampValidityWindow,
}

impl<'witnesses> ExecutionState<'witnesses> {
    pub fn initialize(
        root: RootCall,
        witnesses: &'witnesses [PrivateWitness],
        public_effects: PublicEffects,
    ) -> Result<Self, ExecutionError> {
        let RootCall {
            program_account_id,
            shard_selectors,
            instruction_data,
            authorized_accounts,
        } = root;

        let mut witness_index = HashMap::with_capacity(witnesses.len());
        let mut witness_ids = Vec::with_capacity(witnesses.len());
        let mut pda_family_binding = HashMap::new();
        for (index, witness) in witnesses.iter().enumerate() {
            let account_id = witness.account_id();
            if witness_index.insert(account_id, index).is_some() {
                return Err(ExecutionError::DuplicateWitness { account_id });
            }
            witness_ids.push(account_id);
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

        let mut accounts = HashMap::new();
        let mut root_order = Vec::new();
        for shard_selector in &shard_selectors {
            let account_id = shard_selector.account_id;
            let Entry::Vacant(vacant) = accounts.entry(account_id) else {
                continue;
            };
            let entry = if let Some(&index) = witness_index.get(&account_id) {
                AccountEntry {
                    data: witnesses[index].account.data.clone(),
                    origin: Origin::Private(index),
                }
            } else {
                AccountEntry {
                    data: AccountData::default(),
                    origin: Origin::Public {
                        is_authorized: authorized_accounts.contains(&account_id),
                        observed: BTreeSet::new(),
                        deferred: Vec::new(),
                    },
                }
            };
            vacant.insert(entry);
            root_order.push(account_id);
        }
        if let Some(account_id) = witness_ids
            .into_iter()
            .find(|account_id| !accounts.contains_key(account_id))
        {
            return Err(ExecutionError::WitnessNotInRoot { account_id });
        }

        Ok(Self {
            witnesses,
            public_effects,
            root_order,
            accounts,
            pda_family_binding,
            pending: VecDeque::from([PendingCall {
                call: ChainedCall {
                    program_account_id,
                    shard_selectors,
                    instruction_data,
                    pda_seeds: Vec::new(),
                },
                caller_account_id: None,
                grants: HashSet::new(),
            }]),
            active: None,
            prepared_calls: 0,
            failed: false,
            block_validity_window: BlockValidityWindow::new_unbounded(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
        })
    }

    pub fn prepare_next_call(
        &mut self,
    ) -> Result<Option<&ProgramInput<InstructionData>>, ExecutionError> {
        assert!(self.active.is_none(), "the prepared call was not completed");
        if self.failed {
            return Err(ExecutionError::Aborted);
        }
        self.failed = true;
        let Some(PendingCall {
            call,
            caller_account_id,
            mut grants,
        }) = self.pending.pop_front()
        else {
            self.failed = false;
            return Ok(None);
        };
        if self.prepared_calls > MAX_NUMBER_CHAINED_CALLS {
            return Err(ExecutionError::MaxChainedCallsExceeded);
        }
        self.prepared_calls = self
            .prepared_calls
            .checked_add(1)
            .expect("bounded by MAX_NUMBER_CHAINED_CALLS");

        let ChainedCall {
            program_account_id,
            shard_selectors,
            instruction_data,
            pda_seeds,
        } = call;
        let mut accounts = Vec::with_capacity(shard_selectors.len());
        for shard_selector in shard_selectors {
            let account_id = shard_selector.account_id;
            let is_authorized =
                self.authorize(caller_account_id, &pda_seeds, &mut grants, account_id)?;
            accounts.push(AccountMeta::new(
                account_id,
                is_authorized,
                shard_selector.program_account_id,
            ));
        }

        let active = self.active.insert(ActiveCall {
            input: ProgramInput {
                self_account_id: program_account_id,
                caller_account_id,
                accounts,
                instruction: instruction_data,
            },
            grants,
            plan: None,
        });
        self.failed = false;
        Ok(Some(&active.input))
    }

    fn authorize(
        &mut self,
        caller_account_id: Option<AccountId>,
        pda_seeds: &[PdaSeed],
        grants: &mut HashSet<AccountId>,
        account_id: AccountId,
    ) -> Result<bool, ExecutionError> {
        let entry = self
            .accounts
            .get(&account_id)
            .ok_or(ExecutionError::UnknownAccount { account_id })?;
        let (credential, granted) = match entry.origin {
            Origin::Public { is_authorized, .. } => (
                is_authorized,
                public_seed_grant(caller_account_id, pda_seeds, account_id),
            ),
            Origin::Private(index) => {
                let witness = &self.witnesses[index];
                (
                    matches!(witness.kind, WitnessKind::Regular { ask: Some(_) }),
                    private_seed_grant(caller_account_id, pda_seeds, witness),
                )
            }
        };
        if let Some((program, seed)) = granted {
            bind_family(&mut self.pda_family_binding, program, seed, account_id)?;
            grants.insert(account_id);
        }
        Ok(credential || grants.contains(&account_id))
    }

    pub fn bind_plan(&mut self, output: ProgramOutput) -> Result<(), ExecutionError> {
        if self.failed {
            return Err(ExecutionError::Aborted);
        }
        self.failed = true;
        let active = self.active.as_ref().expect("no call is prepared");
        assert!(active.plan.is_none(), "the plan was already bound");
        let program_account_id = active.input.self_account_id;
        let ProgramOutput {
            self_account_id,
            caller_account_id,
            instruction_data,
            accounts,
            effects,
            chained_calls,
            block_validity_window,
            timestamp_validity_window,
            events,
        } = output;

        if self_account_id != program_account_id {
            return Err(ExecutionError::MismatchedProgramId {
                expected: program_account_id,
                actual: self_account_id,
            });
        }
        if caller_account_id != active.input.caller_account_id {
            return Err(ExecutionError::MismatchedCallerProgramId {
                expected: active.input.caller_account_id,
                actual: caller_account_id,
            });
        }
        if instruction_data != active.input.instruction {
            return Err(ExecutionError::MismatchedInstruction { program_account_id });
        }
        if accounts.len() != active.input.accounts.len() {
            return Err(ExecutionError::RowCountMismatch {
                program_account_id,
                expected: active.input.accounts.len(),
                actual: accounts.len(),
            });
        }
        for (actual, expected) in accounts.into_iter().zip(&active.input.accounts) {
            if actual != *expected {
                return Err(ExecutionError::InputEchoMismatch {
                    program_account_id,
                    expected: Box::new(expected.clone()),
                    actual: Box::new(actual),
                });
            }
        }

        validate_execution(&active.input.accounts, &effects).map_err(|source| {
            ExecutionError::ExecutionValidation {
                program_account_id,
                source,
            }
        })?;
        let block = self
            .block_validity_window
            .intersect(block_validity_window)
            .map_err(|InvalidWindow| ExecutionError::EmptyBlockWindowIntersection)?;
        let timestamp = self
            .timestamp_validity_window
            .intersect(timestamp_validity_window)
            .map_err(|InvalidWindow| ExecutionError::EmptyTimestampWindowIntersection)?;

        self.block_validity_window = block;
        self.timestamp_validity_window = timestamp;
        self.active.as_mut().expect("no call is prepared").plan = Some(BoundPlan {
            effects: effects.into(),
            obligation: None,
            chained_calls,
            events,
        });
        self.failed = false;
        Ok(())
    }

    /// The next effect this call must resolve here. Under [`PublicEffects::Defer`] a public
    /// target is recorded for settlement and skipped rather than resolved, so what is returned is
    /// always an obligation of this execution.
    pub fn next_obligation<S: PublicSource>(
        &mut self,
        source: &mut S,
    ) -> Result<Option<&ResolveInput>, S::Error> {
        if self.failed {
            return Err(ExecutionError::Aborted.into());
        }
        self.failed = true;
        let deferring = self.public_effects == PublicEffects::Defer;
        let active = self.active.as_mut().expect("no call is prepared");
        let program_account_id = active.input.self_account_id;
        let plan = active.plan.as_mut().expect("the plan was not bound");
        assert!(
            plan.obligation.is_none(),
            "the previous obligation was not resolved"
        );
        let input = loop {
            let Some(ShardEffect { selector, data }) = plan.effects.pop_front() else {
                self.failed = false;
                return Ok(None);
            };

            let entry = self
                .accounts
                .get_mut(&selector.account_id)
                .expect("every effect selects an input of the call");
            if deferring && let Origin::Public { deferred, .. } = &mut entry.origin {
                deferred.push(PublicResolution::Apply {
                    program_account_id,
                    shard_program_account_id: selector.program_account_id,
                    data,
                });
                continue;
            }
            if let Origin::Public { observed, .. } = &mut entry.origin
                && !observed.contains(&selector.program_account_id)
            {
                let shard = source.shard(selector.account_id, selector.program_account_id)?;
                observed.insert(selector.program_account_id);
                entry.data.set_shard(selector.program_account_id, shard);
            }
            break ResolveInput {
                self_account_id: program_account_id,
                selector,
                pre_data: entry.data.shard(selector.program_account_id).clone(),
                effect_data: data,
            };
        };

        self.failed = false;
        let bound = self
            .active
            .as_mut()
            .expect("no call is prepared")
            .plan
            .as_mut()
            .expect("the plan was not bound");
        Ok(Some(bound.obligation.insert(input)))
    }

    pub fn accept_resolution(&mut self, output: &ResolveOutput) -> Result<(), ExecutionError> {
        if self.failed {
            return Err(ExecutionError::Aborted);
        }
        self.failed = true;
        let active = self.active.as_mut().expect("no call is prepared");
        let program_account_id = active.input.self_account_id;
        let expected = active
            .plan
            .as_mut()
            .expect("the plan was not bound")
            .obligation
            .take()
            .expect("no obligation is pending");

        validate_resolution(&expected, output).map_err(|source| {
            ExecutionError::ExecutionValidation {
                program_account_id,
                source,
            }
        })?;
        self.accounts
            .get_mut(&output.input.selector.account_id)
            .expect("every effect selects an input of the call")
            .data
            .apply_resolution(output);

        self.failed = false;
        Ok(())
    }

    pub fn complete_call(&mut self) -> Result<Vec<ProgramEvent>, ExecutionError> {
        if self.failed {
            return Err(ExecutionError::Aborted);
        }
        self.failed = true;
        let ActiveCall {
            input,
            grants,
            plan,
        } = self.active.take().expect("no call is prepared");
        let program_account_id = input.self_account_id;
        let BoundPlan {
            effects,
            obligation,
            chained_calls,
            events,
        } = plan.expect("the plan was not bound");

        if !effects.is_empty() || obligation.is_some() {
            return Err(ExecutionError::UnresolvedEffects {
                program_account_id,
                remaining: effects
                    .len()
                    .saturating_add(usize::from(obligation.is_some())),
            });
        }
        for call in chained_calls.into_iter().rev() {
            self.pending.push_front(PendingCall {
                call,
                caller_account_id: Some(program_account_id),
                grants: grants.clone(),
            });
        }

        self.failed = false;
        Ok(events)
    }

    #[must_use]
    pub const fn prepared_call(&self) -> &ProgramInput<InstructionData> {
        &self.active.as_ref().expect("no call is prepared").input
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
    pub fn pending_shard(
        &self,
        account_id: AccountId,
        program_account_id: AccountId,
    ) -> Option<&ShardData> {
        let entry = self.accounts.get(&account_id)?;
        match &entry.origin {
            Origin::Public { observed, .. } if !observed.contains(&program_account_id) => None,
            Origin::Public { .. } | Origin::Private(_) => {
                Some(entry.data.shard(program_account_id))
            }
        }
    }

    pub fn finish(self) -> Result<FinalState, ExecutionError> {
        if self.failed {
            return Err(ExecutionError::Aborted);
        }
        if self.active.is_some() || !self.pending.is_empty() {
            return Err(ExecutionError::IncompleteExecution);
        }
        let Self {
            public_effects,
            root_order,
            mut accounts,
            block_validity_window,
            timestamp_validity_window,
            ..
        } = self;

        let mut resolved = Vec::new();
        let mut deferred_rows = Vec::new();
        let mut private_accounts = HashMap::new();
        for account_id in root_order {
            let AccountEntry { data, origin } = accounts
                .remove(&account_id)
                .expect("every root account has an entry");
            match origin {
                Origin::Public {
                    is_authorized,
                    observed,
                    deferred,
                } => match public_effects {
                    PublicEffects::Defer => deferred_rows.push(PublicAction {
                        account_id,
                        is_authorized,
                        resolutions: deferred,
                    }),
                    PublicEffects::Resolve => {
                        let mut post = data;
                        for program in observed {
                            post.shards.entry(program).or_default();
                        }
                        resolved.push((account_id, post));
                    }
                },
                Origin::Private(_) => {
                    private_accounts.insert(account_id, data);
                }
            }
        }

        Ok(FinalState {
            block_validity_window,
            timestamp_validity_window,
            public: match public_effects {
                PublicEffects::Defer => PublicOutcome::Deferred(deferred_rows),
                PublicEffects::Resolve => PublicOutcome::Resolved(resolved),
            },
            private_accounts,
        })
    }
}

fn public_seed_grant(
    caller_account_id: Option<AccountId>,
    pda_seeds: &[PdaSeed],
    account_id: AccountId,
) -> Option<(AccountId, PdaSeed)> {
    let caller = caller_account_id?;
    pda_seeds.iter().find_map(|seed| {
        (AccountId::for_public_pda(&caller, seed) == account_id).then_some((caller, *seed))
    })
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
