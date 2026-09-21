use std::collections::{BTreeMap, HashMap, HashSet, VecDeque, hash_map::Entry};

use borsh::{BorshDeserialize, BorshSerialize};

use crate::{
    NullifierPublicKey, NullifierSecretKey, NullifierWitness, PrivateWitness, PublicAction,
    WitnessKind,
    account::{AccountData, AccountId, ProgramShardSelector, ShardData},
    program::{
        AccountInput, BlockValidityWindow, CallKind, ChainedCall, ExecutionValidationError,
        InstructionData, InvalidWindow, MAX_NUMBER_CHAINED_CALLS, PdaSeed, ProgramEvent,
        ProgramInput, ProgramOutput, ShardStateDiff, TimestampValidityWindow, validate_execution,
    },
};

#[derive(Clone, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
pub struct RootCall {
    pub program_account_id: AccountId,
    pub shard_selectors: Vec<ProgramShardSelector>,
    pub instruction_data: InstructionData,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
pub struct AccountChange {
    pub data: Option<ShardData>,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
pub struct CallEffects {
    pub account_changes: Vec<AccountChange>,
    pub chained_calls: Vec<ChainedCall>,
    pub block_validity_window: BlockValidityWindow,
    pub timestamp_validity_window: TimestampValidityWindow,
    pub events: Vec<ProgramEvent>,
}

pub type PublicFacts = BTreeMap<AccountId, (bool, AccountData)>;

pub trait PublicSource {
    type Error: From<ExecutionError>;

    fn account(&mut self, account_id: AccountId) -> Result<bool, Self::Error>;

    fn shard(
        &mut self,
        account_id: AccountId,
        program_account_id: AccountId,
    ) -> Result<ShardData, Self::Error>;
}

impl PublicSource for PublicFacts {
    type Error = ExecutionError;

    fn account(&mut self, account_id: AccountId) -> Result<bool, ExecutionError> {
        self.get(&account_id)
            .map(|(is_authorized, _)| *is_authorized)
            .ok_or(ExecutionError::MissingPublicFact {
                shard_selector: ProgramShardSelector::balance(account_id),
            })
    }

    fn shard(
        &mut self,
        account_id: AccountId,
        program_account_id: AccountId,
    ) -> Result<ShardData, ExecutionError> {
        self.get(&account_id)
            .and_then(|(_, data)| data.shards.get(&program_account_id))
            .cloned()
            .ok_or_else(|| ExecutionError::MissingPublicFact {
                shard_selector: ProgramShardSelector::new(account_id, program_account_id),
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstructionEcho {
    Checked,
    Unchecked,
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
        "Program {program_account_id} returned a pre-state it was not handed: expected {expected:?}, actual {actual:?}"
    )]
    PreStateMismatch {
        program_account_id: AccountId,
        expected: Box<AccountInput>,
        actual: Box<AccountInput>,
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

    #[error("Chained call to {program_account_id} did not execute")]
    ChainedCallDidNotExecute { program_account_id: AccountId },

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
        initial: AccountData,
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

struct ActiveCall {
    input: ProgramInput<InstructionData>,
    grants: HashSet<AccountId>,
}

pub struct FinalState {
    pub block_validity_window: BlockValidityWindow,
    pub timestamp_validity_window: TimestampValidityWindow,
    pub public_actions: Vec<PublicAction>,
    pub private_accounts: HashMap<AccountId, AccountData>,
}

pub struct ExecutionState<'witnesses> {
    witnesses: &'witnesses [PrivateWitness],
    root_call_kind: CallKind,
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
    pub fn initialize<S: PublicSource>(
        root: RootCall,
        root_call_kind: CallKind,
        witnesses: &'witnesses [PrivateWitness],
        source: &mut S,
    ) -> Result<Self, S::Error> {
        let RootCall {
            program_account_id,
            shard_selectors,
            instruction_data,
        } = root;

        let mut witness_index = HashMap::with_capacity(witnesses.len());
        let mut witness_ids = Vec::with_capacity(witnesses.len());
        let mut pda_family_binding = HashMap::new();
        for (index, witness) in witnesses.iter().enumerate() {
            let account_id = witness.account_id();
            if witness_index.insert(account_id, index).is_some() {
                return Err(ExecutionError::DuplicateWitness { account_id }.into());
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
                        return Err(ExecutionError::InvalidAuthorizationKey { account_id }.into());
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
                let is_authorized = source.account(account_id)?;
                let initial = AccountData::default();
                AccountEntry {
                    data: initial.clone(),
                    origin: Origin::Public {
                        is_authorized,
                        initial,
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
            return Err(ExecutionError::WitnessNotInRoot { account_id }.into());
        }

        Ok(Self {
            witnesses,
            root_call_kind,
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

    pub fn prepare_next_call<S: PublicSource>(
        &mut self,
        source: &mut S,
    ) -> Result<Option<&ProgramInput<InstructionData>>, S::Error> {
        assert!(self.active.is_none(), "the prepared call was not completed");
        if self.failed {
            return Err(ExecutionError::Aborted.into());
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
            return Err(ExecutionError::MaxChainedCallsExceeded.into());
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
        let mut pre_states = Vec::with_capacity(shard_selectors.len());
        for shard_selector in shard_selectors {
            let account_id = shard_selector.account_id;
            let is_authorized =
                self.authorize(caller_account_id, &pda_seeds, &mut grants, account_id)?;
            self.observe_shard(account_id, shard_selector.program_account_id, source)?;
            pre_states.push(AccountInput::at(
                shard_selector,
                is_authorized,
                &self.accounts[&account_id].data,
            ));
        }

        let active = self.active.insert(ActiveCall {
            input: ProgramInput {
                self_account_id: program_account_id,
                caller_account_id,
                pre_states,
                instruction: instruction_data,
            },
            grants,
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

    fn observe_shard<S: PublicSource>(
        &mut self,
        account_id: AccountId,
        program_account_id: AccountId,
        source: &mut S,
    ) -> Result<(), S::Error> {
        let entry = self
            .accounts
            .get_mut(&account_id)
            .expect("authorized against the same table just before");
        if let Origin::Public { initial, .. } = &mut entry.origin
            && !initial.shards.contains_key(&program_account_id)
        {
            let data = source.shard(account_id, program_account_id)?;
            entry.data.set_shard(program_account_id, data.clone());
            initial.shards.insert(program_account_id, data);
        }
        Ok(())
    }

    pub fn bind_output(
        &mut self,
        output: ProgramOutput,
        instruction_echo: InstructionEcho,
    ) -> Result<CallEffects, ExecutionError> {
        let active = &self.active.as_ref().expect("no call is prepared").input;
        let program_account_id = active.self_account_id;
        let is_root = active.caller_account_id.is_none();
        let ProgramOutput {
            self_account_id,
            caller_account_id,
            call_kind,
            instruction_data,
            state_diffs,
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
        if caller_account_id != active.caller_account_id {
            return Err(ExecutionError::MismatchedCallerProgramId {
                expected: active.caller_account_id,
                actual: caller_account_id,
            });
        }
        if !is_root && call_kind != CallKind::Execute {
            return Err(ExecutionError::ChainedCallDidNotExecute { program_account_id });
        }
        if instruction_echo == InstructionEcho::Checked && instruction_data != active.instruction {
            return Err(ExecutionError::MismatchedInstruction { program_account_id });
        }
        if state_diffs.len() != active.pre_states.len() {
            return Err(ExecutionError::RowCountMismatch {
                program_account_id,
                expected: active.pre_states.len(),
                actual: state_diffs.len(),
            });
        }
        let mut account_changes = Vec::with_capacity(state_diffs.len());
        for (diff, input) in state_diffs.into_iter().zip(&active.pre_states) {
            let ShardStateDiff {
                pre_state,
                post_data,
            } = diff;
            if pre_state != *input {
                return Err(ExecutionError::PreStateMismatch {
                    program_account_id,
                    expected: Box::new(input.clone()),
                    actual: Box::new(pre_state),
                });
            }
            account_changes.push(AccountChange { data: post_data });
        }
        if is_root {
            self.root_call_kind = call_kind;
        }

        Ok(CallEffects {
            account_changes,
            chained_calls,
            block_validity_window,
            timestamp_validity_window,
            events,
        })
    }

    pub fn complete_call(
        &mut self,
        effects: CallEffects,
        verify: impl FnOnce(&ProgramOutput),
    ) -> Result<Vec<ProgramEvent>, ExecutionError> {
        if self.failed {
            return Err(ExecutionError::Aborted);
        }
        self.failed = true;
        let ActiveCall {
            input:
                ProgramInput {
                    self_account_id: program_account_id,
                    caller_account_id,
                    pre_states,
                    instruction: instruction_data,
                },
            grants,
        } = self.active.take().expect("no call is prepared");

        if effects.account_changes.len() != pre_states.len() {
            return Err(ExecutionError::RowCountMismatch {
                program_account_id,
                expected: pre_states.len(),
                actual: effects.account_changes.len(),
            });
        }
        let call_kind = if caller_account_id.is_none() {
            self.root_call_kind
        } else {
            CallKind::Execute
        };
        let output = ProgramOutput {
            self_account_id: program_account_id,
            caller_account_id,
            call_kind,
            instruction_data,
            state_diffs: pre_states
                .into_iter()
                .zip(effects.account_changes)
                .map(|(pre_state, change)| ShardStateDiff {
                    pre_state,
                    post_data: change.data,
                })
                .collect(),
            chained_calls: effects.chained_calls,
            block_validity_window: effects.block_validity_window,
            timestamp_validity_window: effects.timestamp_validity_window,
            events: effects.events,
        };
        verify(&output);
        let ProgramOutput {
            state_diffs,
            chained_calls,
            block_validity_window,
            timestamp_validity_window,
            events,
            ..
        } = output;

        validate_execution(&state_diffs, program_account_id).map_err(|source| {
            ExecutionError::ExecutionValidation {
                program_account_id,
                source,
            }
        })?;
        self.block_validity_window = self
            .block_validity_window
            .intersect(block_validity_window)
            .map_err(|InvalidWindow| ExecutionError::EmptyBlockWindowIntersection)?;
        self.timestamp_validity_window = self
            .timestamp_validity_window
            .intersect(timestamp_validity_window)
            .map_err(|InvalidWindow| ExecutionError::EmptyTimestampWindowIntersection)?;

        for diff in &state_diffs {
            self.accounts
                .get_mut(&diff.pre_state.account_id)
                .expect("every input row names an account of the root call")
                .data
                .apply_diff(diff);
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
    pub const fn root_call_kind(&self) -> CallKind {
        self.root_call_kind
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
            Origin::Public { initial, .. } if !initial.shards.contains_key(&program_account_id) => {
                None
            }
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
            root_order,
            mut accounts,
            block_validity_window,
            timestamp_validity_window,
            ..
        } = self;

        let mut public_actions = Vec::new();
        let mut private_accounts = HashMap::new();
        for account_id in root_order {
            let AccountEntry { data, origin } = accounts
                .remove(&account_id)
                .expect("every root account has an entry");
            match origin {
                Origin::Public {
                    is_authorized,
                    initial,
                } => {
                    let mut post = data;
                    for program in initial.shards.keys() {
                        post.shards.entry(*program).or_default();
                    }
                    public_actions.push(PublicAction {
                        account_id,
                        is_authorized,
                        pre: initial,
                        post,
                    });
                }
                Origin::Private(_) => {
                    private_accounts.insert(account_id, data);
                }
            }
        }

        Ok(FinalState {
            block_validity_window,
            timestamp_validity_window,
            public_actions,
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
