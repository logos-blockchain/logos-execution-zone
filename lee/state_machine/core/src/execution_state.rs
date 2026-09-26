use std::collections::{BTreeSet, HashMap, HashSet, VecDeque, hash_map::Entry};

use borsh::{BorshDeserialize, BorshSerialize};

use crate::{
    NullifierPublicKey, NullifierSecretKey, NullifierWitness, PrivateWitness, PublicAction,
    WitnessKind,
    account::{AccountData, AccountId, ProgramShardSelector, ShardData},
    program::{
        AccountMeta, ApplyInput, ApplyOutput, BlockValidityWindow, ChainedCall, EffectData,
        ExecutionValidationError, InstructionData, InvalidWindow, MAX_NUMBER_CHAINED_CALLS,
        PdaSeed, PlanInput, PlanOutput, ProgramEvent, ShardEffect, TimestampValidityWindow,
        validate_apply_output, validate_plan,
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

pub trait PublicEffectMode {
    type Account;
    const DEFER: bool;

    fn select(applied: (AccountId, AccountData), journal: PublicAction) -> Self::Account;
}

/// Applies public effects and returns touched shards in root account order.
/// Cleared shards remain present as empty values.
pub enum ApplyPublicEffects {}

impl PublicEffectMode for ApplyPublicEffects {
    type Account = (AccountId, AccountData);

    const DEFER: bool = false;

    fn select(applied: (AccountId, AccountData), _journal: PublicAction) -> Self::Account {
        applied
    }
}

/// Collects public effects for settlement, grouped in root account order.
/// Each account's effects remain in execution order.
pub enum DeferPublicEffects {}

impl PublicEffectMode for DeferPublicEffects {
    type Account = PublicAction;

    const DEFER: bool = true;

    fn select(_applied: (AccountId, AccountData), journal: PublicAction) -> Self::Account {
        journal
    }
}

#[derive(Debug, Clone, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct DeferredPublicEffect {
    pub program_account_id: AccountId,
    pub shard_program_account_id: AccountId,
    pub data: EffectData,
}

/// How a traversal runs the programs it reaches. A call's plan and the apply of each of its effects
/// go through the same [`Backend::Call`], so each effect is applied by the code that planned it.
pub trait Backend {
    type PublicEffects: PublicEffectMode;
    type Call;
    type Error: From<ExecutionError>;

    fn plan(
        &mut self,
        input: &PlanInput,
        execution: &ExecutionState<'_>,
    ) -> Result<(PlanOutput, Self::Call), Self::Error>;

    fn apply(
        &mut self,
        call: &mut Self::Call,
        input: &ApplyInput,
    ) -> Result<ApplyOutput, Self::Error>;

    fn complete(
        &mut self,
        call: Self::Call,
        events: Vec<ProgramEvent>,
        execution: &ExecutionState<'_>,
    ) -> Result<(), Self::Error>;

    /// Returns [`ExecutionError::PublicShardUnavailable`] by default.
    /// Backends with public state override this method.
    fn public_shard(
        &mut self,
        shard_selector: ProgramShardSelector,
    ) -> Result<ShardData, Self::Error> {
        Err(ExecutionError::PublicShardUnavailable { shard_selector }.into())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    #[error("No public shard was supplied for {shard_selector:?}")]
    PublicShardUnavailable {
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
}

enum Origin {
    Public {
        is_authorized: bool,
        observed: BTreeSet<AccountId>,
        deferred: Vec<DeferredPublicEffect>,
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

pub struct ExecutionOutcome<P: PublicEffectMode> {
    pub block_validity_window: BlockValidityWindow,
    pub timestamp_validity_window: TimestampValidityWindow,
    pub public: Vec<P::Account>,
    pub private_accounts: HashMap<AccountId, AccountData>,
}

pub struct ExecutionState<'witnesses> {
    witnesses: &'witnesses [PrivateWitness],
    root_order: Vec<AccountId>,
    accounts: HashMap<AccountId, AccountEntry>,
    pda_family_binding: HashMap<(AccountId, PdaSeed), AccountId>,
    pending: VecDeque<PendingCall>,
    block_validity_window: BlockValidityWindow,
    timestamp_validity_window: TimestampValidityWindow,
}

impl<'witnesses> ExecutionState<'witnesses> {
    pub fn initialize(
        root: RootCall,
        witnesses: &'witnesses [PrivateWitness],
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
                    data: match &witnesses[index].nullifier {
                        NullifierWitness::Init { .. } => AccountData::default(),
                        NullifierWitness::Update { account, .. } => account.data.clone(),
                    },
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
            block_validity_window: BlockValidityWindow::new_unbounded(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
        })
    }

    fn prepare_call(
        &mut self,
        PendingCall {
            call,
            caller_account_id,
            mut grants,
        }: PendingCall,
    ) -> Result<(PlanInput, HashSet<AccountId>), ExecutionError> {
        let ChainedCall {
            program_account_id,
            shard_selectors,
            instruction_data,
            pda_seeds,
        } = call;
        let authorized_pdas = compute_public_authorized_pdas(caller_account_id, &pda_seeds);
        let mut accounts = Vec::with_capacity(shard_selectors.len());
        for shard_selector in shard_selectors {
            let account_id = shard_selector.account_id;
            let is_authorized = self.authorize(
                caller_account_id,
                &pda_seeds,
                &authorized_pdas,
                &mut grants,
                account_id,
            )?;
            accounts.push(AccountMeta::new(
                account_id,
                is_authorized,
                shard_selector.program_account_id,
            ));
        }

        Ok((
            PlanInput {
                self_account_id: program_account_id,
                caller_account_id,
                accounts,
                instruction_data,
            },
            grants,
        ))
    }

    fn authorize(
        &mut self,
        caller_account_id: Option<AccountId>,
        pda_seeds: &[PdaSeed],
        authorized_pdas: &HashMap<AccountId, PdaSeed>,
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
                public_seed_grant(caller_account_id, authorized_pdas, account_id),
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

    fn bind_plan(&mut self, input: &PlanInput, plan: &PlanOutput) -> Result<(), ExecutionError> {
        validate_plan(input, plan).map_err(|source| ExecutionError::ExecutionValidation {
            program_account_id: input.self_account_id,
            source,
        })?;
        let block = self
            .block_validity_window
            .intersect(plan.block_validity_window)
            .map_err(|InvalidWindow| ExecutionError::EmptyBlockWindowIntersection)?;
        let timestamp = self
            .timestamp_validity_window
            .intersect(plan.timestamp_validity_window)
            .map_err(|InvalidWindow| ExecutionError::EmptyTimestampWindowIntersection)?;

        self.block_validity_window = block;
        self.timestamp_validity_window = timestamp;
        Ok(())
    }

    fn apply_input<B: Backend>(
        &mut self,
        program_account_id: AccountId,
        ShardEffect { selector, data }: ShardEffect,
        backend: &mut B,
    ) -> Result<ApplyInput, B::Error> {
        let entry = self
            .accounts
            .get_mut(&selector.account_id)
            .expect("every effect selects an input of the call");
        if let Origin::Public { observed, .. } = &mut entry.origin
            && !observed.contains(&selector.program_account_id)
        {
            let shard = backend.public_shard(selector)?;
            observed.insert(selector.program_account_id);
            entry.data.set_shard(selector.program_account_id, shard);
        }
        Ok(ApplyInput {
            self_account_id: program_account_id,
            selector,
            pre_data: entry.data.shard(selector.program_account_id).clone(),
            effect_data: data,
        })
    }

    fn accept_apply_output(
        &mut self,
        input: &ApplyInput,
        output: &ApplyOutput,
    ) -> Result<(), ExecutionError> {
        validate_apply_output(input, output).map_err(|source| {
            ExecutionError::ExecutionValidation {
                program_account_id: input.self_account_id,
                source,
            }
        })?;
        self.accounts
            .get_mut(&output.input.selector.account_id)
            .expect("every effect selects an input of the call")
            .data
            .apply_output(output);
        Ok(())
    }

    pub fn run<B: Backend>(
        mut self,
        backend: &mut B,
    ) -> Result<ExecutionOutcome<B::PublicEffects>, B::Error> {
        let mut prepared_calls = 0;
        while let Some(pending) = self.pending.pop_front() {
            if prepared_calls > MAX_NUMBER_CHAINED_CALLS {
                return Err(ExecutionError::MaxChainedCallsExceeded.into());
            }
            prepared_calls = prepared_calls
                .checked_add(1)
                .expect("bounded by MAX_NUMBER_CHAINED_CALLS");

            let (input, grants) = self.prepare_call(pending)?;
            let (plan, mut call) = backend.plan(&input, &self)?;
            self.bind_plan(&input, &plan)?;
            let PlanOutput {
                effects,
                chained_calls,
                events,
                ..
            } = plan;
            for effect in effects {
                if B::PublicEffects::DEFER
                    && let Origin::Public { deferred, .. } = &mut self
                        .accounts
                        .get_mut(&effect.selector.account_id)
                        .expect("every effect selects an input of the call")
                        .origin
                {
                    deferred.push(DeferredPublicEffect {
                        program_account_id: input.self_account_id,
                        shard_program_account_id: effect.selector.program_account_id,
                        data: effect.data,
                    });
                    continue;
                }
                let apply_input = self.apply_input(input.self_account_id, effect, backend)?;
                let output = backend.apply(&mut call, &apply_input)?;
                self.accept_apply_output(&apply_input, &output)?;
            }
            for chained_call in chained_calls.into_iter().rev() {
                self.pending.push_front(PendingCall {
                    call: chained_call,
                    caller_account_id: Some(input.self_account_id),
                    grants: grants.clone(),
                });
            }
            backend.complete(call, events, &self)?;
        }
        Ok(self.finish())
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

    fn finish<P: PublicEffectMode>(self) -> ExecutionOutcome<P> {
        let Self {
            root_order,
            mut accounts,
            block_validity_window,
            timestamp_validity_window,
            ..
        } = self;

        let mut public = Vec::new();
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
                } => {
                    let mut post = data;
                    for program in observed {
                        post.shards.entry(program).or_default();
                    }
                    public.push(P::select(
                        (account_id, post),
                        PublicAction {
                            account_id,
                            is_authorized,
                            effects: deferred,
                        },
                    ));
                }
                Origin::Private(_) => {
                    private_accounts.insert(account_id, data);
                }
            }
        }

        ExecutionOutcome {
            block_validity_window,
            timestamp_validity_window,
            public,
            private_accounts,
        }
    }
}

fn compute_public_authorized_pdas(
    caller_account_id: Option<AccountId>,
    pda_seeds: &[PdaSeed],
) -> HashMap<AccountId, PdaSeed> {
    let Some(caller) = caller_account_id else {
        return HashMap::new();
    };
    pda_seeds
        .iter()
        .map(|seed| (AccountId::for_public_pda(&caller, seed), *seed))
        .collect()
}

fn public_seed_grant(
    caller_account_id: Option<AccountId>,
    authorized_pdas: &HashMap<AccountId, PdaSeed>,
    account_id: AccountId,
) -> Option<(AccountId, PdaSeed)> {
    let caller = caller_account_id?;
    authorized_pdas.get(&account_id).map(|seed| (caller, *seed))
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
