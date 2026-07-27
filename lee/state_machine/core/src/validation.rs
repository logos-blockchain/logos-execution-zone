use std::collections::{HashMap, HashSet, VecDeque};

use crate::{
    BlockId, Timestamp,
    account::{Account, AccountId, AccountWithMetadata},
    error::InvalidProgramBehaviorError,
    program::{
        BlockValidityWindow, ChainedCall, Claim, DEFAULT_PROGRAM_ID, MAX_NUMBER_CHAINED_CALLS,
        PdaSeed, ProgramId, ProgramOutput, TimestampValidityWindow, ValidityWindow,
        validate_execution,
    },
};

#[derive(Debug)]
pub enum ValidationError {
    ProgramBehavior(InvalidProgramBehaviorError),
    MaxChainedCallsDepthExceeded,
    OutOfValidityWindow,
}

#[derive(Debug)]
struct CallerData {
    program_id: Option<ProgramId>,
    authorized_accounts: HashSet<AccountId>,
}

#[cfg_attr(any(feature = "host", test), derive(Debug))]
pub struct ThreadedDiff {
    pub accounts: Vec<(AccountWithMetadata, Account)>,
    pub block_validity_window: BlockValidityWindow,
    pub timestamp_validity_window: TimestampValidityWindow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authorization {
    Holder,
    None,
}

pub struct Resolved {
    pub account: Account,
    pub authorization: Authorization,
}

pub trait Backend {
    type Error: From<ValidationError>;

    fn output_for_call(
        &mut self,
        call: &ChainedCall,
        caller: Option<ProgramId>,
    ) -> Result<ProgramOutput, Self::Error>;

    fn resolve_pre_state(&mut self, pre: &AccountWithMetadata)
    -> Result<Resolved, ValidationError>;

    fn try_bind_pda(
        &mut self,
        program_id: ProgramId,
        seed: PdaSeed,
        account_id: AccountId,
    ) -> Result<bool, ValidationError>;

    fn key_preimage_presented(&self, pre: &AccountWithMetadata) -> bool;

    fn finalize(&self) -> Result<(), ValidationError>;
}

fn intersect_window<T: Copy + Ord>(
    bounds: (Option<T>, Option<T>),
    window: ValidityWindow<T>,
) -> (Option<T>, Option<T>) {
    let lower = match (bounds.0, window.start()) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (x, None) | (None, x) => x,
    };
    let upper = match (bounds.1, window.end()) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (x, None) | (None, x) => x,
    };
    (lower, upper)
}

pub fn validate_state_diff<E: Backend>(
    env: &mut E,
    initial_call: ChainedCall,
) -> Result<ThreadedDiff, E::Error> {
    let mut state_diff: HashMap<AccountId, Account> = HashMap::new();
    let mut pre_states: Vec<AccountWithMetadata> = Vec::new();
    let mut globally_authorized: HashSet<AccountId> = HashSet::new();
    let mut block_bounds: (Option<BlockId>, Option<BlockId>) = (None, None);
    let mut ts_bounds: (Option<Timestamp>, Option<Timestamp>) = (None, None);

    let mut chained_calls = VecDeque::from_iter([(
        initial_call,
        CallerData {
            program_id: None,
            authorized_accounts: HashSet::new(),
        },
    )]);
    let mut chain_calls_counter = 0;

    while let Some((chained_call, caller_data)) = chained_calls.pop_front() {
        if chain_calls_counter > MAX_NUMBER_CHAINED_CALLS {
            return Err(ValidationError::MaxChainedCallsDepthExceeded.into());
        }

        let mut program_output = env.output_for_call(&chained_call, caller_data.program_id)?;

        for pre in &program_output.pre_states {
            let account_id = pre.account_id;

            let expected = if let Some(post) = state_diff.get(&account_id) {
                post.clone()
            } else {
                pre_states.push(pre.clone());
                let resolved = env.resolve_pre_state(pre)?;
                if matches!(resolved.authorization, Authorization::Holder) {
                    globally_authorized.insert(account_id);
                }
                resolved.account
            };
            if pre.account != expected {
                return Err(ValidationError::ProgramBehavior(
                    InvalidProgramBehaviorError::InconsistentAccountPreState {
                        account_id,
                        expected: Box::new(expected),
                        actual: Box::new(pre.account.clone()),
                    },
                )
                .into());
            }

            let mut seed_authorizes = false;
            if let Some(caller) = caller_data.program_id {
                for &seed in &chained_call.pda_seeds {
                    if env.try_bind_pda(caller, seed, account_id)? {
                        seed_authorizes = true;
                        break;
                    }
                }
            }
            let is_indeed_authorized = seed_authorizes
                || globally_authorized.contains(&account_id)
                || caller_data.authorized_accounts.contains(&account_id);
            if pre.is_authorized && !is_indeed_authorized {
                return Err(ValidationError::ProgramBehavior(
                    InvalidProgramBehaviorError::InvalidAccountAuthorization { account_id },
                )
                .into());
            }
            if !pre.is_authorized && is_indeed_authorized {
                return Err(ValidationError::ProgramBehavior(
                    InvalidProgramBehaviorError::AuthorizedAccountMarkedAsNotAuthorized {
                        account_id,
                    },
                )
                .into());
            }
        }

        if program_output.self_program_id != chained_call.program_id {
            return Err(ValidationError::ProgramBehavior(
                InvalidProgramBehaviorError::MismatchedProgramId {
                    expected: chained_call.program_id,
                    actual: program_output.self_program_id,
                },
            )
            .into());
        }
        if program_output.caller_program_id != caller_data.program_id {
            return Err(ValidationError::ProgramBehavior(
                InvalidProgramBehaviorError::MismatchedCallerProgramId {
                    expected: caller_data.program_id,
                    actual: program_output.caller_program_id,
                },
            )
            .into());
        }

        validate_execution(
            &program_output.pre_states,
            &program_output.post_states,
            chained_call.program_id,
        )
        .map_err(|e| ValidationError::ProgramBehavior(e.into()))?;

        block_bounds = intersect_window(block_bounds, program_output.block_validity_window);
        ts_bounds = intersect_window(ts_bounds, program_output.timestamp_validity_window);

        for (index, post) in program_output.post_states.iter_mut().enumerate() {
            let Some(claim) = post.required_claim() else {
                continue;
            };
            let pre = &program_output.pre_states[index];
            let account_id = pre.account_id;

            if post.account().program_owner != DEFAULT_PROGRAM_ID {
                return Err(ValidationError::ProgramBehavior(
                    InvalidProgramBehaviorError::ClaimedNonDefaultAccount { account_id },
                )
                .into());
            }

            match claim {
                Claim::Key => {
                    if !env.key_preimage_presented(pre) {
                        return Err(ValidationError::ProgramBehavior(
                            InvalidProgramBehaviorError::UnprovenAccountClaim { account_id },
                        )
                        .into());
                    }
                }
                Claim::Pda(seed) => {
                    if !env.try_bind_pda(chained_call.program_id, seed, account_id)? {
                        return Err(ValidationError::ProgramBehavior(
                            InvalidProgramBehaviorError::MismatchedPdaClaim { account_id },
                        )
                        .into());
                    }
                }
            }

            post.account_mut().program_owner = chained_call.program_id;
        }

        for (pre, post) in program_output
            .pre_states
            .iter()
            .zip(program_output.post_states.iter())
        {
            state_diff.insert(pre.account_id, post.account().clone());
        }

        let authorized_accounts: HashSet<AccountId> = caller_data
            .authorized_accounts
            .into_iter()
            .chain(
                program_output
                    .pre_states
                    .iter()
                    .filter(|pre| pre.is_authorized)
                    .map(|pre| pre.account_id),
            )
            .collect();
        for new_call in program_output.chained_calls.into_iter().rev() {
            chained_calls.push_front((
                new_call,
                CallerData {
                    program_id: Some(chained_call.program_id),
                    authorized_accounts: authorized_accounts.clone(),
                },
            ));
        }

        chain_calls_counter = chain_calls_counter
            .checked_add(1)
            .expect("we check the max depth at the beginning of the loop");
    }

    let block_validity_window: BlockValidityWindow = block_bounds
        .try_into()
        .map_err(|_err| ValidationError::OutOfValidityWindow)?;
    let timestamp_validity_window: TimestampValidityWindow = ts_bounds
        .try_into()
        .map_err(|_err| ValidationError::OutOfValidityWindow)?;

    env.finalize()?;

    let accounts: Vec<(AccountWithMetadata, Account)> = pre_states
        .into_iter()
        .map(|pre| {
            let post = state_diff
                .get(&pre.account_id)
                .cloned()
                .expect("post state must exist for every pre state");
            (pre, post)
        })
        .collect();

    for (pre, post) in &accounts {
        if pre.account.program_owner == DEFAULT_PROGRAM_ID
            && pre.account != *post
            && post.program_owner == DEFAULT_PROGRAM_ID
        {
            return Err(ValidationError::ProgramBehavior(
                InvalidProgramBehaviorError::DefaultAccountModifiedWithoutClaim {
                    account_id: pre.account_id,
                },
            )
            .into());
        }
    }

    Ok(ThreadedDiff {
        accounts,
        block_validity_window,
        timestamp_validity_window,
    })
}
