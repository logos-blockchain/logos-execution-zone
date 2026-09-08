use std::{
    borrow::Cow,
    collections::{HashMap, HashSet, VecDeque},
    hash::Hash,
    panic::{AssertUnwindSafe, catch_unwind},
};

use lee_core::{
    BlockId, Commitment, Nullifier, PrivacyPreservingCircuitOutput, ProgramImageClaim,
    PublicAction, Timestamp,
    account::{Account, AccountId, AccountInput, Cycles, Nonce, ProgramShardSelector},
    program::{
        CallKind, CallerData, ChainedCall, PROGRAM_LOADER_ACCOUNT_ID, ProgramOutput,
        TransactionEvent, compute_public_authorized_pdas, get_program_via,
        pre_states_match_shard_selectors, validate_execution,
    },
};
use log::debug;
use program_loader_core::Instruction as ProgramLoaderInstruction;

use crate::{
    V03State, ensure,
    error::{InvalidProgramBehaviorError, LeeError},
    privacy_preserving_transaction::{
        PrivacyPreservingTransaction, circuit::Proof, message::Message,
    },
    program::Program,
    public_transaction::PublicTransaction,
    state::MAX_NUMBER_CHAINED_CALLS,
};

pub struct StateDiff {
    pub signer_account_ids: Vec<AccountId>,
    pub public_diff: HashMap<AccountId, Account>,
    pub new_commitments: Vec<Commitment>,
    pub new_nullifiers: Vec<Nullifier>,
    pub events: Vec<TransactionEvent>,
}

/// The validated output of executing or verifying a transaction, ready to be applied to the state.
///
/// It can only be constructed by the transaction validation functions inside this crate, ensuring
/// the diff has been checked before any state mutation occurs. Under the `test-utils` feature the
/// [`crate::test_utils`] module additionally exposes a hand-rolled constructor for unit-testing
/// downstream validation logic; that feature must never be enabled in a production build.
pub struct ValidatedStateDiff(StateDiff);

#[cfg(feature = "test-utils")]
impl ValidatedStateDiff {
    /// Test-only constructor that wraps an already-built [`StateDiff`] **without validating it**.
    ///
    /// Kept in this module so the wrapped field can stay private: in a normal build (feature off)
    /// the only ways to obtain a `ValidatedStateDiff` remain the `from_*_transaction` validators.
    #[must_use]
    pub const fn new_unchecked(state_diff: StateDiff) -> Self {
        Self(state_diff)
    }
}

/// The metered result of a public execution: the cycle count accumulated
/// across every call in the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionOutcome {
    pub cycles: Cycles,
}

impl ExecutionOutcome {
    /// The outcome of transaction kinds that meter nothing.
    pub const FREE: Self = Self { cycles: 0 };
}

impl ValidatedStateDiff {
    /// [`Self::from_public_transaction_with_cycle_budget`] at the default budget,
    /// discarding the metered outcome.
    pub fn from_public_transaction(
        tx: &PublicTransaction,
        state: &V03State,
        block_id: BlockId,
        timestamp: Timestamp,
    ) -> Result<Self, LeeError> {
        Self::from_public_transaction_with_cycle_budget(
            tx,
            state,
            block_id,
            timestamp,
            crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET,
        )
        .map(|(diff, _)| diff)
    }

    /// Validates and executes `tx` under `cycle_budget`, shared by every call
    /// in the chain: each nested session is limited to the remaining budget, so
    /// the chain cannot exceed the budget in aggregate.
    pub fn from_public_transaction_with_cycle_budget(
        tx: &PublicTransaction,
        state: &V03State,
        block_id: BlockId,
        timestamp: Timestamp,
        cycle_budget: Cycles,
    ) -> Result<(Self, ExecutionOutcome), LeeError> {
        let mut cycles_used: u64 = 0;
        let diff = Self::execute_public_core(
            tx,
            state,
            block_id,
            timestamp,
            cycle_budget,
            &mut cycles_used,
        )?;
        Ok((
            diff,
            ExecutionOutcome {
                cycles: cycles_used,
            },
        ))
    }

    /// The settlement-shaped variant: authenticate, execute under `cycle_budget`,
    /// and return a diff that is always safe to apply.
    ///
    /// - `Ok` on success: carries the transaction's full effects plus the signers' nonce advances.
    /// - `Ok` on a *reverted* action: the failure is charged w.r.t `LeeError::is_chargeable`, nonce
    ///   advances if charged.
    /// - `Err` covers a transaction a correct proposer would never include
    pub fn from_public_transaction_metered(
        tx: &PublicTransaction,
        state: &V03State,
        block_id: BlockId,
        timestamp: Timestamp,
        cycle_budget: u64,
    ) -> (ExecutionOutcome, Result<Self, LeeError>) {
        // Authentication failure is a malformed transaction, not a revert: bail
        // before executing so the caller can reject the block.
        let signers = match authenticate_public_transaction_signers(tx, state) {
            Ok(signers) => signers,
            Err(err) => return (ExecutionOutcome::FREE, Err(err)),
        };
        let message = tx.message();
        // Signers both authorize the execution and advance their replay nonces.
        let authorized: HashSet<AccountId> = signers.iter().copied().collect();
        let mut cycles_used: u64 = 0;
        let result = Self::execute_authorized(
            message.program_account_id,
            &message.shard_selectors,
            &message.instruction_data,
            &authorized,
            signers.clone(),
            state,
            block_id,
            timestamp,
            cycle_budget,
            &mut cycles_used,
        );
        // any failure pays the full declared budget
        let cycles = if result.is_err() {
            cycle_budget
        } else {
            cycles_used
        };
        let diff = match result {
            Ok(diff) => diff,
            // A chargeable action failure keeps no effects but still advances the
            // signers' nonces, so what `apply_state_diff` receives is the nonce
            // bumps alone: the fee stays committed and the tx cannot be replayed.
            Err(err) if err.is_chargeable() => Self(StateDiff {
                signer_account_ids: signers,
                public_diff: HashMap::new(),
                new_commitments: Vec::new(),
                new_nullifiers: Vec::new(),
                events: Vec::new(),
            }),
            // A non-chargeable failure is a structural defect a correct proposer
            // would never include; reject the whole block.
            Err(err) => return (ExecutionOutcome { cycles }, Err(err)),
        };
        (ExecutionOutcome { cycles }, Ok(diff))
    }

    /// Executes a fee-settlement invocation (reserve or refund), authorized by
    /// the fee declaration rather than a signature and advancing no nonces (the
    /// action phase owns the payer's replay nonce).
    ///
    /// Fee-scoped by name on purpose: it skips the signature check, so it must
    /// not read as a general escape hatch. `authorized` is the guest's
    /// `is_authorized` set — the payer for the reserve, empty for the refund.
    pub fn from_fee_settlement_invocation(
        program_account_id: AccountId,
        shard_selectors: &[ProgramShardSelector],
        instruction_data: &[u8],
        authorized: &HashSet<AccountId>,
        state: &V03State,
        block_id: BlockId,
        timestamp: Timestamp,
    ) -> Result<Self, LeeError> {
        let mut cycles_used = 0; // dont care
        Self::execute_authorized(
            program_account_id,
            shard_selectors,
            instruction_data,
            authorized,
            Vec::new(), // no nonces to advance!
            state,
            block_id,
            timestamp,
            crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET,
            &mut cycles_used,
        )
    }

    fn execute_public_core(
        tx: &PublicTransaction,
        state: &V03State,
        block_id: BlockId,
        timestamp: Timestamp,
        cycle_budget: u64,
        cycles_used: &mut u64,
    ) -> Result<Self, LeeError> {
        let signer_account_ids = authenticate_public_transaction_signers(tx, state)?;
        let message = tx.message();
        // Signers both authorize the execution and advance their replay nonces.
        let authorized: HashSet<AccountId> = signer_account_ids.iter().copied().collect();
        Self::execute_authorized(
            message.program_account_id,
            &message.shard_selectors,
            &message.instruction_data,
            &authorized,
            signer_account_ids,
            state,
            block_id,
            timestamp,
            cycle_budget,
            cycles_used,
        )
    }

    /// Shared execution core: validates and executes one program invocation
    /// (with its chained calls), producing a diff. `authorized` is the guest's
    /// `is_authorized` set; `nonce_bearers` become the diff's `signer_account_ids`
    /// (their nonces advance on apply).
    #[expect(
        clippy::too_many_arguments,
        reason = "the execution core threads the full invocation context"
    )]
    fn execute_authorized(
        program_account_id: AccountId,
        shard_selectors: &[ProgramShardSelector],
        instruction_data: &[u8],
        authorized: &HashSet<AccountId>,
        nonce_bearers: Vec<AccountId>,
        state: &V03State,
        block_id: BlockId,
        timestamp: Timestamp,
        cycle_budget: u64,
        cycles_used: &mut u64,
    ) -> Result<Self, LeeError> {
        ensure!(
            !shard_selectors.is_empty(),
            LeeError::InvalidInput("Public transaction must have at least one account".into())
        );

        // All account_ids must be different
        ensure!(
            shard_selectors
                .iter()
                .map(|shard_selector| shard_selector.account_id)
                .collect::<HashSet<_>>()
                .len()
                == shard_selectors.len(),
            LeeError::InvalidInput("Duplicate account_ids found in message".into(),)
        );

        let mut state_diff: HashMap<AccountId, Account> = HashMap::new();
        let declared: HashSet<AccountId> = shard_selectors
            .iter()
            .map(|shard_selector| shard_selector.account_id)
            .collect();
        // Shard selectors seen in program outputs.
        let mut shard_selectors_seen: HashSet<ProgramShardSelector> = HashSet::new();
        let mut events: Vec<TransactionEvent> = Vec::new();

        let initial_call = ChainedCall {
            program_account_id,
            instruction_data: instruction_data.to_vec(),
            shard_selectors: shard_selectors.to_vec(),
            pda_seeds: vec![],
        };

        let initial_caller_data = CallerData {
            account_id: None,
            authorized_accounts: authorized.clone(),
        };

        let mut chained_calls =
            VecDeque::<(ChainedCall, CallerData)>::from_iter([(initial_call, initial_caller_data)]);
        let mut chain_calls_counter = 0;

        while let Some((chained_call, caller_data)) = chained_calls.pop_front() {
            ensure!(
                chain_calls_counter <= MAX_NUMBER_CHAINED_CALLS,
                LeeError::MaxChainedCallsDepthExceeded
            );

            let authorized_pdas =
                compute_public_authorized_pdas(caller_data.account_id, &chained_call.pda_seeds);

            // Account is authorized if it is either in the caller's authorized accounts or in the
            // list of PDAs the caller has authorized.
            let is_authorized = |account_id: &AccountId| {
                authorized_pdas.contains(account_id)
                    || caller_data.authorized_accounts.contains(account_id)
            };

            // The caller only names shard selectors; resolve each one's actual value from the
            // protocol's own tracked state, not from anything it asserts. Resolvable only if
            // declared up front or already touched in this transaction — never merely because
            // it exists somewhere in global state.
            let absent = Account::default();
            let real_pre_states: Vec<AccountInput> = chained_call
                .shard_selectors
                .iter()
                .map(|shard_selector| {
                    let account_id = shard_selector.account_id;
                    let account = match state_diff.get(&account_id) {
                        Some(account) => account,
                        None if declared.contains(&account_id) => {
                            state.get_account_by_id_ref(account_id).unwrap_or(&absent)
                        }
                        None => {
                            return Err(LeeError::from(
                                InvalidProgramBehaviorError::UnknownChainedCallAccount {
                                    account_id,
                                },
                            ));
                        }
                    };
                    Ok(AccountInput::at(
                        *shard_selector,
                        is_authorized(&account_id),
                        &account.data,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?;

            debug!(
                "Program {:?} pre_states: {:?}, instruction_data: {:?}",
                chained_call.program_account_id, real_pre_states, chained_call.instruction_data
            );
            let program_output = if chained_call.program_account_id == PROGRAM_LOADER_ACCOUNT_ID {
                // Native dispatch: `program_loader` is a pseudo-program run as Rust rather than a
                // guest ELF, so there is no zkVM session to charge cycles against.
                execute_program_loader(
                    chained_call.program_account_id,
                    caller_data.account_id,
                    &real_pre_states,
                    &chained_call.instruction_data,
                )?
            } else {
                // Looks through `state_diff` first, falling back to `state` — so an earlier
                // chained call in this same transaction that deployed this program is seen
                // immediately, rather than only on the next transaction.
                let Some((program_id, elf)) =
                    get_program_via(chained_call.program_account_id, |id| {
                        state_diff
                            .get(&id)
                            .or_else(|| state.get_account_by_id_ref(id))
                    })
                else {
                    return Err(LeeError::UnknownProgram {
                        chained: caller_data.account_id.is_some(),
                    });
                };
                let program = Program::new_unchecked(program_id, Cow::Owned(elf));
                let (program_output, call_cycles) = program.execute(
                    chained_call.program_account_id,
                    caller_data.account_id,
                    &real_pre_states,
                    &chained_call.instruction_data,
                    cycle_budget.saturating_sub(*cycles_used),
                )?;
                *cycles_used = cycles_used
                    .checked_add(call_cycles)
                    .expect("cycle sums fit u64: overflow would need ~2^64 executed cycles");
                program_output
            };
            debug!(
                "Program {:?} output: {:?}",
                chained_call.program_account_id, program_output
            );

            // A chained callee must account for exactly the shard selectors its caller named, in
            // order. The top-level call has no caller, so it's exempt here.
            ensure!(
                caller_data.account_id.is_none()
                    || pre_states_match_shard_selectors(
                        &chained_call.shard_selectors,
                        &program_output.state_diffs
                    ),
                InvalidProgramBehaviorError::ChainedCallAccountsMismatch {
                    program_account_id: chained_call.program_account_id
                }
            );

            let named_accounts: HashSet<AccountId> = chained_call
                .shard_selectors
                .iter()
                .map(|shard_selector| shard_selector.account_id)
                .collect();

            for pre in program_output
                .state_diffs
                .iter()
                .map(|diff| &diff.pre_state)
            {
                let account_id = pre.account_id;
                ensure!(
                    named_accounts.contains(&account_id),
                    InvalidProgramBehaviorError::UndeclaredAccountInProgramOutput {
                        program_account_id: chained_call.program_account_id,
                        account_id
                    }
                );

                // Check that the program output pre_states coincide with the values in the public
                // state or with any modifications to those values during the chain of calls.
                let shard_selector = ProgramShardSelector::from(pre);
                let expected = state_diff
                    .get(&account_id)
                    .or_else(|| state.get_account_by_id_ref(account_id))
                    .unwrap_or(&absent);
                let consistent = expected.data.balance == pre.balance
                    && pre
                        .shard
                        .as_ref()
                        .is_none_or(|(program, data)| expected.data.shard(*program) == data);
                ensure!(
                    consistent,
                    InvalidProgramBehaviorError::InconsistentAccountPreState {
                        account_id,
                        expected: Box::new(AccountInput::at(
                            shard_selector,
                            pre.is_authorized,
                            &expected.data
                        )),
                        actual: Box::new(pre.clone())
                    }
                );

                // Check that the program output pre_states marked as authorized are indeed
                // authorized, and vice-versa.
                let is_indeed_authorized = is_authorized(&account_id);
                ensure!(
                    !pre.is_authorized || is_indeed_authorized,
                    InvalidProgramBehaviorError::InvalidAccountAuthorization { account_id }
                );
                ensure!(
                    pre.is_authorized || !is_indeed_authorized,
                    InvalidProgramBehaviorError::AuthorizedAccountMarkedAsNotAuthorized {
                        account_id
                    }
                );

                shard_selectors_seen.insert(shard_selector);
            }

            // Verify that the program output's self_account_id matches the expected address.
            ensure!(
                program_output.self_account_id == chained_call.program_account_id,
                InvalidProgramBehaviorError::MismatchedProgramId {
                    expected: chained_call.program_account_id,
                    actual: program_output.self_account_id
                }
            );

            // Verify that the program output's caller_account_id matches the actual caller.
            ensure!(
                program_output.caller_account_id == caller_data.account_id,
                InvalidProgramBehaviorError::MismatchedCallerProgramId {
                    expected: caller_data.account_id,
                    actual: program_output.caller_account_id,
                }
            );

            // Only a top-level call may legitimately be a no-op; a chained call must execute.
            if caller_data.account_id.is_some() {
                ensure!(
                    program_output.call_kind == CallKind::Execute,
                    InvalidProgramBehaviorError::ChainedCallDidNotExecute {
                        program_account_id: chained_call.program_account_id
                    }
                );
            }

            // Verify execution corresponds to a well-behaved program.
            // See the # Programs section for the definition of the `validate_execution` method.
            validate_execution(&program_output.state_diffs, chained_call.program_account_id)
                .map_err(InvalidProgramBehaviorError::ExecutionValidationFailed)?;

            // Verify validity window
            ensure!(
                program_output.block_validity_window.is_valid_for(block_id)
                    && program_output
                        .timestamp_validity_window
                        .is_valid_for(timestamp),
                LeeError::OutOfValidityWindow
            );

            // Apply balance and shard changes, preserving all other shards.
            for diff in &program_output.state_diffs {
                let account_id = diff.pre_state.account_id;
                state_diff
                    .entry(account_id)
                    .or_insert_with(|| state.get_account_by_id(account_id))
                    .data
                    .apply_diff(diff)
                    .map_err(InvalidProgramBehaviorError::BalanceDiffFailed)?;
            }

            // Write all the output event data into a proper event struct,
            // marking its emitter program.
            events.extend(
                program_output
                    .events
                    .into_iter()
                    .map(|event| TransactionEvent {
                        account_id: chained_call.program_account_id,
                        event,
                    }),
            );

            // Source from `program_output.state_diffs` (the callee's own checked echo), not
            // `chained_call.shard_selectors` (bare shard selectors the caller supplied, carrying no
            // authorization claim at all and forgeable, audit-issue 91) — the loop above
            // already gates program_output's `is_authorized` via the `!pre.is_authorized ||
            // is_indeed_authorized` check.
            //
            // Union with the caller's authorized set so that authorization is monotonically
            // growing: once an account is authorized at any point in the chain it remains
            // authorized for all subsequent calls.
            let mut authorized_accounts = caller_data.authorized_accounts;
            authorized_accounts.extend(
                program_output
                    .state_diffs
                    .iter()
                    .map(|diff| &diff.pre_state)
                    .filter(|pre| pre.is_authorized)
                    .map(|pre| pre.account_id),
            );
            for new_call in program_output.chained_calls.into_iter().rev() {
                chained_calls.push_front((
                    new_call,
                    CallerData {
                        account_id: Some(chained_call.program_account_id),
                        authorized_accounts: authorized_accounts.clone(),
                    },
                ));
            }

            chain_calls_counter = chain_calls_counter
                .checked_add(1)
                .expect("we check the max depth at the beginning of the loop");
        }

        // Every initial shard selector must appear in a program output.
        for shard_selector in shard_selectors {
            ensure!(
                shard_selectors_seen.contains(shard_selector),
                InvalidProgramBehaviorError::DeclaredAccountMissingFromOutput {
                    account_id: shard_selector.account_id
                }
            );
        }

        Ok(Self(StateDiff {
            signer_account_ids: nonce_bearers,
            public_diff: state_diff,
            new_commitments: vec![],
            new_nullifiers: vec![],
            events,
        }))
    }

    pub fn from_privacy_preserving_transaction(
        tx: &PrivacyPreservingTransaction,
        state: &V03State,
        block_id: BlockId,
        timestamp: Timestamp,
    ) -> Result<Self, LeeError> {
        let message = &tx.message;
        let witness_set = &tx.witness_set;
        let commitments = message.commitments();
        let nullifiers = message.nullifiers();
        let public_account_ids = message.public_account_ids();

        // 1. Commitments or nullifiers are non empty
        ensure!(
            !message.private_actions.is_empty(),
            LeeError::InvalidInput(
                "Empty commitments and empty nullifiers found in message".into(),
            )
        );

        // 2. Check there are no duplicate account_ids in the public_account_ids list.
        ensure!(
            n_unique(&public_account_ids) == public_account_ids.len(),
            LeeError::InvalidInput("Duplicate account_ids found in message".into())
        );

        // Check there are no duplicate nullifiers in the new_nullifiers list
        ensure!(
            n_unique(&nullifiers.iter().map(|(n, _)| n).collect::<Vec<_>>()) == nullifiers.len(),
            LeeError::InvalidInput("Duplicate nullifiers found in message".into())
        );

        // Check there are no duplicate commitments in the new_commitments list
        ensure!(
            n_unique(&commitments) == commitments.len(),
            LeeError::InvalidInput("Duplicate commitments found in message".into())
        );

        // 3. Nonce checks and Valid signatures
        // Check exactly one nonce is provided for each signature
        ensure!(
            message.nonces.len() == witness_set.signatures_and_public_keys.len(),
            LeeError::InvalidInput(
                "Mismatch between number of nonces and signatures/public keys".into(),
            )
        );

        // Check the signatures are valid
        ensure!(
            witness_set.signatures_are_valid_for(message),
            LeeError::InvalidInput("Invalid signature for given message and public key".into())
        );

        let signer_account_ids = tx.signer_account_ids();
        // Check nonces corresponds to the current nonces on the public state.
        for (account_id, nonce) in signer_account_ids.iter().zip(&message.nonces) {
            let current_nonce = state
                .get_account_by_id_ref(*account_id)
                .map_or_else(Nonce::default, |account| account.nonce);
            ensure!(
                current_nonce == *nonce,
                LeeError::InvalidInput("Nonce mismatch".into())
            );
        }

        // Verify validity window
        ensure!(
            message.block_validity_window.is_valid_for(block_id)
                && message.timestamp_validity_window.is_valid_for(timestamp),
            LeeError::OutOfValidityWindow
        );

        // Build each public pre-state from chain state and the action's shard keys.
        let absent = Account::default();
        let public_actions: Vec<PublicAction> = message
            .public_actions
            .iter()
            .map(|action| PublicAction {
                account_id: action.account_id,
                is_authorized: signer_account_ids.contains(&action.account_id),
                pre: state
                    .get_account_by_id_ref(action.account_id)
                    .unwrap_or(&absent)
                    .data
                    .project(action.post.shards.keys().copied()),
                post: action.post.clone(),
            })
            .collect();

        // 4. Proof verification
        check_privacy_preserving_circuit_proof_is_valid(
            state,
            &witness_set.proof,
            public_actions,
            message,
        )?;

        // 5. Commitment freshness
        state.check_commitments_are_new(&commitments)?;

        // 6. Nullifier uniqueness
        state.check_nullifiers_are_valid(&nullifiers)?;

        let public_diff = message
            .public_actions
            .iter()
            .map(|action| {
                let mut account = state.get_account_by_id(action.account_id);
                account.data.apply(&action.post);
                (action.account_id, account)
            })
            .collect();
        let new_nullifiers = nullifiers.iter().map(|(nullifier, _)| *nullifier).collect();

        Ok(Self(StateDiff {
            signer_account_ids,
            public_diff,
            new_commitments: commitments,
            new_nullifiers,
            events: vec![],
        }))
    }

    /// Returns the public account changes produced by this transaction.
    ///
    /// Used by callers (e.g. the sequencer) to inspect the diff before committing it, for example
    /// to enforce that system accounts are not modified by user transactions.
    #[must_use]
    pub const fn public_diff(&self) -> &HashMap<AccountId, Account> {
        &self.0.public_diff
    }

    pub(crate) fn into_state_diff(self) -> StateDiff {
        self.0
    }
}

/// Runs `program_loader`'s instruction as native Rust rather than a guest ELF, producing the same
/// [`ProgramOutput`] shape a guest call would — so the rest of the dispatch loop (chained-call
/// bookkeeping, `validate_execution`, splicing) treats it identically either way.
///
/// `program_loader_core`'s functions panic on malformed input, mirroring the assert-based style
/// every other `*_core` crate uses under its guest's sandbox. There is no zkVM sandbox here, so
/// `catch_unwind` stands in for it: a panic becomes a chargeable
/// [`LeeError::ProgramExecutionFailed`] instead of taking down the caller.
fn execute_program_loader(
    self_account_id: AccountId,
    caller_account_id: Option<AccountId>,
    pre_states: &[AccountInput],
    instruction_data: &[u8],
) -> Result<ProgramOutput, LeeError> {
    let instruction: ProgramLoaderInstruction = borsh::from_slice(instruction_data)
        .map_err(|e| LeeError::ProgramExecutionFailed(e.to_string()))?;

    let state_diffs = catch_unwind(AssertUnwindSafe(|| match instruction {
        ProgramLoaderInstruction::WriteSegment {
            bytecode,
            next_segment,
        } => program_loader_core::write_segment(pre_states, bytecode, next_segment),
        ProgramLoaderInstruction::CreateHeader {
            first_segment,
            immutable,
        } => program_loader_core::create_header(pre_states, first_segment, immutable),
        ProgramLoaderInstruction::UpdateHeader {
            first_segment,
            immutable,
        } => program_loader_core::update_header(pre_states, first_segment, immutable),
    }))
    .map_err(|panic| {
        let message = panic
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| panic.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "program_loader panicked".to_owned());
        LeeError::ProgramExecutionFailed(message)
    })?;

    Ok(ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data.to_vec(),
        state_diffs,
    ))
}

/// Validates the witness set and replay nonces of a public transaction against
/// `state`, returning the signer account ids.
fn authenticate_public_transaction_signers(
    tx: &PublicTransaction,
    state: &V03State,
) -> Result<Vec<AccountId>, LeeError> {
    let message = tx.message();
    let witness_set = tx.witness_set();

    ensure!(
        message.nonces.len() == witness_set.signatures_and_public_keys.len(),
        LeeError::InvalidInput(
            "Mismatch between number of nonces and signatures/public keys".into(),
        )
    );

    ensure!(
        witness_set.is_valid_for(message),
        LeeError::InvalidInput("Invalid signature for given message and public key".into())
    );

    let signer_account_ids = tx.signer_account_ids();
    for (account_id, nonce) in signer_account_ids.iter().zip(&message.nonces) {
        let current_nonce = state
            .get_account_by_id_ref(*account_id)
            .map_or_else(Nonce::default, |account| account.nonce);
        ensure!(
            current_nonce == *nonce,
            LeeError::InvalidInput("Nonce mismatch".into())
        );
    }

    Ok(signer_account_ids)
}

fn check_privacy_preserving_circuit_proof_is_valid(
    state: &V03State,
    proof: &Proof,
    public_actions: Vec<PublicAction>,
    message: &Message,
) -> Result<(), LeeError> {
    // Anchor each claimed image_id to real chain state: reconstruct the claims using the
    // program's *actual* current image_id (via `get_program_image_id`), not the message's own
    // claim. If the claim was wrong, the reconstructed journal won't match what the receipt
    // actually committed to, and `proof.is_valid_for` below fails — the same mechanism
    // `public_actions` already relies on for authenticating account content against real state.
    let program_image_claims = message
        .program_image_claims
        .iter()
        .map(|claim| {
            let image_id = state
                .get_program_image_id(claim.account_id)
                .ok_or_else(|| {
                    LeeError::InvalidInput(format!("Unknown program {}", claim.account_id))
                })?;
            Ok(ProgramImageClaim {
                account_id: claim.account_id,
                image_id,
            })
        })
        .collect::<Result<Vec<_>, LeeError>>()?;

    let output = PrivacyPreservingCircuitOutput {
        public_actions,
        private_actions: message.private_actions.clone(),
        block_validity_window: message.block_validity_window,
        timestamp_validity_window: message.timestamp_validity_window,
        program_image_claims,
    };
    proof
        .is_valid_for(&output)
        .then_some(())
        .ok_or(LeeError::InvalidPrivacyPreservingProof)
}

fn n_unique<T: Eq + Hash>(data: &[T]) -> usize {
    let set: HashSet<&T> = data.iter().collect();
    set.len()
}

#[cfg(test)]
mod tests;
