use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    hash::Hash,
    panic::{AssertUnwindSafe, catch_unwind},
};

use lee_core::{
    BlockId, Commitment, Nullifier, PrivacyPreservingCircuitOutput, ProgramImageClaim,
    PublicAction, Timestamp,
    account::{Account, AccountId, Cycles, Nonce, ProgramShardSelector, ShardData},
    execution_state::{
        ExecutionError, ExecutionState, PublicEffects, PublicOutcome, PublicResolution,
        PublicSource, RootCall,
    },
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
    program::{
        InstructionData, PROGRAM_LOADER_ACCOUNT_ID, ProgramInput, ProgramOutput, ResolveInput,
        ResolveOutput, TransactionEvent, get_program_via, validate_resolution,
    },
};
use log::debug;
use program_loader_core::Instruction as ProgramLoaderInstruction;

use crate::{
    V03State, ensure,
    error::{InvalidProgramBehaviorError, LeeError},
    privacy_preserving_transaction::{
        PrivacyPreservingTransaction,
        circuit::Proof,
        message::{Message, PublicActionWithID},
    },
    program::Program,
    public_transaction::PublicTransaction,
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

struct ChainSource<'state> {
    state: &'state V03State,
}

impl PublicSource for ChainSource<'_> {
    type Error = LeeError;

    fn shard(
        &mut self,
        account_id: AccountId,
        program_account_id: AccountId,
    ) -> Result<ShardData, LeeError> {
        Ok(self
            .state
            .get_account_by_id_ref(account_id)
            .map_or_else(ShardData::empty, |account| {
                account.data.shard(program_account_id).clone()
            }))
    }
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

        // An account may select several shards, but never the same one twice.
        ensure!(
            shard_selectors.iter().collect::<HashSet<_>>().len() == shard_selectors.len(),
            LeeError::InvalidInput("Duplicate shard selectors found in message".into(),)
        );

        let mut source = ChainSource { state };
        let mut execution = ExecutionState::initialize(
            RootCall {
                program_account_id,
                shard_selectors: shard_selectors.to_vec(),
                instruction_data: instruction_data.to_vec(),
                authorized_accounts: authorized.iter().copied().collect(),
            },
            &[],
            PublicEffects::Resolve,
        )?;
        let mut events: Vec<TransactionEvent> = Vec::new();

        while execution.prepare_next_call()?.is_some() {
            let call = execution.prepared_call();
            let self_account_id = call.self_account_id;
            let caller_account_id = call.caller_account_id;
            debug!(
                "Program {self_account_id:?} accounts: {:?}, instruction_data: {:?}",
                call.accounts, call.instruction
            );

            // The program instance is selected once and held for the whole invocation, so every
            // effect of this plan is resolved by the code that planned it.
            let (plan, evaluator) = if self_account_id == PROGRAM_LOADER_ACCOUNT_ID {
                // Native dispatch: `program_loader` is a pseudo-program run as Rust rather than a
                // guest ELF, so there is no zkVM session to charge cycles against.
                let plan = execute_program_loader(call, |account_id| {
                    loader_shard(&execution, state, account_id)
                })?;
                (plan, Evaluator::Loader)
            } else if self_account_id == NATIVE_TOKEN_PROGRAM_ID {
                let plan =
                    native_token::execute(caller_account_id, &call.accounts, &call.instruction)
                        .map_err(InvalidProgramBehaviorError::NativeTransferFailed)?;
                (plan, Evaluator::Native)
            } else {
                let Some((program_id, elf)) = get_program_via(self_account_id, |account_id| {
                    execution
                        .pending_shard(account_id, PROGRAM_LOADER_ACCOUNT_ID)
                        .or_else(|| state.loader_shard(account_id))
                }) else {
                    return Err(LeeError::UnknownProgram {
                        chained: caller_account_id.is_some(),
                    });
                };
                let program = Program::new_unchecked(program_id, Cow::Owned(elf));
                let (plan, call_cycles) =
                    program.execute(call, remaining(cycle_budget, *cycles_used))?;
                charge(cycles_used, call_cycles);
                (plan, Evaluator::Guest(program))
            };
            debug!("Program {self_account_id:?} plan: {plan:?}");

            execution.bind_plan(plan)?;

            while let Some(obligation) = execution.next_obligation(&mut source)? {
                let input = obligation.clone();
                let resolution = match &evaluator {
                    Evaluator::Loader => ResolveOutput {
                        post_data: Some(catch_program_loader_panic(|| {
                            program_loader_core::resolve(&input)
                        })?),
                        input,
                    },
                    Evaluator::Native => ResolveOutput {
                        post_data: Some(
                            native_token::resolve(&input)
                                .map_err(InvalidProgramBehaviorError::NativeTransferFailed)?,
                        ),
                        input,
                    },
                    Evaluator::Guest(program) => {
                        let (resolution, call_cycles) =
                            program.resolve(&input, remaining(cycle_budget, *cycles_used))?;
                        charge(cycles_used, call_cycles);
                        resolution
                    }
                };
                execution.accept_resolution(&resolution)?;
            }

            let call_events = execution.complete_call()?;

            ensure!(
                execution.block_validity_window().is_valid_for(block_id)
                    && execution
                        .timestamp_validity_window()
                        .is_valid_for(timestamp),
                LeeError::OutOfValidityWindow
            );

            // Write all the output event data into a proper event struct,
            // marking its emitter program.
            events.extend(call_events.into_iter().map(|event| TransactionEvent {
                account_id: self_account_id,
                event,
            }));
        }

        let PublicOutcome::Resolved(accounts) = execution.finish()?.public else {
            unreachable!("resolving public effects produces resolved accounts")
        };
        let public_diff = accounts
            .into_iter()
            .map(|(account_id, data)| {
                let mut account = state.get_account_by_id(account_id);
                account.data.apply(&data);
                (account_id, account)
            })
            .collect();

        Ok(Self(StateDiff {
            signer_account_ids: nonce_bearers,
            public_diff,
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

        // The journal carries no public state, only the effects settlement must fold. Its
        // authorization bits are reconstructed here from the verified signatures, never taken
        // from the prover's claim.
        let public_actions: Vec<PublicAction> = message
            .public_actions
            .iter()
            .map(|action| PublicAction {
                account_id: action.account_id,
                is_authorized: signer_account_ids.contains(&action.account_id),
                resolutions: action.resolutions.clone(),
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

        let public_diff = fold_public_resolutions(
            state,
            &message.public_actions,
            crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET,
        )?;
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

enum Evaluator {
    Loader,
    Native,
    Guest(Program),
}

const fn remaining(cycle_budget: Cycles, used: Cycles) -> Cycles {
    cycle_budget.saturating_sub(used)
}

const fn charge(used: &mut Cycles, call_cycles: Cycles) {
    *used = used
        .checked_add(call_cycles)
        .expect("cycle sums fit u64: overflow would need ~2^64 executed cycles");
}

/// The same lookup `get_program_via` uses, which is what keeps deploy-then-call working within
/// one transaction.
fn loader_shard<'state>(
    execution: &'state ExecutionState<'_>,
    state: &'state V03State,
    account_id: AccountId,
) -> &'state ShardData {
    const ABSENT: &ShardData = &ShardData::empty();
    execution
        .pending_shard(account_id, PROGRAM_LOADER_ACCOUNT_ID)
        .or_else(|| state.loader_shard(account_id))
        .unwrap_or(ABSENT)
}

/// `program_loader_core`'s functions panic on malformed input, mirroring the assert-based style
/// every other `*_core` crate uses under its guest's sandbox. There is no zkVM sandbox here, so
/// `catch_unwind` stands in for it: a panic becomes a chargeable
/// [`LeeError::ProgramExecutionFailed`] instead of taking down the caller.
fn catch_program_loader_panic<T>(run: impl FnOnce() -> T) -> Result<T, LeeError> {
    catch_unwind(AssertUnwindSafe(run)).map_err(|panic| {
        let message = panic
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| panic.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "program_loader panicked".to_owned());
        LeeError::ProgramExecutionFailed(message)
    })
}

/// Produces the same [`ProgramOutput`] shape a guest call would, so the rest of the dispatch loop
/// treats it identically either way. Its plan reads live loader shards through `shard` because it
/// is trusted, public-only protocol code, not a guest planning from state-free metadata.
fn execute_program_loader<'state>(
    input: &ProgramInput<InstructionData>,
    shard: impl Fn(AccountId) -> &'state ShardData,
) -> Result<ProgramOutput, LeeError> {
    let ProgramInput {
        self_account_id,
        caller_account_id,
        accounts,
        instruction: instruction_data,
    } = input;
    let instruction: ProgramLoaderInstruction = borsh::from_slice(instruction_data)
        .map_err(|e| LeeError::ProgramExecutionFailed(e.to_string()))?;

    let effects = catch_program_loader_panic(|| match instruction {
        ProgramLoaderInstruction::WriteSegment {
            bytecode,
            next_segment,
        } => program_loader_core::write_segment(accounts, shard, bytecode, next_segment),
        ProgramLoaderInstruction::CreateHeader {
            first_segment,
            immutable,
        } => program_loader_core::create_header(accounts, shard, first_segment, immutable),
        ProgramLoaderInstruction::UpdateHeader {
            first_segment,
            immutable,
        } => program_loader_core::update_header(accounts, shard, first_segment, immutable),
    })?;

    Ok(ProgramOutput::new(
        *self_account_id,
        *caller_account_id,
        instruction_data.clone(),
        accounts.clone(),
    )
    .with_effects(effects))
}

/// Runs each recorded public effect against live state, under one aggregate cycle budget shared
/// by every resolver in the transaction.
///
/// Private transactions are fee-exempt, so this guest work is currently unpaid and a proof whose
/// resolver always fails can be resubmitted at no cost. That hole is accepted deliberately and
/// is what the charged-settlement work closes.
fn fold_public_resolutions(
    state: &V03State,
    actions: &[PublicActionWithID],
    cycle_budget: Cycles,
) -> Result<HashMap<AccountId, Account>, LeeError> {
    let mut pending: HashMap<AccountId, Account> = HashMap::new();
    let mut cycles_used: Cycles = 0;
    let mut loaded: HashMap<AccountId, Program> = HashMap::new();
    for action in actions {
        let account = pending
            .entry(action.account_id)
            .or_insert_with(|| state.get_account_by_id(action.account_id));
        for resolution in &action.resolutions {
            let PublicResolution::Apply {
                program_account_id,
                shard_program_account_id,
                data,
            } = resolution;
            let input = ResolveInput {
                self_account_id: *program_account_id,
                selector: ProgramShardSelector::new(action.account_id, *shard_program_account_id),
                pre_data: account.data.shard(*shard_program_account_id).clone(),
                effect_data: data.clone(),
            };
            // Native balance is protocol-recomputed; every other evaluator is the guest the
            // proof's image claims already bound to this account. Only the native branch builds
            // an output of its own, so only it needs a copy of the scheduled input.
            let output = if *program_account_id == NATIVE_TOKEN_PROGRAM_ID {
                ResolveOutput {
                    post_data: Some(
                        native_token::resolve(&input)
                            .map_err(InvalidProgramBehaviorError::NativeTransferFailed)?,
                    ),
                    input: input.clone(),
                }
            } else {
                if !loaded.contains_key(program_account_id) {
                    let Some((program_id, elf)) =
                        get_program_via(*program_account_id, |id| state.loader_shard(id))
                    else {
                        return Err(LeeError::UnknownProgram { chained: false });
                    };
                    loaded.insert(
                        *program_account_id,
                        Program::new_unchecked(program_id, Cow::Owned(elf)),
                    );
                }
                let program = &loaded[program_account_id];
                let (output, call_cycles) =
                    program.resolve(&input, remaining(cycle_budget, cycles_used))?;
                charge(&mut cycles_used, call_cycles);
                output
            };
            validate_resolution(&input, &output).map_err(|source| {
                InvalidProgramBehaviorError::Execution(ExecutionError::ExecutionValidation {
                    program_account_id: *program_account_id,
                    source,
                })
            })?;
            account.data.apply_resolution(&output);
        }
    }
    Ok(pending)
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
