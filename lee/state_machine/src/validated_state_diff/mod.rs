use std::{
    borrow::Cow,
    collections::{HashMap, HashSet, hash_map::Entry},
    hash::Hash,
    panic::{AssertUnwindSafe, catch_unwind},
};

use lee_core::{
    BlockId, Commitment, Nullifier, PrivacyPreservingCircuitOutput, ProgramImageClaim,
    PublicAction, Timestamp,
    account::{Account, AccountId, Cycles, Nonce, ProgramShardSelector, ShardData},
    execution_state::{DeferredPublicEffect, ExecutionError, ExecutionState, RootCall},
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
    program::{
        ApplyInput, ApplyOutput, PROGRAM_LOADER_ACCOUNT_ID, PlanInput, PlanOutput,
        TransactionEvent, get_program_via, validate_apply_output,
    },
};
use program_loader_core::Instruction as ProgramLoaderInstruction;
use public_backend::PublicBackend;

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

mod public_backend;

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
pub struct ExecutionCharge {
    pub cycles: Cycles,
}

impl ExecutionCharge {
    /// The charge of transaction kinds that meter nothing.
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
    ) -> Result<(Self, ExecutionCharge), LeeError> {
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
            ExecutionCharge {
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
    ) -> (ExecutionCharge, Result<Self, LeeError>) {
        // Authentication failure is a malformed transaction, not a revert: bail
        // before executing so the caller can reject the block.
        let signers = match authenticate_public_transaction_signers(tx, state) {
            Ok(signers) => signers,
            Err(err) => return (ExecutionCharge::FREE, Err(err)),
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
        // A non-zero exit keeps its count: the failing call's cycles ride on the error since
        // `execute_authorized` bailed before adding them. A panic or session-limit bail loses
        // the count and pays the full budget.
        let cycles = match &result {
            Ok(_) => cycles_used,
            Err(LeeError::ProgramExitedWithCode { cycles, .. }) => {
                cycles_used.saturating_add(*cycles)
            }
            Err(_) => cycle_budget,
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
            Err(err) => return (ExecutionCharge { cycles }, Err(err)),
        };
        (ExecutionCharge { cycles }, Ok(diff))
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

        let execution = ExecutionState::initialize(
            RootCall {
                program_account_id,
                shard_selectors: shard_selectors.to_vec(),
                instruction_data: instruction_data.to_vec(),
                authorized_accounts: authorized.iter().copied().collect(),
            },
            &[],
        )?;
        let mut backend = PublicBackend::new(state, block_id, timestamp, cycle_budget, cycles_used);
        let public_diff = execution
            .run(&mut backend)?
            .public
            .into_iter()
            .map(|(account_id, data)| {
                let mut account = state.get_account_by_id(account_id);
                account.data.update(&data);
                (account_id, account)
            })
            .collect();
        let (events, new_commitments) = backend.into_outputs();

        Ok(Self(StateDiff {
            signer_account_ids: nonce_bearers,
            public_diff,
            new_commitments,
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

        // Check that there are no duplicate signers
        let signer_account_ids = tx.signer_account_ids();
        ensure!(
            n_unique(&signer_account_ids) == signer_account_ids.len(),
            LeeError::InvalidInput("Duplicate signers found in witness set".into())
        );

        // Check the signatures are valid
        ensure!(
            witness_set.signatures_are_valid_for(message),
            LeeError::InvalidInput("Invalid signature for given message and public key".into())
        );

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
                effects: action.effects.clone(),
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

        let public_diff = apply_public_effects(
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

enum Applier {
    Loader,
    Native,
    Guest(Program),
}

impl Applier {
    fn apply(
        &self,
        input: &ApplyInput,
        cycle_budget: Cycles,
        cycles_used: &mut Cycles,
    ) -> Result<ApplyOutput, LeeError> {
        match self {
            Self::Loader => Ok(ApplyOutput {
                post_data: Some(catch_program_loader_panic(|| {
                    program_loader_core::apply(input)
                })?),
                input: input.clone(),
            }),
            Self::Native => Ok(native_token::apply_output(input)
                .map_err(InvalidProgramBehaviorError::NativeTransferFailed)?),
            Self::Guest(program) => {
                let (output, call_cycles) =
                    program.apply(input, remaining(cycle_budget, *cycles_used))?;
                charge(cycles_used, call_cycles);
                Ok(output)
            }
        }
    }
}

fn load_program<'state>(
    account_id: AccountId,
    loader_shard: impl Fn(AccountId) -> Option<&'state ShardData>,
) -> Option<Program> {
    let (program_id, elf) = get_program_via(account_id, loader_shard)?;
    let elf = crate::program::attach_kernel(&elf);
    Some(Program::new_unchecked(program_id, Cow::Owned(elf)))
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
) -> Option<&'state ShardData> {
    execution
        .pending_shard(account_id, PROGRAM_LOADER_ACCOUNT_ID)
        .or_else(|| state.loader_shard(account_id))
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

/// Produces the same [`PlanOutput`] shape a guest call would, so the rest of the dispatch loop
/// treats it identically either way. Its plan reads live loader shards through `shard` because it
/// is trusted, public-only protocol code, not a guest planning from state-free metadata.
fn plan_program_loader<'state>(
    input: &PlanInput,
    shard: impl Fn(AccountId) -> &'state ShardData,
) -> Result<(PlanOutput, Option<Commitment>), LeeError> {
    let accounts = &input.accounts;
    let instruction: ProgramLoaderInstruction = borsh::from_slice(&input.instruction_data)
        .map_err(|e| LeeError::ProgramExecutionFailed(e.to_string()))?;

    let (effects, new_commitment) = catch_program_loader_panic(|| match instruction {
        ProgramLoaderInstruction::WriteSegment {
            bytecode,
            next_segment,
        } => (
            program_loader_core::write_segment(accounts, shard, bytecode, next_segment),
            None,
        ),
        ProgramLoaderInstruction::CreateHeader {
            first_segment,
            immutable,
        } => program_loader_core::create_header(accounts, shard, first_segment, immutable),
        ProgramLoaderInstruction::UpdateHeader {
            first_segment,
            immutable,
        } => program_loader_core::update_header(accounts, shard, first_segment, immutable),
    })?;

    Ok((
        PlanOutput::new(input.clone()).with_effects(effects),
        new_commitment,
    ))
}

/// Applies public effects to live state under one shared cycle budget.
/// Private transactions are currently fee-exempt, so failed settlement attempts
/// can be repeated without paying a fee.
fn apply_public_effects(
    state: &V03State,
    actions: &[PublicActionWithID],
    cycle_budget: Cycles,
) -> Result<HashMap<AccountId, Account>, LeeError> {
    let mut pending: HashMap<AccountId, Account> = HashMap::new();
    let mut cycles_used: Cycles = 0;
    let mut appliers: HashMap<AccountId, Applier> = HashMap::new();
    for action in actions {
        let account = pending
            .entry(action.account_id)
            .or_insert_with(|| state.get_account_by_id(action.account_id));
        for effect in &action.effects {
            let DeferredPublicEffect {
                program_account_id,
                shard_program_account_id,
                data,
            } = effect;
            let input = ApplyInput {
                self_account_id: *program_account_id,
                selector: ProgramShardSelector::new(action.account_id, *shard_program_account_id),
                pre_data: account.data.shard(*shard_program_account_id).clone(),
                effect_data: data.clone(),
            };
            // Native balance is protocol-recomputed; every other evaluator is the guest the
            // proof's image claims already bound to this account.
            let applier = match appliers.entry(*program_account_id) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => {
                    entry.insert(if *program_account_id == NATIVE_TOKEN_PROGRAM_ID {
                        Applier::Native
                    } else {
                        Applier::Guest(
                            load_program(*program_account_id, |id| state.loader_shard(id))
                                .ok_or(LeeError::UnknownProgram { chained: false })?,
                        )
                    })
                }
            };
            let output = applier.apply(&input, cycle_budget, &mut cycles_used)?;
            validate_apply_output(&input, &output).map_err(|source| {
                InvalidProgramBehaviorError::Execution(ExecutionError::ExecutionValidation {
                    program_account_id: *program_account_id,
                    source,
                })
            })?;
            account.data.apply_output(&output);
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

    // A repeated signer would advance its nonce once per entry.
    let signer_account_ids = tx.signer_account_ids();
    ensure!(
        n_unique(&signer_account_ids) == signer_account_ids.len(),
        LeeError::InvalidInput("Duplicate signers found in witness set".into())
    );

    ensure!(
        witness_set.is_valid_for(message),
        LeeError::InvalidInput("Invalid signature for given message and public key".into())
    );

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
    // Anchor each `Disclosed` claim to real chain state, reconstructing it independently rather
    // than trusting the message's own claim — a wrong claim means the reconstructed journal won't
    // match what the receipt actually committed to, so `proof.is_valid_for` fails below.
    // `Undisclosed`'s membership check already happened in-circuit; the one thing left to check
    // here is that its `root` is one the commitment tree has actually had.
    let program_image_claims = message
        .program_image_claims
        .iter()
        .map(|claim| match claim {
            ProgramImageClaim::Disclosed { account_id, .. } => {
                let image_id = state.get_program_image_id(*account_id).ok_or_else(|| {
                    LeeError::InvalidInput(format!("Unknown program {account_id}"))
                })?;
                Ok(ProgramImageClaim::Disclosed {
                    account_id: *account_id,
                    image_id,
                })
            }
            ProgramImageClaim::Undisclosed { root } => {
                ensure!(
                    state.is_known_commitment_root(root),
                    LeeError::InvalidInput("Unrecognized commitment set digest".to_owned())
                );
                Ok(*claim)
            }
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
