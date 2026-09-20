use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    panic::{AssertUnwindSafe, catch_unwind},
};

use lee_core::{
    BlockId, Commitment, Nullifier, PrivacyPreservingCircuitOutput, ProgramImageClaim,
    PublicAction, Timestamp,
    account::{Account, AccountId, AccountWithMetadata, Cycles},
    program::{
        AccountStateDiff, ChainedCall, DEFAULT_PROGRAM_OWNER, ExecutionValidationError,
        ProgramOutput, TransactionEvent, post_state,
    },
    validation::{Backend as _, CallContext, Declarations, validate_state_diff},
};
use program_loader_core::Instruction as ProgramLoaderInstruction;

use crate::{
    V03State, ensure,
    error::{InvalidProgramBehaviorError, LeeError},
    privacy_preserving_transaction::{
        PrivacyPreservingTransaction,
        circuit::Proof,
        message::{Message, PublicActionWithID},
    },
    public_transaction::PublicTransaction,
    validated_state_diff::public_backend::PublicBackend,
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
            &message.account_ids,
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
        account_ids: &[AccountId],
        instruction_data: &[u8],
        authorized: &HashSet<AccountId>,
        state: &V03State,
        block_id: BlockId,
        timestamp: Timestamp,
    ) -> Result<Self, LeeError> {
        let mut cycles_used = 0; // dont care
        Self::execute_authorized(
            program_account_id,
            account_ids,
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
            &message.account_ids,
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
    ///
    /// The walk itself lives in [`lee_core::validation`], shared with the privacy preserving
    /// circuit; everything specific to executing rather than verifying is in [`PublicBackend`].
    #[expect(
        clippy::too_many_arguments,
        reason = "the execution core threads the full invocation context"
    )]
    fn execute_authorized(
        program_account_id: AccountId,
        account_ids: &[AccountId],
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
            !account_ids.is_empty(),
            LeeError::InvalidInput("Public transaction must have at least one account".into())
        );

        // All account_ids must be different
        ensure!(
            account_ids.iter().collect::<HashSet<_>>().len() == account_ids.len(),
            LeeError::InvalidInput("Duplicate account_ids found in message".into(),)
        );

        let initial_call = ChainedCall {
            program_account_id,
            instruction_data: instruction_data.to_vec(),
            pre_state_ids: account_ids.to_vec(),
            pda_seeds: vec![],
        };
        let declarations = Declarations {
            must_be_touched: account_ids,
            // A public transaction declares its accounts up front, so the top-level call is
            // confined to them just as a chained call is confined to the ids its caller named.
            root_output_is_confined: true,
        };

        let mut backend = PublicBackend::new(
            state,
            block_id,
            timestamp,
            account_ids,
            authorized,
            cycle_budget.saturating_sub(*cycles_used),
        );
        let result = validate_state_diff(&mut backend, initial_call, &declarations);

        // Read back before propagating the failure: a chargeable revert still owes the cycles
        // every call burned before the one that failed.
        *cycles_used = cycles_used
            .checked_add(backend.cycles_used())
            .expect("cycle sums fit u64: overflow would need ~2^64 executed cycles");

        let threaded = result?;

        Ok(Self(StateDiff {
            signer_account_ids: nonce_bearers,
            public_diff: threaded
                .accounts
                .into_iter()
                .map(|(pre, post)| (pre.account_id, post))
                .collect(),
            new_commitments: vec![],
            new_nullifiers: vec![],
            events: backend.into_events(),
        }))
    }

    /// [`Self::from_privacy_preserving_transaction_with_cycle_budget`] at the default budget,
    /// discarding the metered outcome.
    pub fn from_privacy_preserving_transaction(
        tx: &PrivacyPreservingTransaction,
        state: &V03State,
        block_id: BlockId,
        timestamp: Timestamp,
    ) -> Result<Self, LeeError> {
        Self::from_privacy_preserving_transaction_with_cycle_budget(
            tx,
            state,
            block_id,
            timestamp,
            crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET,
        )
        .map(|(diff, _)| diff)
    }

    /// Validates `tx` and settles its `Deferred` public actions under `cycle_budget`: each is
    /// replayed, host-side, against live state - the same `PublicBackend::resolve_write` an
    /// ordinary public transaction's own `Incremental` diffs go through, so settlement's cost is
    /// metered exactly the same way.
    pub fn from_privacy_preserving_transaction_with_cycle_budget(
        tx: &PrivacyPreservingTransaction,
        state: &V03State,
        block_id: BlockId,
        timestamp: Timestamp,
        cycle_budget: Cycles,
    ) -> Result<(Self, ExecutionOutcome), LeeError> {
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
            let current_nonce = state.get_account_by_id(*account_id).nonce;
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

        // Build pre_states for proof verification. Only a `Bound` action's `pre` is actually
        // consulted below (`check_privacy_preserving_circuit_proof_is_valid`'s `Deferred` arm
        // never reads it) - skip the live state read for a `Deferred` account entirely.
        let public_pre_states: Vec<_> = message
            .public_actions
            .iter()
            .map(|action| {
                let account_id = action.account_id();
                match action {
                    PublicActionWithID::Bound { .. } => AccountWithMetadata::new(
                        state.get_account_by_id(account_id),
                        signer_account_ids.contains(&account_id),
                        account_id,
                    ),
                    PublicActionWithID::Deferred { .. } => {
                        AccountWithMetadata::new(Account::default(), false, account_id)
                    }
                }
            })
            .collect();

        // 4. Proof verification
        check_privacy_preserving_circuit_proof_is_valid(
            state,
            &witness_set.proof,
            &public_pre_states,
            message,
        )?;

        // 5. Commitment freshness
        state.check_commitments_are_new(&commitments)?;

        // 6. Nullifier uniqueness
        state.check_nullifiers_are_valid(&nullifiers)?;

        let mut backend = PublicBackend::new(
            state,
            block_id,
            timestamp,
            &[],
            &HashSet::new(),
            cycle_budget,
        );
        let public_diff = message
            .public_actions
            .iter()
            .map(|action| resolve_public_action(action, state, &mut backend))
            .collect::<Result<HashMap<_, _>, _>>()?;
        let new_nullifiers = nullifiers.iter().map(|(nullifier, _)| *nullifier).collect();

        Ok((
            Self(StateDiff {
                signer_account_ids,
                public_diff,
                new_commitments: commitments,
                new_nullifiers,
                events: vec![],
            }),
            ExecutionOutcome {
                cycles: backend.cycles_used(),
            },
        ))
    }

    /// Returns the public account changes produced by this transaction.
    ///
    /// Used by callers (e.g. the sequencer) to inspect the diff before committing it, for example
    /// to enforce that system accounts are not modified by user transactions.
    #[must_use]
    pub fn public_diff(&self) -> HashMap<AccountId, Account> {
        self.0.public_diff.clone()
    }

    pub(crate) fn into_state_diff(self) -> StateDiff {
        self.0
    }
}

/// Runs `program_loader`'s instruction as native Rust rather than a guest ELF, producing the same
/// [`ProgramOutput`] shape a guest call would — so the rest of the dispatch loop (chained-call
/// bookkeeping, `validate_execution`, ownership acquisition) treats it identically either way.
///
/// `program_loader_core`'s functions panic on malformed input, mirroring the assert-based style
/// every other `*_core` crate uses under its guest's sandbox. There is no zkVM sandbox here, so
/// `catch_unwind` stands in for it: a panic becomes a chargeable
/// [`LeeError::ProgramExecutionFailed`] instead of taking down the caller.
fn execute_program_loader(
    self_account_id: AccountId,
    caller_account_id: Option<AccountId>,
    pre_states: &[AccountWithMetadata],
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
        let current_nonce = state.get_account_by_id(*account_id).nonce;
        ensure!(
            current_nonce == *nonce,
            LeeError::InvalidInput("Nonce mismatch".into())
        );
    }

    Ok(signer_account_ids)
}

/// Resolves one message-level public action to the `Account` it leaves behind. `Bound`'s
/// `post_state` is already final and proven - used as-is. `Deferred` carries a list of raw,
/// unresolved deltas, one per touch by an `Incremental`-supporting program, replayed in order
/// via `PublicBackend::resolve_write` against live state - each resolution building on the
/// previous one's result (`resolved_so_far`, standing in for `CallContext::touched`). `backend`
/// is shared across every action in the message, so `cycles_used` accumulates the whole
/// settlement's cost.
///
/// Also re-checks data ownership on each resolved diff (`validate_execution`'s own rule, but not
/// the full check - its balance-sum check spans one program call's diffs together, which a lone
/// `DeferredResolution` was never part of): an account's real owner can differ by settlement time
/// from what the prover saw at proof time, so the circuit's own check isn't a substitute for
/// checking again here.
fn resolve_public_action(
    action: &PublicActionWithID,
    state: &V03State,
    backend: &mut PublicBackend<'_>,
) -> Result<(AccountId, Account), LeeError> {
    let (account_id, resolutions) = match action {
        PublicActionWithID::Bound {
            account_id,
            post_state,
        } => return Ok((*account_id, post_state.clone())),
        PublicActionWithID::Deferred {
            account_id,
            resolutions,
        } => (*account_id, resolutions),
    };
    ensure!(
        !resolutions.is_empty(),
        LeeError::InvalidInput(format!(
            "Deferred action for account {account_id} carries no resolutions"
        ))
    );

    let mut resolved_so_far: HashMap<AccountId, Account> = HashMap::new();
    for deferred in resolutions {
        let pre_account = resolved_so_far
            .get(&account_id)
            .cloned()
            .unwrap_or_else(|| state.get_account_by_id(account_id));
        let diff = AccountStateDiff {
            pre_state: AccountWithMetadata::new(Account::default(), false, account_id),
            post_balance_diff: deferred.post_balance_diff,
            post_data: deferred.post_data.clone(),
        };
        let empty_authorized = HashSet::new();
        let ctx = CallContext {
            caller_account_id: None,
            program_account_id: deferred.executing_account_id,
            pda_seeds: &[],
            authorized_accounts: &empty_authorized,
            touched: &resolved_so_far,
        };
        // `DeferredResolution` doesn't carry a caller - nothing reads it, and settlement has no
        // record of what it was at proving time anyway.
        let resolved = backend.resolve_write(&diff, &ctx)?;
        ensure!(
            !resolved
                .post_data
                .as_ref()
                .is_some_and(|data| *data != pre_account.data)
                || pre_account.program_owner == DEFAULT_PROGRAM_OWNER
                || pre_account.program_owner == deferred.executing_account_id,
            InvalidProgramBehaviorError::ExecutionValidationFailed(
                ExecutionValidationError::UnauthorizedDataModification {
                    account_id,
                    executing_account_id: deferred.executing_account_id,
                }
            )
        );
        let post = post_state(&resolved, deferred.executing_account_id)
            .map_err(InvalidProgramBehaviorError::BalanceDiffFailed)?;
        resolved_so_far.insert(account_id, post);
    }

    Ok((
        account_id,
        resolved_so_far
            .remove(&account_id)
            .expect("just inserted above: resolutions is non-empty"),
    ))
}

fn check_privacy_preserving_circuit_proof_is_valid(
    state: &V03State,
    proof: &Proof,
    public_pre_states: &[AccountWithMetadata],
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

    // `Deferred`'s shape here matches `PublicActionWithID::Deferred` exactly - the circuit never
    // resolved it either, so reconstructing what it committed to is a plain re-tag, not a replay.
    // Settlement's own replay (`resolve_public_action`) happens later, against live state.
    let output = PrivacyPreservingCircuitOutput {
        public_actions: public_pre_states
            .iter()
            .cloned()
            .zip(&message.public_actions)
            .map(|(pre, action)| match action {
                PublicActionWithID::Bound { post_state, .. } => PublicAction::Bound {
                    pre,
                    post: post_state.clone(),
                },
                PublicActionWithID::Deferred {
                    account_id,
                    resolutions,
                } => PublicAction::Deferred {
                    account_id: *account_id,
                    resolutions: resolutions.clone(),
                },
            })
            .collect(),
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
