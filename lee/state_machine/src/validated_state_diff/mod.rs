use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    panic::{AssertUnwindSafe, catch_unwind},
};

use lee_core::{
    BlockId, Commitment, Nullifier, PrivacyPreservingCircuitOutput, ProgramImageClaim,
    PublicAction, Timestamp,
    account::{Account, AccountId, Cycles, Nonce, ProgramShardSelector},
    program::{AccountInput, ChainedCall, ProgramOutput, TransactionEvent},
    validation::validate_state_diff,
};
use program_loader_core::Instruction as ProgramLoaderInstruction;

use crate::{
    V03State, ensure,
    error::LeeError,
    privacy_preserving_transaction::{
        PrivacyPreservingTransaction, circuit::Proof, message::Message,
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
    ///
    /// The walk itself lives in [`lee_core::validation`], shared with the privacy preserving
    /// circuit; everything specific to executing rather than verifying is in [`PublicBackend`].
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
        let declared: HashSet<AccountId> = shard_selectors
            .iter()
            .map(|shard_selector| shard_selector.account_id)
            .collect();

        let initial_call = ChainedCall {
            program_account_id,
            instruction_data: instruction_data.to_vec(),
            shard_selectors: shard_selectors.to_vec(),
            pda_seeds: vec![],
        };
        let mut backend = PublicBackend::new(
            state,
            block_id,
            timestamp,
            declared,
            authorized,
            cycle_budget.saturating_sub(*cycles_used),
        );
        let result = validate_state_diff(&mut backend, initial_call, shard_selectors);

        // Read back before propagating the failure: a chargeable revert still owes the cycles
        // every call burned before the one that failed.
        *cycles_used = cycles_used
            .checked_add(backend.cycles_used())
            .expect("cycle sums fit u64: overflow would need ~2^64 executed cycles");

        let threaded = result?;

        // The traversal tracks balances and shards; nonces are untouched by execution and
        // advance only at apply time, so re-attach each account's committed nonce.
        let public_diff = threaded
            .accounts
            .into_iter()
            .map(|(account_id, tracked)| {
                let nonce = state
                    .get_account_by_id_ref(account_id)
                    .map(|account| account.nonce)
                    .unwrap_or_default();
                let data = tracked.current;
                (account_id, Account { nonce, data })
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
) -> Result<(ProgramOutput, Option<Commitment>), LeeError> {
    let instruction: ProgramLoaderInstruction = borsh::from_slice(instruction_data)
        .map_err(|e| LeeError::ProgramExecutionFailed(e.to_string()))?;

    // WriteSegment never emits a commitment; CreateHeader/UpdateHeader emit one only when this
    // call is what makes the header immutable.
    let (state_diffs, new_commitment) = catch_unwind(AssertUnwindSafe(|| match instruction {
        ProgramLoaderInstruction::WriteSegment {
            bytecode,
            next_segment,
        } => (
            program_loader_core::write_segment(pre_states, bytecode, next_segment),
            None,
        ),
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

    Ok((
        ProgramOutput::new(
            self_account_id,
            caller_account_id,
            instruction_data.to_vec(),
            state_diffs,
        ),
        new_commitment,
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
