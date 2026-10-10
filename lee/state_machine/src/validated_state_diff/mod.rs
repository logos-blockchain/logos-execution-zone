use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    hash::Hash,
    panic::{AssertUnwindSafe, catch_unwind},
};

use lee_core::{
    BlockId, Commitment, CommitmentSetDigest, Nullifier, ProgramImageClaim, ProvenExecution,
    RecoveryBinding, RootCall, Timestamp,
    account::{Account, AccountId, Actor, ActorState, Cycles, Nonce},
    execution_state::{
        PublicExecutionContext, PublicOutcome, PublicPart, TransactionEntry, TransitionView,
        WholeTransaction,
    },
    program::{MessageBody, PROGRAM_LOADER_ACCOUNT_ID, Publication, TransactionEvent},
};
use public_backend::PublicBackend;

use crate::{
    PublicAccountEvidence, V03State, ensure,
    error::LeeError,
    privacy_preserving_transaction::{PrivacyPreservingTransaction, circuit::Proof},
    program::Program,
    public_transaction::PublicTransaction,
};

mod public_backend;

#[derive(Default)]
pub struct StateDiff {
    pub signer_account_ids: Vec<AccountId>,
    pub public_diff: HashMap<AccountId, Account>,
    pub new_commitments: Vec<Commitment>,
    pub new_nullifiers: Vec<(Nullifier, CommitmentSetDigest)>,
    pub events: Vec<TransactionEvent>,
    pub published: Vec<Publication>,
    pub recovery_bindings: Vec<RecoveryBinding>,
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
/// across every transition of the transaction.
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

    /// Validates and executes `tx` under `cycle_budget`, shared by every transition
    /// of the transaction: each transition is limited to the remaining budget, so
    /// the transaction cannot exceed the budget in aggregate.
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
        let mut cycles_used: u64 = 0;
        // Signers both authorize the execution and advance their replay nonces.
        let result = Self::execute_authorized(
            message.execution.root.clone(),
            message.context.clone(),
            evidence(&signers, &message.admission_evidence),
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
                ..StateDiff::default()
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
        to: Actor,
        message: &[u8],
        public_actors: &BTreeSet<Actor>,
        authorized: &HashSet<AccountId>,
        state: &V03State,
        block_id: BlockId,
        timestamp: Timestamp,
    ) -> Result<Self, LeeError> {
        let mut cycles_used = 0; // dont care
        Self::execute_authorized(
            RootCall {
                to,
                message: message.to_vec(),
            },
            PublicExecutionContext::new(public_actors.iter().copied(), authorized.iter().copied()),
            authorized.iter().copied().collect(),
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
        Self::execute_authorized(
            message.execution.root.clone(),
            message.context.clone(),
            evidence(&signer_account_ids, &message.admission_evidence),
            signer_account_ids,
            state,
            block_id,
            timestamp,
            cycle_budget,
            cycles_used,
        )
    }

    /// Shared execution core: validates and executes one transaction root and
    /// every transition it leads to, producing a diff. `nonce_bearers` become the
    /// diff's `signer_account_ids` (their nonces advance on apply).
    #[expect(
        clippy::too_many_arguments,
        reason = "the execution core threads the full invocation context"
    )]
    fn execute_authorized(
        root: RootCall,
        context: PublicExecutionContext,
        evidence: BTreeSet<AccountId>,
        nonce_bearers: Vec<AccountId>,
        state: &V03State,
        block_id: BlockId,
        timestamp: Timestamp,
        cycle_budget: u64,
        cycles_used: &mut u64,
    ) -> Result<Self, LeeError> {
        ensure!(
            context.runs_publicly(root.to),
            LeeError::InvalidInput("Root actor is not declared".into())
        );
        let backend = PublicBackend::new(
            state,
            cycle_budget,
            cycles_used,
            context.cast_promotions.clone(),
            evidence,
        );
        let request = WholeTransaction::new(context, TransactionEntry::Call(root), &[])
            .map_err(|error| LeeError::InvalidInput(error.to_string()))?;
        settle(
            backend,
            |backend| Ok(request.execute(backend)?.public),
            block_id,
            timestamp,
            StateDiff {
                signer_account_ids: nonce_bearers,
                ..StateDiff::default()
            },
        )
        .map(Self)
    }

    pub fn from_privacy_preserving_transaction(
        tx: &PrivacyPreservingTransaction,
        state: &V03State,
        block_id: BlockId,
        timestamp: Timestamp,
    ) -> Result<Self, LeeError> {
        let message = &tx.message;
        let execution = &message.execution;
        let commitments = execution.commitments();
        let nullifiers = execution.nullifiers();

        // 1. Private actions or recovery bindings are non empty
        ensure!(
            !execution.private_actions.is_empty() || !execution.recovery_bindings.is_empty(),
            LeeError::InvalidInput(
                "Empty commitments, nullifiers and recovery bindings found in message".into(),
            )
        );

        // 2. Check there are no duplicate nullifiers in the new_nullifiers list
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
        let signer_account_ids = tx.check_stateless()?;
        check_nonces(state, &message.nonces)?;

        // Verify validity window
        ensure!(
            execution.validity.is_valid_at(block_id, timestamp),
            LeeError::OutOfValidityWindow
        );

        // 4. Proof verification
        check_privacy_preserving_circuit_proof_is_valid(
            state,
            &tx.witness_set.proof,
            &message.context,
            execution,
        )?;

        // 5. Commitment freshness
        state.check_commitments_are_new(&commitments)?;

        // 6. Nullifier uniqueness
        state.check_nullifiers_are_valid(&nullifiers)?;
        state.check_recovery_bindings_are_new(&execution.recovery_bindings)?;

        // 7. Entry: the public part runs a public root; a privately received message is spent by
        // its private action alone.
        let request = PublicPart::new(
            message.context.clone(),
            execution.public_root.clone(),
            execution.boundary.clone(),
        )
        .map_err(|error| LeeError::InvalidInput(error.to_string()))?;
        let mut cycles_used = 0;
        let backend = PublicBackend::new(
            state,
            crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET,
            &mut cycles_used,
            message.context.cast_promotions.clone(),
            evidence(&signer_account_ids, &message.admission_evidence),
        );
        let mut diff = settle(
            backend,
            |backend| request.execute(backend),
            block_id,
            timestamp,
            StateDiff {
                signer_account_ids,
                new_commitments: commitments,
                new_nullifiers: nullifiers,
                recovery_bindings: execution.recovery_bindings.clone(),
                ..StateDiff::default()
            },
        )?;
        // The proven private Casts follow the live public ones.
        diff.published
            .extend(execution.casts.iter().cloned().map(Publication::Sealed));
        Ok(Self(diff))
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

fn load_program<'state>(
    account_id: AccountId,
    loader_actor_state: impl Fn(AccountId) -> Option<&'state ActorState>,
) -> Option<Program> {
    let (program_id, elf) = crate::program::resolve_program(account_id, loader_actor_state)?;
    Some(Program::new_unchecked(program_id, Cow::Owned(elf)))
}

/// The same lookup `get_program_via` uses, which is what keeps deploy-then-call working within
/// one transaction.
fn loader_actor_state<'state>(
    view: &'state TransitionView<'_>,
    state: &'state V03State,
    account_id: AccountId,
) -> Option<&'state ActorState> {
    view.staged_state(Actor::new(account_id, PROGRAM_LOADER_ACCOUNT_ID))
        .or_else(|| state.loader_actor_state(account_id))
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

fn publish(
    state: &V03State,
    introduced: &[RecoveryBinding],
    body: MessageBody,
) -> Result<Publication, LeeError> {
    let recovery = state
        .bound_note(introduced, body.to.account_id)
        .ok_or(LeeError::UnboundCastDestination { actor: body.to })?
        .clone();
    Ok(Publication::Clear { body, recovery })
}

fn settle(
    mut backend: PublicBackend<'_>,
    execute: impl FnOnce(&mut PublicBackend<'_>) -> Result<PublicOutcome, LeeError>,
    block_id: BlockId,
    timestamp: Timestamp,
    mut diff: StateDiff,
) -> Result<StateDiff, LeeError> {
    let PublicOutcome {
        validity,
        accounts,
        events,
        casts,
    } = execute(&mut backend)?;
    ensure!(
        validity.is_valid_at(block_id, timestamp),
        LeeError::OutOfValidityWindow
    );
    let state = backend.state();
    // An account first reached here is registered even when its handler leaves it empty.
    diff.public_diff = accounts
        .into_iter()
        .filter_map(|(account_id, data)| {
            let pre = state.get_account_by_id_ref(account_id);
            let executed = !data.actor_states.is_empty();
            let mut post = pre.cloned().unwrap_or_default();
            post.data.update(&data);
            let changed = pre.map_or(executed, |pre| *pre != post);
            changed.then_some((account_id, post))
        })
        .collect();
    diff.new_commitments.extend(backend.finish()?);
    diff.events = events
        .into_iter()
        .map(|(actor, event)| TransactionEvent {
            account_id: actor.program_account_id,
            event,
        })
        .collect();
    diff.published = casts
        .into_iter()
        .map(|body| publish(state, &diff.recovery_bindings, body))
        .collect::<Result<_, _>>()?;
    Ok(diff)
}

fn evidence(
    signers: &[AccountId],
    admission_evidence: &[PublicAccountEvidence],
) -> BTreeSet<AccountId> {
    signers
        .iter()
        .copied()
        .chain(
            admission_evidence
                .iter()
                .map(PublicAccountEvidence::account_id),
        )
        .collect()
}

/// Validates the witness set and replay nonces of a public transaction against
/// `state`, returning the signer account ids.
fn authenticate_public_transaction_signers(
    tx: &PublicTransaction,
    state: &V03State,
) -> Result<Vec<AccountId>, LeeError> {
    let signer_account_ids = tx.check_stateless()?;
    check_nonces(state, &tx.message().nonces)?;
    Ok(signer_account_ids)
}

fn check_nonces(state: &V03State, nonces: &BTreeMap<AccountId, Nonce>) -> Result<(), LeeError> {
    for (account_id, nonce) in nonces {
        let current_nonce = state
            .get_account_by_id_ref(*account_id)
            .map_or_else(Nonce::default, |account| account.nonce);
        ensure!(
            current_nonce == *nonce,
            LeeError::InvalidInput("Nonce mismatch".into())
        );
    }
    Ok(())
}

fn check_privacy_preserving_circuit_proof_is_valid(
    state: &V03State,
    proof: &Proof,
    context: &PublicExecutionContext,
    execution: &ProvenExecution,
) -> Result<(), LeeError> {
    // Anchor each `Disclosed` claim to real chain state: the message must name the image its
    // account holds now, which is also what the receipt has to have committed to.
    // `Undisclosed`'s membership check already happened in-circuit; the one thing left to check
    // here is that its `root` is one the commitment tree has actually had.
    for claim in &execution.program_image_claims {
        match claim {
            ProgramImageClaim::Disclosed {
                account_id,
                image_id,
            } => {
                let live = state.get_program_image_id(*account_id).ok_or_else(|| {
                    LeeError::InvalidInput(format!("Unknown program {account_id}"))
                })?;
                ensure!(live == *image_id, LeeError::InvalidPrivacyPreservingProof);
            }
            ProgramImageClaim::Undisclosed { root } => {
                ensure!(
                    state.is_known_commitment_root(root),
                    LeeError::InvalidInput("Unrecognized commitment set digest".to_owned())
                );
            }
        }
    }
    proof
        .is_valid_for(context, execution)
        .then_some(())
        .ok_or(LeeError::InvalidPrivacyPreservingProof)
}

fn n_unique<T: Eq + Hash>(data: &[T]) -> usize {
    let set: HashSet<&T> = data.iter().collect();
    set.len()
}

#[cfg(test)]
mod tests;
