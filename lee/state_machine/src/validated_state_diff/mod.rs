use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    hash::Hash,
    panic::{AssertUnwindSafe, catch_unwind},
};

use lee_core::{
    BlockId, Commitment, Nullifier, PrivacyPreservingCircuitOutput, ProgramImageClaim, Timestamp,
    account::{Account, AccountId, Actor, ActorState, Cycles, Nonce},
    execution_state::{
        PublicExecutionContext, PublicOutcome, PublicPart, TransactionEntry, TurnView,
        WholeTransaction,
    },
    program::{MessageBody, MessageId, PROGRAM_LOADER_ACCOUNT_ID, StoredMessage, TransactionEvent},
};
use public_backend::PublicBackend;

use crate::{
    PublicIdentity, V03State, ensure,
    error::LeeError,
    privacy_preserving_transaction::{PrivacyPreservingTransaction, circuit::Proof},
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
    pub consumed: Vec<MessageId>,
    pub published: Vec<MessageBody>,
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
            message.root.clone(),
            &message.public_actors,
            &authorized,
            signers.clone(),
            &identity_account_ids(&message.identities),
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
                consumed: Vec::new(),
                published: Vec::new(),
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
        public_actors: &[Actor],
        authorized: &HashSet<AccountId>,
        state: &V03State,
        block_id: BlockId,
        timestamp: Timestamp,
    ) -> Result<Self, LeeError> {
        let mut cycles_used = 0; // dont care
        Self::execute_authorized(
            TransactionEntry::Call {
                to,
                message: message.to_vec(),
            },
            public_actors,
            authorized,
            Vec::new(), // no nonces to advance!
            &HashSet::new(),
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
            message.root.clone(),
            &message.public_actors,
            &authorized,
            signer_account_ids,
            &identity_account_ids(&message.identities),
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
        root: TransactionEntry<MessageId>,
        public_actors: &[Actor],
        authorized: &HashSet<AccountId>,
        nonce_bearers: Vec<AccountId>,
        identities: &HashSet<AccountId>,
        state: &V03State,
        block_id: BlockId,
        timestamp: Timestamp,
        cycle_budget: u64,
        cycles_used: &mut u64,
    ) -> Result<Self, LeeError> {
        let (root, consumed_message) = match root {
            TransactionEntry::Call { to, message } => {
                (TransactionEntry::Call { to, message }, None)
            }
            TransactionEntry::Receive(id) => {
                let record = state
                    .pending_message(id)
                    .ok_or_else(|| LeeError::InvalidInput("Root message is not pending".into()))?;
                (TransactionEntry::Receive(record.clone()), Some(id))
            }
        };
        let context =
            PublicExecutionContext::new(public_actors.to_vec(), authorized.iter().copied());
        ensure!(
            public_actors.contains(&root.destination()),
            LeeError::InvalidInput("Root actor is not declared".into())
        );
        if let Some(record) = root.receipt() {
            admit_public_receipt(record, &context, |account_id| {
                identities.contains(&account_id) || state.is_designated_public_account(account_id)
            })?;
        }
        let request = WholeTransaction::new(context, root, &[])
            .map_err(|error| LeeError::InvalidInput(error.to_string()))?;
        let settled = settle(
            state,
            |backend| Ok(request.execute(backend)?.public),
            block_id,
            timestamp,
            cycle_budget,
            cycles_used,
        )?;

        Ok(Self(StateDiff {
            signer_account_ids: nonce_bearers,
            consumed: consumed_message.into_iter().collect(),
            ..settled
        }))
    }

    pub fn from_privacy_preserving_transaction(
        tx: &PrivacyPreservingTransaction,
        state: &V03State,
        block_id: BlockId,
        timestamp: Timestamp,
    ) -> Result<Self, LeeError> {
        let message = &tx.message;
        let execution = &message.execution;
        let witness_set = &tx.witness_set;
        let commitments = execution.commitments();
        let nullifiers = execution.nullifiers();

        // 1. Commitments or nullifiers are non empty
        ensure!(
            !execution.private_actions.is_empty(),
            LeeError::InvalidInput(
                "Empty commitments and empty nullifiers found in message".into(),
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

        ensure!(
            sorted(signer_account_ids.iter().copied()) == execution.context.authorized_accounts,
            LeeError::InvalidInput("Authorized accounts do not match the signers".into())
        );

        // Verify validity window
        ensure!(
            execution.block_validity_window.is_valid_for(block_id)
                && execution.timestamp_validity_window.is_valid_for(timestamp),
            LeeError::OutOfValidityWindow
        );

        // 4. Proof verification
        check_privacy_preserving_circuit_proof_is_valid(state, &witness_set.proof, execution)?;

        // 5. Commitment freshness
        state.check_commitments_are_new(&commitments)?;

        // 6. Nullifier uniqueness
        state.check_nullifiers_are_valid(&nullifiers)?;

        // 7. Pending receipt
        if let Some(id) = execution.consumed_message {
            let record = state.pending_message(id).ok_or_else(|| {
                LeeError::InvalidInput("A consumed message is not pending".into())
            })?;
            let identities = identity_account_ids(&message.identities);
            admit_public_receipt(record, &execution.context, |account_id| {
                identities.contains(&account_id) || state.is_designated_public_account(account_id)
            })?;
        }

        let request = PublicPart::new(execution.context.clone(), execution.boundary.clone())
            .map_err(|error| LeeError::InvalidInput(error.to_string()))?;
        let mut cycles_used = 0;
        let mut settled = settle(
            state,
            |backend| request.execute(backend),
            block_id,
            timestamp,
            crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET,
            &mut cycles_used,
        )?;
        // The proven private Casts follow the live public ones.
        settled.published.extend(execution.casts.iter().cloned());
        let new_nullifiers = nullifiers.iter().map(|(nullifier, _)| *nullifier).collect();

        Ok(Self(StateDiff {
            signer_account_ids,
            new_commitments: commitments
                .into_iter()
                .chain(settled.new_commitments)
                .collect(),
            new_nullifiers,
            consumed: execution.consumed_message.into_iter().collect(),
            ..settled
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

fn load_program<'state>(
    account_id: AccountId,
    loader_shard: impl Fn(AccountId) -> Option<&'state ActorState>,
) -> Option<Program> {
    let (program_id, elf) = crate::program::resolve_program(account_id, loader_shard)?;
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
    view: &'state TurnView<'_>,
    state: &'state V03State,
    account_id: AccountId,
) -> Option<&'state ActorState> {
    view.staged_state(Actor::new(account_id, PROGRAM_LOADER_ACCOUNT_ID))
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

pub fn admit_public_receipt(
    record: &StoredMessage,
    context: &PublicExecutionContext,
    proves_identity: impl Fn(AccountId) -> bool,
) -> Result<(), LeeError> {
    let to = record.body.to;
    ensure!(
        !context.actors.contains(&to)
            || context.authorized_accounts.contains(&to.account_id)
            || proves_identity(to.account_id),
        LeeError::UnprovenPublicIdentity { actor: to }
    );
    Ok(())
}

fn settle(
    state: &V03State,
    execute: impl FnOnce(&mut PublicBackend<'_>) -> Result<PublicOutcome, LeeError>,
    block_id: BlockId,
    timestamp: Timestamp,
    cycle_budget: Cycles,
    cycles_used: &mut Cycles,
) -> Result<StateDiff, LeeError> {
    let mut backend = PublicBackend::new(state, cycle_budget, cycles_used);
    let PublicOutcome {
        block_validity_window,
        timestamp_validity_window,
        accounts,
        events,
        casts,
    } = execute(&mut backend)?;
    ensure!(
        block_validity_window.is_valid_for(block_id)
            && timestamp_validity_window.is_valid_for(timestamp),
        LeeError::OutOfValidityWindow
    );
    ensure!(
        u128::try_from(casts.len())
            .is_ok_and(|count| state.next_message_sequence().checked_add(count).is_some()),
        LeeError::InvalidInput("Message sequence exhausted".into())
    );
    let public_diff = accounts
        .into_iter()
        .map(|(account_id, data)| {
            let mut account = state.get_account_by_id(account_id);
            account.data.update(&data);
            (account_id, account)
        })
        .collect();
    let events = events
        .into_iter()
        .map(|(actor, event)| TransactionEvent {
            account_id: actor.program_account_id,
            event,
        })
        .collect();
    Ok(StateDiff {
        signer_account_ids: Vec::new(),
        public_diff,
        new_commitments: backend.into_outputs(),
        new_nullifiers: Vec::new(),
        events,
        consumed: Vec::new(),
        published: casts,
    })
}

pub fn sorted(ids: impl IntoIterator<Item = AccountId>) -> Vec<AccountId> {
    let mut ids: Vec<AccountId> = ids.into_iter().collect();
    ids.sort_unstable();
    ids
}

fn identity_account_ids(identities: &[PublicIdentity]) -> HashSet<AccountId> {
    identities.iter().map(PublicIdentity::account_id).collect()
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
    execution: &PrivacyPreservingCircuitOutput,
) -> Result<(), LeeError> {
    // Anchor each `Disclosed` claim to real chain state, reconstructing it independently rather
    // than trusting the message's own claim — a wrong claim means the reconstructed journal won't
    // match what the receipt actually committed to, so `proof.is_valid_for` fails below.
    // `Undisclosed`'s membership check already happened in-circuit; the one thing left to check
    // here is that its `root` is one the commitment tree has actually had.
    let program_image_claims = execution
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
        program_image_claims,
        ..execution.clone()
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
