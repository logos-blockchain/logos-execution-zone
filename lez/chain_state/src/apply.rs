//! The single validate-then-apply entry point shared by the sequencer and the
//! indexer. Pure and storage-free: callers apply on a scratch clone of state and
//! commit only on `Ok`.

use std::collections::HashSet;

use common::{
    HashType,
    block::{Block, BlockMeta},
    transaction::{
        LeeTransaction, TxEvents, clock_invocation, fee_invocation, fee_refund_invocation,
        fee_reserve_invocation, private_fee_refund_invocation, validate_user_state_modification,
    },
};
use fee_core::{
    BlockFeeSummary,
    assess::{FeeTxView, fee_actual_base, fee_reserve, private_fee_required},
    market,
    state::FeeState,
    validity::{FeeError, accumulate_exec_gas, accumulate_stor_gas, validate_static_tx},
};
use lee::{GENESIS_BLOCK_ID, V03State};
use lee_core::{BlockId, Timestamp, program::TransactionEvent};

use crate::{
    classify::{ClassifyError, FeeClass, classify},
    ingest_error::BlockIngestError,
};

/// The parent the next block must chain on.
// `l1_slot` will be added here when the `ChainState` anchor layer lands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tip {
    pub block_id: u64,
    pub hash: HashType,
}

impl From<&Block> for Tip {
    fn from(block: &Block) -> Self {
        Self {
            block_id: block.header.block_id,
            hash: block.header.hash,
        }
    }
}

impl From<BlockMeta> for Tip {
    fn from(meta: BlockMeta) -> Self {
        Self {
            block_id: meta.id,
            hash: meta.hash,
        }
    }
}

impl From<&Tip> for BlockMeta {
    fn from(tip: &Tip) -> Self {
        Self {
            id: tip.block_id,
            hash: tip.hash,
        }
    }
}

/// Outcome of feeding a parsed L2 block to a validated tip.
pub enum AcceptOutcome {
    /// Chained and applied; the tip advances.
    Applied(Vec<(BlockId, Vec<TxEvents>)>),
    /// A duplicate re-delivery of an already-applied block. No state change.
    AlreadyApplied,
    /// Did not chain or failed to apply; the tip stays frozen.
    Parked(BlockIngestError),
    /// Chained but failed to apply, possibly transiently
    /// ([`BlockIngestError::is_retryable`]); nothing recorded, tip and state
    /// untouched. The caller retries and parks once it gives up.
    ///
    /// TODO: Only the indexer's `accept_block` emits this today; the sequencer's
    /// `ChainState` parks on all failures without retrying (see `on_follow`).
    RetryableFailure(BlockIngestError),
}

/// Validates `block` against `tip`, then applies it to `state`.
///
/// Mutates `state` in place, so callers pass a scratch clone and commit on `Ok`.
pub fn apply_block(
    tip: Option<&Tip>,
    block: &Block,
    state: &mut V03State,
) -> Result<Vec<TxEvents>, BlockIngestError> {
    validate_against_tip(tip, block)?;
    apply_block_to_state(block, state)
}

/// Checks that `block` is the valid continuation of `tip`: hash integrity,
/// then block-id continuity, then `prev_block_hash` linkage. A `None` tip
/// (cold state) expects the genesis block.
pub fn validate_against_tip(tip: Option<&Tip>, block: &Block) -> Result<(), BlockIngestError> {
    let computed = block.recompute_hash();
    if computed != block.header.hash {
        return Err(BlockIngestError::HashMismatch {
            computed,
            header: block.header.hash,
        });
    }

    match tip {
        None => {
            if block.header.block_id != GENESIS_BLOCK_ID {
                return Err(BlockIngestError::UnexpectedBlockId {
                    expected: GENESIS_BLOCK_ID,
                    got: block.header.block_id,
                });
            }
        }
        Some(tip) => {
            let expected = tip
                .block_id
                .checked_add(1)
                .expect("block id should not overflow");
            if block.header.block_id != expected {
                return Err(BlockIngestError::UnexpectedBlockId {
                    expected,
                    got: block.header.block_id,
                });
            }
            if block.header.prev_block_hash != tip.hash {
                return Err(BlockIngestError::BrokenChainLink {
                    expected_prev: tip.hash,
                    got_prev: block.header.prev_block_hash,
                });
            }
        }
    }
    Ok(())
}

/// Applies a block's transactions to `state`, mapping every failure to a
/// [`BlockIngestError`] so the caller can park rather than crash. Operates in
/// place; the caller commits only on `Ok`.
///
/// On `Ok` also returns the indexed transaction events in emission order.
pub fn apply_block_to_state(
    block: &Block,
    state: &mut V03State,
) -> Result<Vec<TxEvents>, BlockIngestError> {
    let (clock_entry, front) = block
        .body
        .transactions
        .split_last()
        .ok_or(BlockIngestError::EmptyBlock)?;

    let LeeTransaction::Public(clock_tx) = clock_entry else {
        return Err(BlockIngestError::InvalidClockTransaction);
    };
    if *clock_tx != clock_invocation(block.header.block_id, block.header.timestamp) {
        return Err(BlockIngestError::InvalidClockTransaction);
    }

    let (fee_entry, user_txs) = front
        .split_last()
        .ok_or(BlockIngestError::InvalidFeeTransaction)?;
    let LeeTransaction::Public(fee_tx) = fee_entry else {
        return Err(BlockIngestError::InvalidFeeTransaction);
    };
    // The fee tx is byte-compared only after the user transactions have been
    // settled: its summary is derived from their execution.

    let opening = opening_fee_state(state);
    let mut summary = BlockFeeSummary::default();
    let mut block_events = Vec::new();

    let is_genesis = block.header.block_id == GENESIS_BLOCK_ID;
    for (tx_index, transaction) in user_txs.iter().enumerate() {
        let tx_index_u64 = u64::try_from(tx_index).expect("tx index fits in u64");
        let state_transition = |err: anyhow::Error| BlockIngestError::StateTransition {
            tx_index: tx_index_u64,
            reason: format!("{err:#}"),
        };

        // Genesis transactions transition directly; every other user transaction
        // settles its fee. Both surface the events their execution emitted.
        let events = if is_genesis {
            let LeeTransaction::Public(public_tx) = transaction else {
                return Err(BlockIngestError::NonPublicGenesisTransaction);
            };
            state
                .transition_from_public_transaction(
                    public_tx,
                    block.header.block_id,
                    block.header.timestamp,
                )
                .map_err(|err| state_transition(err.into()))?
        } else {
            settle_transaction(
                transaction,
                state,
                &opening,
                block.header.block_id,
                block.header.timestamp,
                tx_index_u64,
                &mut summary,
            )?
        };
        collect_tx_events(&mut block_events, tx_index, transaction, events);
    }

    // The forced fee transaction must carry exactly the summary this block's
    // settlement produced. Its reward target rides inside the tx; the
    // byte-compare pins the summary and tx shape. The producer chooses that
    // account freely, like a coinbase output, but it must not be a restricted
    // system account: the fee tx settles via the direct transition, bypassing
    // the user-tx restricted-account guards, so without this floor a producer
    // could credit the bridge and decouple its balance from L1 deposits.
    let payee = common::transaction::fee_invocation_payee(fee_tx)
        .ok_or(BlockIngestError::InvalidFeeTransaction)?;
    if *fee_tx != fee_invocation(summary, block_payout(&opening, &summary), payee) {
        return Err(BlockIngestError::InvalidFeeTransaction);
    }
    common::transaction::validate_reward_target(payee.producer())
        .map_err(|reason| BlockIngestError::InvalidRewardTarget { reason })?;

    let fee_events = state
        .transition_from_public_transaction(fee_tx, block.header.block_id, block.header.timestamp)
        .map_err(|err| BlockIngestError::StateTransition {
            tx_index: user_txs.len().try_into().expect("tx index fits in u64"),
            reason: format!("{:#}", anyhow::Error::from(err)),
        })?;
    collect_tx_events(&mut block_events, user_txs.len(), fee_entry, fee_events);

    // Clock events are collected separately. The clock program currently emits
    // none; this future-proofs the design with no bearing on current semantics.
    let clock_events = state
        .transition_from_public_transaction(clock_tx, block.header.block_id, block.header.timestamp)
        .map_err(|err| BlockIngestError::StateTransition {
            tx_index: (user_txs.len().saturating_add(1))
                .try_into()
                .expect("tx index fits in u64"),
            reason: format!("{:#}", anyhow::Error::from(err)),
        })?;
    collect_tx_events(
        &mut block_events,
        user_txs.len().saturating_add(1),
        clock_entry,
        clock_events,
    );

    Ok(block_events)
}

/// Collects a transaction's events into the block's event list, stamped with
/// the emitting transaction's index and hash.
fn collect_tx_events(
    block_events: &mut Vec<TxEvents>,
    tx_index: usize,
    transaction: &LeeTransaction,
    events: Vec<TransactionEvent>,
) {
    if events.is_empty() {
        return;
    }
    block_events.push(TxEvents {
        tx_index: tx_index.try_into().expect("tx index fits in u32"),
        tx_hash: transaction.hash(),
        events,
    });
}

/// Reads the fee state a block opening on `state` prices against.
///
/// A malformed fee-state account is consensus-critical corruption (only the
/// fee guest may write it), so the panic inside `from_bytes` is the
/// halt-the-node behavior the spec prescribes for consensus faults.
#[must_use]
pub fn opening_fee_state(state: &V03State) -> FeeState {
    FeeState::from_bytes(
        state
            .get_account_by_id(system_accounts::fee_state_account_id())
            .data
            .actor_state(system_accounts::fee_program_id()),
    )
}

/// The producer payout a block settling to `summary` pays out of the escrow.
///
/// The fee state is written only by the forced fee transaction, so the state a block opens on
/// is still the state that transaction applies against; the fee guest recomputes this against
/// it and refuses a proposal that does not match.
#[must_use]
pub fn block_payout(opening: &FeeState, summary: &BlockFeeSummary) -> u128 {
    opening.clone().apply_block(summary)
}

pub fn derive_block_summary(
    state: &V03State,
    transactions: &[LeeTransaction],
    block_id: BlockId,
    timestamp: Timestamp,
) -> Result<(BlockFeeSummary, u128), BlockIngestError> {
    let mut scratch = state.clone();
    let opening = opening_fee_state(&scratch);
    let mut summary = BlockFeeSummary::default();
    for (tx_index, transaction) in transactions.iter().enumerate() {
        settle_transaction(
            transaction,
            &mut scratch,
            &opening,
            block_id,
            timestamp,
            u64::try_from(tx_index).expect("tx index fits in u64"),
            &mut summary,
        )?;
    }
    let payout = block_payout(&opening, &summary);
    Ok((summary, payout))
}

/// Classifies and applies one user transaction at its turn, accumulating the
/// block summary.
///
/// Shared by the apply path (any `Err` invalidates the block), the sequencer's
/// builder (which runs it on a scratch clone and drops the transaction on
/// `Err`), and block-building test helpers.
pub fn settle_transaction(
    transaction: &LeeTransaction,
    state: &mut V03State,
    opening: &FeeState,
    block_id: BlockId,
    timestamp: Timestamp,
    tx_index: u64,
    summary: &mut BlockFeeSummary,
) -> Result<Vec<TransactionEvent>, BlockIngestError> {
    let class = classify(transaction, false).map_err(|err| match err {
        ClassifyError::Unserializable(err) => BlockIngestError::InvalidFeeClass {
            tx_index,
            reason: format!("unserializable transaction: {err}"),
        },
        ClassifyError::MissingFeeDeclaration => {
            BlockIngestError::MissingFeeDeclaration { tx_index }
        }
        ClassifyError::MissingPrivateFee => BlockIngestError::InvalidFeeClass {
            tx_index,
            reason: err.to_string(),
        },
    })?;
    let events = match class {
        FeeClass::Exempt => {
            let diff = transaction
                .compute_state_diff(state, block_id, timestamp)
                .map_err(|err| BlockIngestError::StateTransition {
                    tx_index,
                    reason: format!("{:#}", anyhow::Error::from(err)),
                })?;

            // A deposit or dispatch forged in the injection shape still passes;
            // only verifying it against its source can close that (#809).
            validate_user_state_modification(transaction, state, &diff).map_err(|err| {
                BlockIngestError::RestrictedAccountModification {
                    tx_index,
                    reason: err.to_string(),
                }
            })?;

            state
                .apply_state_diff(diff)
                .map_err(|err| BlockIngestError::StateTransition {
                    tx_index,
                    reason: format!("{:#}", anyhow::Error::from(err)),
                })?
        }
        FeeClass::Charged(view @ FeeTxView::Private { .. }) => settle_private_transaction(
            transaction,
            &view,
            state,
            opening,
            block_id,
            timestamp,
            tx_index,
            summary,
        )?,
        FeeClass::Charged(view) => settle_charged_transaction(
            transaction,
            &view,
            state,
            opening,
            block_id,
            timestamp,
            tx_index,
            summary,
        )?,
    };
    Ok(events)
}

/// Settles one private transaction against the reserve it paid inside its proof.
///
/// The actual fee is priced at the opening base fees and taken from the
/// reserve; a surplus above [`market::MIN_PRIVATE_REFUND`] is refunded to the
/// payer as a published message, a smaller one is kept as tip. Every failure
/// invalidates the transaction: fee and action share one proof, so there is no
/// revert that keeps the fee.
#[expect(
    clippy::too_many_arguments,
    reason = "the settlement threads exactly the block-transition context"
)]
fn settle_private_transaction(
    transaction: &LeeTransaction,
    view: &FeeTxView,
    state: &mut V03State,
    opening: &FeeState,
    block_id: BlockId,
    timestamp: Timestamp,
    tx_index: u64,
    summary: &mut BlockFeeSummary,
) -> Result<Vec<TransactionEvent>, BlockIngestError> {
    let fee_validity = |reason: String| BlockIngestError::InvalidFeeClass { tx_index, reason };
    let gas_cap = |err: FeeError| BlockIngestError::GasCapExceeded {
        tx_index,
        reason: err.to_string(),
    };
    let (LeeTransaction::PrivacyPreserving(private_tx), FeeTxView::Private { payer, reserve }) =
        (transaction, view)
    else {
        unreachable!("only private transactions classify as a private fee view");
    };

    validate_static_tx(view, opening).map_err(|err| fee_validity(err.to_string()))?;

    // The verification cost is charged up front; the effects may use what is
    // left of the block's execution gas.
    let gas_used_exec =
        accumulate_exec_gas(summary.gas_used_exec, market::PRIVATE_VERIFY_GAS).map_err(gas_cap)?;
    let gas_used_stor =
        accumulate_stor_gas(summary.gas_used_stor, market::PRIVATE_GAS_STOR).map_err(gas_cap)?;
    let cycle_budget = market::MAX_GAS_EXEC
        .checked_sub(gas_used_exec)
        .expect("the accumulator is cap-checked");
    let (diff, effect_cycles) =
        lee::ValidatedStateDiff::from_privacy_preserving_transaction_metered(
            private_tx,
            state,
            block_id,
            timestamp,
            cycle_budget,
        )
        .map_err(|err| BlockIngestError::StateTransition {
            tx_index,
            reason: format!("{:#}", anyhow::Error::from(err)),
        })?;
    let gas_used_exec = accumulate_exec_gas(gas_used_exec, effect_cycles).map_err(gas_cap)?;

    let actual = private_fee_required(effect_cycles, opening.base_fee_exec, opening.base_fee_stor);
    let surplus = reserve.checked_sub(actual).ok_or_else(|| {
        fee_validity(
            FeeError::PrivateFeeBelowRequired {
                required: actual,
                reserve: *reserve,
            }
            .to_string(),
        )
    })?;

    validate_user_state_modification(transaction, state, &diff).map_err(|err| {
        BlockIngestError::RestrictedAccountModification {
            tx_index,
            reason: err.to_string(),
        }
    })?;
    let events = state
        .apply_state_diff(diff)
        .map_err(|err| fee_validity(format!("private action failed: {err}")))?;

    // A surplus worth a note goes back to the payer, if a recovery binding lets it be
    // published there; dust and an unbound payer's surplus stay as tip.
    let (refund, tip) =
        if surplus > market::MIN_PRIVATE_REFUND && state.recovery_binding(*payer).is_some() {
            (surplus, 0)
        } else {
            (0, surplus)
        };
    if refund > 0 {
        let refund_msg = private_fee_refund_invocation(*payer, refund);
        let refund_diff = lee::ValidatedStateDiff::from_fee_settlement_invocation(
            refund_msg.execution.root.to,
            &refund_msg.execution.root.message,
            &refund_msg.public_context.actors,
            &HashSet::new(),
            state,
            block_id,
            timestamp,
        )
        .map_err(|err| fee_validity(format!("private fee refund failed: {err}")))?;
        state
            .apply_state_diff(refund_diff)
            .map_err(|err| fee_validity(format!("private fee refund failed: {err}")))?;
    }

    summary.gas_used_exec = gas_used_exec;
    summary.gas_used_stor = gas_used_stor;
    summary.revenue_base = summary
        .revenue_base
        .checked_add(actual)
        .expect("block revenue fits u128");
    summary.revenue_tip = summary
        .revenue_tip
        .checked_add(tip)
        .expect("block tips fit u128");
    Ok(events)
}

/// The reserve → action → refund cycle for one charged transaction.
///
/// The two failure modes sit on opposite sides of the line on purpose:
/// - A precondition failure (unaffordable reserve, missing authorization, malformed signatures)
///   means the transaction should never have been *included* — a correct proposer would not build
///   this block, so the whole block is invalid.
/// - A failed *action* is ordinary execution semantics: the transaction was validly included and
///   paid its fee, its effects just did not take. It reverts, keeping the fee and burning the
///   signers' replay nonces.
#[expect(
    clippy::too_many_arguments,
    reason = "the settlement threads exactly the block-transition context the spec names"
)]
fn settle_charged_transaction(
    transaction: &LeeTransaction,
    view: &FeeTxView,
    state: &mut V03State,
    opening: &FeeState,
    block_id: BlockId,
    timestamp: Timestamp,
    tx_index: u64,
    summary: &mut BlockFeeSummary,
) -> Result<Vec<TransactionEvent>, BlockIngestError> {
    let fee_validity = |reason: String| BlockIngestError::InvalidFeeClass { tx_index, reason };
    let (LeeTransaction::Public(public_tx), FeeTxView::Public { payer, .. }) = (transaction, view)
    else {
        unreachable!("only public transactions classify as a public fee view");
    };
    let payer = *payer;

    validate_static_tx(view, opening).map_err(|err| fee_validity(err.to_string()))?;
    if !lee::is_fee_authorized(public_tx.message(), public_tx.witness_set()) {
        return Err(fee_validity(
            "designated payer's authorization is missing".into(),
        ));
    }

    // Phase 1: Reserve
    //
    // hold `reserved` from the payer in the inbox via a native transfer,
    // authorized by the fee declaration.
    //
    // This does NOT advance the nonce, invalidates the tx if the payer cannot afford it.
    let reserved = fee_reserve(view, opening);
    let reserve_msg = fee_reserve_invocation(payer, reserved);
    let payer_authorized = HashSet::from([payer]);
    let reserve_diff = lee::ValidatedStateDiff::from_fee_settlement_invocation(
        reserve_msg.execution.root.to,
        &reserve_msg.execution.root.message,
        &reserve_msg.public_context.actors,
        &payer_authorized,
        state,
        block_id,
        timestamp,
    )
    .map_err(|err| fee_validity(format!("fee reserve failed: {err}")))?;
    // Reserve is a fee-internal move; its events are not the user's.
    state
        .apply_state_diff(reserve_diff)
        .map_err(|err| fee_validity(format!("fee reserve failed: {err}")))?;

    // Phase 2: Action
    //
    // Runs the metered execution at `gas_limit`. The returned diff carries the
    // action's effects on success or only the signers' nonce advances on a
    // revert; either way the reserved fee stays committed. An authentication
    // failure is a malformed transaction that invalidates the whole block.
    let gas_limit = view.gas_limit();
    let (charge, result) = lee::ValidatedStateDiff::from_public_transaction_metered(
        public_tx, state, block_id, timestamp, gas_limit,
    );
    let action_diff = result.map_err(|err| fee_validity(format!("fee action failed: {err}")))?;
    // r0 cycle count can overshoot, clamp to `gas_limit`
    let charged_cycles = charge.cycles.min(gas_limit);

    summary.gas_used_exec =
        accumulate_exec_gas(summary.gas_used_exec, charged_cycles).map_err(|err| {
            BlockIngestError::GasCapExceeded {
                tx_index,
                reason: err.to_string(),
            }
        })?;
    summary.gas_used_stor =
        accumulate_stor_gas(summary.gas_used_stor, view.gas_stor()).map_err(|err| {
            BlockIngestError::GasCapExceeded {
                tx_index,
                reason: err.to_string(),
            }
        })?;

    // A reverted action's diff is nonce-only; a successful one is held to the user-state guard.
    validate_user_state_modification(transaction, state, &action_diff).map_err(|err| {
        BlockIngestError::RestrictedAccountModification {
            tx_index,
            reason: err.to_string(),
        }
    })?;
    // The action's events are the transaction's user-facing events.
    let action_events = state
        .apply_state_diff(action_diff)
        .map_err(|err| fee_validity(format!("fee action failed: {err}")))?;

    // Phase 3: Refund
    //
    // Return the unspent reserve to the payer via the fee program,
    // leaving the inbox holding exactly this transaction's actual fee.
    let fee_base = fee_actual_base(charged_cycles, view, opening);
    let fee_total = fee_base
        .checked_add(u128::from(view.tip()))
        .expect("fee_base + tip fits u128");
    let refund = reserved
        .checked_sub(fee_total)
        .expect("the reserve prices gas_limit, which bounds the actual fee");
    if refund > 0 {
        let refund_msg = fee_refund_invocation(payer, refund);
        let refund_diff = lee::ValidatedStateDiff::from_fee_settlement_invocation(
            refund_msg.execution.root.to,
            &refund_msg.execution.root.message,
            &refund_msg.public_context.actors,
            &HashSet::new(),
            state,
            block_id,
            timestamp,
        )
        .map_err(|err| fee_validity(format!("fee refund failed: {err}")))?;
        // Refund is a fee-internal move; its events are not the user's.
        state
            .apply_state_diff(refund_diff)
            .map_err(|err| fee_validity(format!("fee refund failed: {err}")))?;
    }

    summary.revenue_base = summary
        .revenue_base
        .checked_add(fee_base)
        .expect("block revenue fits u128");
    summary.revenue_tip = summary
        .revenue_tip
        .checked_add(u128::from(view.tip()))
        .expect("block tips fit u128");
    Ok(action_events)
}

#[cfg(test)]
mod tests {
    use std::{
        borrow::Cow,
        collections::{BTreeMap, BTreeSet},
    };

    use common::{
        block::HashableBlockData,
        test_utils::{
            create_transaction_native_token_transfer, produce_dummy_block,
            produce_dummy_empty_transaction, producer_account_for_testing, test_fee_declaration,
        },
        transaction::FeePayee,
    };
    use lee::{
        AccountId, Actor, PublicTransaction, RootCall, TransactionEntry,
        privacy_preserving_transaction::circuit::ProgramCatalog,
        program::Program,
        public_transaction,
        test_utils::{TestPrivateKeys, no_seal, update_witness},
    };
    use lee_core::{
        EphemeralSecretKey, PrivateAccountKind, Recipient, RecipientEncryption, SenderPresentation,
        account::Nonce,
        native_token,
        program::{ProgramEvent, Publication, Response},
    };
    use test_guest_core::Script;
    use testnet_initial_state::{initial_pub_accounts_private_keys, initial_state};

    use super::*;

    /// The alias a private sender presents under; its opening is bound for refunds.
    const ALIAS_OPENING: [u8; 32] = [9; 32];

    #[must_use]
    const fn event_emitter() -> Program {
        Program::new_unchecked(
            test_methods::SCRIPTED_ID,
            Cow::Borrowed(test_methods::SCRIPTED_ELF),
        )
    }

    fn emitted(n: u8) -> ProgramEvent {
        ProgramEvent {
            selector: [n; 8],
            data: vec![n; 4],
        }
    }

    fn tip_of(block: &Block) -> Tip {
        Tip::from(block)
    }

    #[test]
    fn genesis_applies_on_empty_tip() {
        let mut state = initial_state(true);
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
    }

    #[test]
    fn non_genesis_first_block_is_unexpected_id() {
        let mut state = initial_state(true);
        let block = produce_dummy_block(2, None, vec![]);
        let err = apply_block(None, &block, &mut state).expect_err("should reject");
        assert!(matches!(
            err,
            BlockIngestError::UnexpectedBlockId {
                expected: 1,
                got: 2
            }
        ));
    }

    #[test]
    fn skip_ahead_block_is_unexpected_id() {
        let mut state = initial_state(true);
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");

        // Tip is at 1; a block with id 3 skips ahead.
        let bad = produce_dummy_block(3, Some(genesis.header.hash), vec![]);
        let err =
            apply_block(Some(&tip_of(&genesis)), &bad, &mut state).expect_err("should reject");
        assert!(matches!(
            err,
            BlockIngestError::UnexpectedBlockId {
                expected: 2,
                got: 3
            }
        ));
    }

    #[test]
    fn broken_chain_link_detected() {
        let mut state = initial_state(true);
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");

        // Correct id (2), wrong parent hash.
        let block2 = produce_dummy_block(2, Some(HashType([9_u8; 32])), vec![]);
        let err =
            apply_block(Some(&tip_of(&genesis)), &block2, &mut state).expect_err("should reject");
        assert!(matches!(err, BlockIngestError::BrokenChainLink { .. }));
    }

    #[test]
    fn hash_mismatch_detected() {
        let mut state = initial_state(true);
        let mut genesis = produce_dummy_block(1, None, vec![]);
        // Tampering with the header invalidates the stored hash.
        genesis.header.timestamp = 999;
        let err = apply_block(None, &genesis, &mut state).expect_err("should reject");
        assert!(matches!(err, BlockIngestError::HashMismatch { .. }));
    }

    #[test]
    fn empty_block_rejected() {
        let mut state = initial_state(true);
        // A block with no transactions at all (not even the mandatory clock tx).
        let block = HashableBlockData {
            block_id: 1,
            prev_block_hash: HashType([0_u8; 32]),
            timestamp: 0,
            transactions: vec![],
        }
        .into_pending_block();
        let err = apply_block(None, &block, &mut state).expect_err("should reject");
        assert!(matches!(err, BlockIngestError::EmptyBlock));
    }

    #[test]
    fn fee_state_advances_with_the_chain() {
        let mut state = initial_state(true);
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        let mut tip = tip_of(&genesis);
        for id in 2..=5_u64 {
            let block = produce_dummy_block(id, Some(tip.hash), vec![]);
            apply_block(Some(&tip), &block, &mut state).expect("block applies");
            tip = tip_of(&block);
        }

        let fee_state = fee_core::state::FeeState::from_bytes(
            state
                .get_account_by_id(system_accounts::fee_state_account_id())
                .data
                .actor_state(system_accounts::fee_program_id()),
        );
        // Five blocks applied: height tracks the chain; zero load holds the floor.
        assert_eq!(fee_state.height, 5);
        assert_eq!(fee_state.base_fee_exec, fee_core::market::BASE_FEE_EXEC_MIN);
        assert_eq!(fee_state.base_fee_stor, fee_core::market::BASE_FEE_STOR_MIN);
        assert_eq!(fee_state.payout_carry, 0);
        // Escrow and inbox hold no balance.
        assert_eq!(
            state
                .get_account_by_id(system_accounts::fee_escrow_account_id())
                .data
                .native_balance()
                .unwrap(),
            0
        );
        assert_eq!(
            state
                .get_account_by_id(system_accounts::fee_inbox_account_id())
                .data
                .native_balance()
                .unwrap(),
            0
        );
    }

    #[test]
    fn missing_fee_tx_is_invalid_fee() {
        let mut state = initial_state(true);
        // Correct clock tail but no fee tx before it.
        let block = HashableBlockData {
            block_id: 1,
            prev_block_hash: HashType([0_u8; 32]),
            timestamp: 100,
            transactions: vec![
                produce_dummy_empty_transaction(),
                LeeTransaction::Public(clock_invocation(1, 100)),
            ],
        }
        .into_pending_block();
        let err = apply_block(None, &block, &mut state).expect_err("should reject");
        assert!(matches!(err, BlockIngestError::InvalidFeeTransaction));
    }

    #[test]
    fn nonzero_fee_summary_is_invalid_fee() {
        let mut state = initial_state(true);
        let bad_summary = fee_core::BlockFeeSummary {
            gas_used_exec: 1,
            ..fee_core::BlockFeeSummary::default()
        };
        let block = HashableBlockData {
            block_id: 1,
            prev_block_hash: HashType([0_u8; 32]),
            timestamp: 100,
            transactions: vec![
                LeeTransaction::Public(fee_invocation(
                    bad_summary,
                    0,
                    FeePayee::Present(producer_account_for_testing()),
                )),
                LeeTransaction::Public(clock_invocation(1, 100)),
            ],
        }
        .into_pending_block();
        let err = apply_block(None, &block, &mut state).expect_err("should reject");
        assert!(matches!(err, BlockIngestError::InvalidFeeTransaction));
    }

    #[test]
    fn missing_clock_tail_is_invalid_clock() {
        let mut state = initial_state(true);
        // Last tx is not the expected clock invocation for the timestamp.
        let block = HashableBlockData {
            block_id: 1,
            prev_block_hash: HashType([0_u8; 32]),
            timestamp: 50,
            transactions: vec![produce_dummy_empty_transaction()],
        }
        .into_pending_block();
        let err = apply_block(None, &block, &mut state).expect_err("should reject");
        assert!(matches!(err, BlockIngestError::InvalidClockTransaction));
    }

    #[test]
    fn applies_transfers_and_advances_state() {
        // The producer's reward account is claimed from genesis, simulating the
        // stake a real sequencer holds before producing, so the charged blocks
        // below can credit it (crediting an unclaimed account is rejected).
        let mut state =
            initial_state(true).with_public_accounts([common::test_utils::producer_seed()]);
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();
        let initial_from = state.get_account_by_id(from).data.native_balance().unwrap();
        let initial_to = state.get_account_by_id(to).data.native_balance().unwrap();

        // Genesis (block 1): fee/clock only.
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        let mut tip = tip_of(&genesis);

        // Blocks 2..=11: one charged native transfer of 10 each (nonces 0..=9).
        for i in 0..10_u64 {
            let tx = create_transaction_native_token_transfer(from, i.into(), to, 10, &sign_key);
            let block = settled_block(i + 2, tip.hash, vec![tx], &state);
            apply_block(Some(&tip), &block, &mut state).expect("transfer applies");
            tip = tip_of(&block);
        }

        // The recipient gained exactly the transferred amount; the sender lost
        // it plus real fees; every fee unit is accounted for in the fee flow:
        // the inbox drained each block, so all revenue sits in escrow plus what
        // the guest already paid the producer.
        assert_eq!(
            state.get_account_by_id(to).data.native_balance().unwrap(),
            initial_to + 100
        );
        let from_final = state.get_account_by_id(from).data.native_balance().unwrap();
        let fees_paid = initial_from - 100 - from_final;
        assert!(fees_paid > 0, "charged transfers must pay a nonzero fee");

        let producer = producer_account_for_testing();
        let escrow = state
            .get_account_by_id(system_accounts::fee_escrow_account_id())
            .data
            .native_balance()
            .unwrap();
        let producer_balance = state
            .get_account_by_id(producer)
            .data
            .native_balance()
            .unwrap();
        let inbox = state
            .get_account_by_id(system_accounts::fee_inbox_account_id())
            .data
            .native_balance()
            .unwrap();
        assert_eq!(inbox, 0, "the inbox must drain every block");
        assert_eq!(
            fees_paid,
            escrow + producer_balance,
            "all fees flow to escrow plus the producer",
        );
        assert!(
            producer_balance > 0,
            "smoothed payouts must have started paying the producer",
        );
    }

    #[test]
    fn a_user_fee_program_invocation_cannot_drain_the_inbox() {
        // Critical A: the forced fee invocation is the block tail, byte-compared
        // separately, so any fee-program call in the user section is
        // illegitimate. Left unguarded on the apply path, a block author could
        // invoke the fee program's Refund to sweep the inbox to an attacker
        // account, and honest followers would apply the block. The apply-path
        // guard must reject it.
        let mut state = initial_state(true);
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");

        let accounts = initial_pub_accounts_private_keys();
        let attacker = accounts[0].account_id;
        let attacker_key = accounts[0].pub_sign_key.clone();
        let recipient = accounts[1].account_id;

        let opening = FeeState::from_bytes(
            state
                .get_account_by_id(system_accounts::fee_state_account_id())
                .data
                .actor_state(system_accounts::fee_program_id()),
        );

        // Accrue real revenue in the inbox with one legitimate charged transfer.
        let mut summary = BlockFeeSummary::default();
        let transfer =
            create_transaction_native_token_transfer(attacker, 0, recipient, 10, &attacker_key);
        settle_transaction(&transfer, &mut state, &opening, 2, 200, 0, &mut summary)
            .expect("the legitimate transfer settles");
        let inbox_revenue = state
            .get_account_by_id(system_accounts::fee_inbox_account_id())
            .data
            .native_balance()
            .unwrap();
        assert!(inbox_revenue > 0, "the transfer must have funded the inbox");

        // The drain: invoke the fee program's Refund to sweep the accrued inbox
        // revenue to the attacker. The guest accepts it — the fee program owns
        // the inbox it debits — producing a diff that modifies the restricted
        // inbox, which the apply-path guard must reject.
        let fee_state = fee_invocation(BlockFeeSummary::default(), 0, FeePayee::Present(attacker))
            .message()
            .execution
            .root
            .to;
        let message = lee::public_transaction::Message::try_new_with_fees(
            fee_state,
            vec![
                fee_state,
                lee::Actor::native_balance(system_accounts::fee_inbox_account_id()),
                lee::Actor::native_balance(attacker),
            ],
            BTreeMap::from([(attacker, state.get_account_by_id(attacker).nonce)]),
            fee_core::Message::Refund {
                amount: inbox_revenue,
                payer: attacker,
            },
            common::test_utils::test_fee_declaration(attacker),
        )
        .expect("drain message builds");
        let witness = lee::public_transaction::WitnessSet::for_message(&message, &[&attacker_key]);
        let drain = LeeTransaction::Public(lee::PublicTransaction::new(message, witness));

        let mut drain_acc = BlockFeeSummary::default();
        let err = settle_transaction(&drain, &mut state, &opening, 3, 200, 1, &mut drain_acc)
            .expect_err("a user-section fee-program invocation must be rejected");
        assert!(
            matches!(err, BlockIngestError::RestrictedAccountModification { .. }),
            "expected RestrictedAccountModification, got {err:?}",
        );
    }

    #[test]
    fn a_signed_public_transfer_without_a_fee_is_rejected_not_executed_for_free() {
        // Exempt means executed-and-included for free. If a fee-less public
        // transfer were classified exempt, any signer could opt out of fees by
        // dropping the declaration. A correctly-signed transfer that omits the
        // fee must be rejected outright, and must move nothing.
        let mut state = initial_state(true);
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");

        let accounts = initial_pub_accounts_private_keys();
        let sender = accounts[0].account_id;
        let sender_key = accounts[0].pub_sign_key.clone();
        let recipient = accounts[1].account_id;

        let opening = FeeState::from_bytes(
            state
                .get_account_by_id(system_accounts::fee_state_account_id())
                .data
                .actor_state(system_accounts::fee_program_id()),
        );
        let sender_before = state
            .get_account_by_id(sender)
            .data
            .native_balance()
            .unwrap();
        let recipient_before = state
            .get_account_by_id(recipient)
            .data
            .native_balance()
            .unwrap();

        let free = common::test_utils::create_transaction_native_token_transfer_without_fee(
            sender,
            0,
            recipient,
            10,
            &sender_key,
        );
        let mut summary = BlockFeeSummary::default();
        let err = settle_transaction(&free, &mut state, &opening, 2, 200, 0, &mut summary)
            .expect_err("a fee-less public transfer must be rejected");
        assert!(
            matches!(err, BlockIngestError::MissingFeeDeclaration { .. }),
            "expected MissingFeeDeclaration, got {err:?}",
        );
        // The rejection happens before any state mutation: nothing moved.
        assert_eq!(
            state
                .get_account_by_id(sender)
                .data
                .native_balance()
                .unwrap(),
            sender_before
        );
        assert_eq!(
            state
                .get_account_by_id(recipient)
                .data
                .native_balance()
                .unwrap(),
            recipient_before
        );
    }

    #[test]
    fn a_charged_action_that_reverts_is_charged_not_block_rejected() {
        let mut state = initial_state(true);
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");

        let accounts = initial_pub_accounts_private_keys();
        let payer = accounts[0].account_id;
        let payer_key = accounts[0].pub_sign_key.clone();
        let recipient = accounts[1].account_id;

        let opening = FeeState::from_bytes(
            state
                .get_account_by_id(system_accounts::fee_state_account_id())
                .data
                .actor_state(system_accounts::fee_program_id()),
        );

        let payer_before = state
            .get_account_by_id(payer)
            .data
            .native_balance()
            .unwrap();
        let payer_nonce_before = u128::from(state.get_account_by_id(payer).nonce);
        let recipient_before = state
            .get_account_by_id(recipient)
            .data
            .native_balance()
            .unwrap();

        // Move more than the payer owns: the guest's `checked_sub` panics, so the
        // action reverts after the reserve has already been taken.
        let over_balance = payer_before.checked_add(1).expect("balance + 1 fits u128");
        let tx = create_transaction_native_token_transfer(
            payer,
            payer_nonce_before,
            recipient,
            over_balance,
            &payer_key,
        );

        let mut summary = BlockFeeSummary::default();
        let events = settle_transaction(&tx, &mut state, &opening, 2, 200, 0, &mut summary)
            .expect("a reverted action is charged, not block-rejected");
        assert!(events.is_empty(), "a reverted action emits no user events");

        // The transfer moved nothing.
        assert_eq!(
            state
                .get_account_by_id(recipient)
                .data
                .native_balance()
                .unwrap(),
            recipient_before
        );
        // The nonce advanced, so the transaction cannot be replayed.
        assert_eq!(
            u128::from(state.get_account_by_id(payer).nonce),
            payer_nonce_before
                .checked_add(1)
                .expect("nonce + 1 fits u128"),
        );
        // The fee was charged: the payer paid, and it accrued as real revenue.
        assert!(
            state
                .get_account_by_id(payer)
                .data
                .native_balance()
                .unwrap()
                < payer_before,
            "the reverted action still pays a fee",
        );
        assert!(
            summary.revenue_base > 0,
            "the charged revert accrues real fee revenue",
        );
    }

    #[test]
    fn a_non_genesis_block_rewarding_a_system_account_is_rejected() {
        let mut state = initial_state(true);
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        let tip = tip_of(&genesis);

        // A non-genesis block whose forced fee tx credits the bridge — a system
        // account — must be rejected before the fee settlement runs.
        let block = settled_block_rewarding(
            2,
            tip.hash,
            vec![],
            &state,
            FeePayee::Present(system_accounts::bridge_account_id()),
        );
        let err = apply_block(Some(&tip), &block, &mut state)
            .expect_err("a reward to a system account is rejected");
        assert!(matches!(err, BlockIngestError::InvalidRewardTarget { .. }));
    }

    #[test]
    fn a_block_crediting_an_absent_producer_it_cannot_reach_is_rejected() {
        let mut state = initial_state(true);
        let accounts = initial_pub_accounts_private_keys();
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        let tip = tip_of(&genesis);
        let producer = common::test_utils::producer_account_for_testing();
        // Its tip makes the fee transaction credit the producer.
        let transfer = common::test_utils::create_transaction_native_token_transfer_with_fees(
            accounts[0].account_id,
            0,
            accounts[1].account_id,
            10,
            &accounts[0].pub_sign_key,
            lee::FeeDeclaration::new(accounts[0].account_id, 2_000_000, 1, u128::MAX >> 1),
        );

        for (payee, refusal) in [
            (
                FeePayee::Present(producer),
                "declared public but not admitted",
            ),
            (FeePayee::Bound(producer), "without a recovery binding"),
        ] {
            let block = settled_block_rewarding(2, tip.hash, vec![transfer.clone()], &state, payee);
            let err = apply_block(Some(&tip), &block, &mut state.clone())
                .expect_err("an absent, unbound producer cannot be paid");

            assert!(matches!(
                err,
                BlockIngestError::StateTransition { reason, .. } if reason.contains(refusal)
            ));
        }
    }

    #[test]
    fn creates_events_for_transactions() {
        // The producer's reward account is claimed from genesis, simulating the
        // stake a real sequencer holds before producing, so the charged blocks
        // below can credit it (crediting an unclaimed account is rejected).
        let mut state = initial_state(true)
            .with_public_accounts([common::test_utils::producer_seed()])
            .with_programs(vec![event_emitter()]);

        // Genesis (block 1): fee/clock only.
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        let tip = tip_of(&genesis);

        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();
        let emitter_id = AccountId::from_builtin_program(event_emitter().id());

        let emitter = Actor::new(from, emitter_id);
        let message = public_transaction::Message::try_new_with_fees(
            emitter,
            vec![emitter],
            BTreeMap::from([(from, Nonce(0))]),
            Script {
                response: Response::keep_state().event(emitted(5)),
                ..Script::default()
            },
            test_fee_declaration(from),
        )
        .expect("test instruction must serialize");
        let witness_set = public_transaction::WitnessSet::for_message(&message, &[&sign_key]);
        let pub_tx = PublicTransaction::new(message, witness_set).into();

        let block = settled_block(2, tip.hash, vec![pub_tx], &state);
        let events = apply_block(Some(&tip), &block, &mut state).expect("transfer applies");

        assert_eq!(events.len(), 1, "There should be exactly one event emitted");
        assert_eq!(
            events[0].events.len(),
            1,
            "There should be exactly one transaction event emitted"
        );
        assert_eq!(events[0].events[0].event.data, vec![5; 4]);
        assert_eq!(events[0].events[0].event.selector, [5; 8]);
    }

    /// A funded private sender next to the initial state, for in-proof fee tests.
    fn private_sender_state(seeds: &[u8]) -> (V03State, Vec<(TestPrivateKeys, lee::Account)>) {
        let senders: Vec<_> = seeds
            .iter()
            .map(|&seed| {
                (
                    TestPrivateKeys {
                        ask: lee_core::AuthorizationSecretKey([seed; 32]),
                        d: [seed.wrapping_add(1); 32],
                        z: [seed.wrapping_add(2); 32],
                    },
                    lee::Account::funded(1_000_000_000),
                )
            })
            .collect();
        let state =
            initial_state(true).with_private_accounts(senders.iter().map(|(keys, account)| {
                (
                    lee_core::Commitment::new(&keys.account_id(), account),
                    lee_core::Nullifier::for_account_initialization(
                        &keys.account_id(),
                        &keys.nsk(),
                    ),
                )
            }));
        (state, senders)
    }

    /// A deshielding transfer of `amount` from the private `sender` to a public `recipient`,
    /// paying `fee` inside the proof from the sender presented under [`ALIAS_OPENING`].
    fn private_tx(
        state: &V03State,
        sender: &(TestPrivateKeys, lee::Account),
        recipient: AccountId,
        amount: u128,
        fee: Option<lee_core::FeeTransfer>,
    ) -> LeeTransaction {
        private_tx_presented(state, sender, recipient, amount, fee, true)
    }

    /// [`private_tx`] with the sender presented under its alias and bound for refunds, or
    /// canonically and unbound.
    fn private_tx_presented(
        state: &V03State,
        (keys, funded): &(TestPrivateKeys, lee::Account),
        recipient: AccountId,
        amount: u128,
        fee: Option<lee_core::FeeTransfer>,
        bound: bool,
    ) -> LeeTransaction {
        let public_actors = vec![
            Actor::native_balance(recipient),
            Actor::native_balance(system_accounts::fee_inbox_account_id()),
        ];
        let public_actor_states = public_actors
            .iter()
            .map(|actor| {
                (
                    *actor,
                    state
                        .get_account_by_id(actor.account_id)
                        .data
                        .actor_state(actor.program_account_id)
                        .clone(),
                )
            })
            .collect();
        let membership_proof = state
            .get_proof_for_commitment(&lee_core::Commitment::new(&keys.account_id(), funded))
            .expect("the sender's commitment is in state");
        let (output, proof) = lee::execute_and_prove(
            lee::ProvingInput {
                root: TransactionEntry::Sync(RootCall {
                    to: Actor::native_balance(keys.account_id()),
                    message: borsh::to_vec(&native_token::Message::Transfer {
                        to: recipient,
                        amount,
                    })
                    .unwrap(),
                }),
                fee,
                public_context: lee::PublicExecutionContext::new(public_actors, []),
                private_witnesses: vec![update_witness(keys, funded.clone(), membership_proof)],
                dummy_inputs: Vec::new(),
                ciphertext_padding: None,
                recoveries: bound
                    .then(|| RecipientEncryption {
                        recipient: Recipient {
                            npk: keys.npk(),
                            vpk: keys.vpk(),
                            kind: PrivateAccountKind::Regular,
                            opening: Some(ALIAS_OPENING),
                        },
                        esk: EphemeralSecretKey([1; 32]),
                    })
                    .into_iter()
                    .collect(),
                private_promotions: BTreeSet::new(),
            },
            &lee::Simulation {
                public_actor_states,
                admitted_accounts: None,
            },
            &ProgramCatalog::default(),
            |_| {
                if bound {
                    SenderPresentation::Blinded(ALIAS_OPENING)
                } else {
                    SenderPresentation::Canonical
                }
            },
            |_, _| false,
            no_seal,
        )
        .expect("the private transfer proves");
        let message = lee::privacy_preserving_transaction::Message::from_circuit_output(
            BTreeMap::new(),
            output,
        );
        LeeTransaction::PrivacyPreserving(lee::PrivacyPreservingTransaction::new(
            message,
            lee::privacy_preserving_transaction::WitnessSet::from_raw_parts(vec![], proof),
        ))
    }

    fn inbox_fee(amount: u128, payer: AccountId) -> lee_core::FeeTransfer {
        lee_core::FeeTransfer {
            payer,
            recipient: system_accounts::fee_inbox_account_id(),
            amount,
        }
    }

    fn native_balance(state: &V03State, account_id: AccountId) -> u128 {
        state
            .get_account_by_id(account_id)
            .data
            .native_balance()
            .unwrap()
    }

    /// The native credit published to `alias`, if any.
    fn published_credit(state: &V03State, alias: AccountId) -> Option<u128> {
        state
            .publications_from(0)
            .find_map(|(_, publication)| match publication {
                Publication::Clear { body, .. } if body.to == Actor::native_balance(alias) => {
                    match borsh::from_slice(&body.message).unwrap() {
                        native_token::Message::Credit(amount) => Some(amount),
                        native_token::Message::Transfer { .. }
                        | native_token::Message::ReadState => None,
                    }
                }
                Publication::Clear { .. } | Publication::Sealed(_) => None,
            })
    }

    #[test]
    fn a_private_transaction_pays_its_actual_fee_and_is_refunded_the_surplus() {
        let (state, senders) = private_sender_state(&[0x51]);
        let sender = &senders[0];
        let alias = sender.0.account_id().blinded(&ALIAS_OPENING);
        let recipient = initial_pub_accounts_private_keys()[0].account_id;
        let required = fee_core::assess::private_fee_required(0, 8, 8);
        let surplus = fee_core::market::MIN_PRIVATE_REFUND + 1;
        let tx = private_tx(
            &state,
            sender,
            recipient,
            10,
            Some(inbox_fee(required + surplus, sender.0.account_id())),
        );
        let recipient_pre = native_balance(&state, recipient);

        let mut settled = state;
        let mut summary = BlockFeeSummary::default();
        settle_transaction(
            &tx,
            &mut settled,
            &FeeState::genesis(),
            1,
            100,
            0,
            &mut summary,
        )
        .expect("a reserve covering the fee settles");
        assert_eq!(summary.gas_used_exec, fee_core::market::PRIVATE_VERIFY_GAS);
        assert_eq!(summary.gas_used_stor, fee_core::market::PRIVATE_GAS_STOR);
        assert_eq!(summary.revenue_base, required);
        assert_eq!(summary.revenue_tip, 0);
        // The inbox keeps the actual fee; the surplus is published back to the alias.
        assert_eq!(
            native_balance(&settled, system_accounts::fee_inbox_account_id()),
            required
        );
        assert_eq!(native_balance(&settled, recipient), recipient_pre + 10);
        assert_eq!(published_credit(&settled, alias), Some(surplus));
    }

    #[test]
    fn an_unbound_payers_surplus_is_kept_as_tip() {
        let (state, senders) = private_sender_state(&[0x56]);
        let sender = &senders[0];
        let recipient = initial_pub_accounts_private_keys()[0].account_id;
        let required = fee_core::assess::private_fee_required(0, 8, 8);
        let surplus = fee_core::market::MIN_PRIVATE_REFUND + 1;
        let tx = private_tx_presented(
            &state,
            sender,
            recipient,
            10,
            Some(inbox_fee(required + surplus, sender.0.account_id())),
            false,
        );

        let mut settled = state;
        let mut summary = BlockFeeSummary::default();
        settle_transaction(
            &tx,
            &mut settled,
            &FeeState::genesis(),
            1,
            100,
            0,
            &mut summary,
        )
        .expect("settles");
        assert_eq!(summary.revenue_base, required);
        assert_eq!(summary.revenue_tip, surplus);
        assert_eq!(published_credit(&settled, sender.0.account_id()), None);
    }

    #[test]
    fn a_dust_surplus_is_kept_as_tip() {
        let (state, senders) = private_sender_state(&[0x52]);
        let sender = &senders[0];
        let alias = sender.0.account_id().blinded(&ALIAS_OPENING);
        let recipient = initial_pub_accounts_private_keys()[0].account_id;
        let required = fee_core::assess::private_fee_required(0, 8, 8);
        let reserve = required + fee_core::market::MIN_PRIVATE_REFUND;
        let tx = private_tx(
            &state,
            sender,
            recipient,
            10,
            Some(inbox_fee(reserve, sender.0.account_id())),
        );

        let mut settled = state;
        let mut summary = BlockFeeSummary::default();
        settle_transaction(
            &tx,
            &mut settled,
            &FeeState::genesis(),
            1,
            100,
            0,
            &mut summary,
        )
        .expect("settles");
        assert_eq!(summary.revenue_base, required);
        assert_eq!(summary.revenue_tip, fee_core::market::MIN_PRIVATE_REFUND);
        assert_eq!(
            native_balance(&settled, system_accounts::fee_inbox_account_id()),
            reserve
        );
        assert_eq!(published_credit(&settled, alias), None);
    }

    #[test]
    fn an_underpaid_or_unpaid_private_transaction_is_rejected() {
        let (state, senders) = private_sender_state(&[0x53]);
        let sender = &senders[0];
        let recipient = initial_pub_accounts_private_keys()[0].account_id;
        let required = fee_core::assess::private_fee_required(0, 8, 8);

        for fee in [
            None,
            Some(inbox_fee(required - 1, sender.0.account_id())),
            // Paid to another public account: the inbox sees no credit.
            Some(lee_core::FeeTransfer {
                recipient,
                ..inbox_fee(required, sender.0.account_id())
            }),
        ] {
            let tx = private_tx(&state, sender, recipient, 10, fee);
            let mut summary = BlockFeeSummary::default();
            let err = settle_transaction(
                &tx,
                &mut state.clone(),
                &FeeState::genesis(),
                1,
                100,
                0,
                &mut summary,
            )
            .expect_err("an unpaid fee is rejected");
            assert!(
                matches!(err, BlockIngestError::InvalidFeeClass { .. }),
                "{err:?}"
            );
            assert_eq!(summary, BlockFeeSummary::default());
        }
    }

    #[test]
    fn two_private_transactions_settle_in_one_block_and_fund_the_producer() {
        let (mut state, senders) = private_sender_state(&[0x54, 0x55]);
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        let recipient = initial_pub_accounts_private_keys()[0].account_id;
        let required = fee_core::assess::private_fee_required(0, 8, 8);

        let txs: Vec<_> = senders
            .iter()
            .map(|sender| {
                private_tx(
                    &state,
                    sender,
                    recipient,
                    10,
                    Some(inbox_fee(required + 1, sender.0.account_id())),
                )
            })
            .collect();
        let producer = common::test_utils::producer_account_for_testing();
        let producer_pre = native_balance(&state, producer);
        let block = settled_block(2, genesis.header.hash, txs, &state);
        apply_block(Some(&tip_of(&genesis)), &block, &mut state).expect("both settle");

        // The block tail drained the inbox: base revenue to escrow (minus this block's
        // smoothed payout), tips and payout to the producer. Nothing is lost.
        assert_eq!(
            native_balance(&state, system_accounts::fee_inbox_account_id()),
            0
        );
        let producer_gain = native_balance(&state, producer) - producer_pre;
        assert!(
            producer_gain >= 2,
            "the producer receives at least the tips"
        );
        assert_eq!(
            native_balance(&state, system_accounts::fee_escrow_account_id()) + producer_gain,
            2 * required + 2
        );
    }

    /// A block whose forced fee transaction carries the summary its user
    /// transactions actually settle to, signed by the shared test key.
    fn settled_block(
        id: u64,
        prev_hash: HashType,
        transactions: Vec<LeeTransaction>,
        state: &V03State,
    ) -> common::block::Block {
        settled_block_rewarding(
            id,
            prev_hash,
            transactions,
            state,
            FeePayee::Present(common::test_utils::producer_account_for_testing()),
        )
    }

    /// [`settled_block`] with an explicit reward target, for exercising the
    /// reward-target guard.
    fn settled_block_rewarding(
        id: u64,
        prev_hash: HashType,
        mut transactions: Vec<LeeTransaction>,
        state: &V03State,
        reward: FeePayee,
    ) -> common::block::Block {
        let timestamp = id.saturating_mul(100);
        let (summary, payout) = super::derive_block_summary(state, &transactions, id, timestamp)
            .expect("test transactions settle");
        transactions.push(LeeTransaction::Public(fee_invocation(
            summary, payout, reward,
        )));
        transactions.push(LeeTransaction::Public(clock_invocation(id, timestamp)));
        HashableBlockData {
            block_id: id,
            prev_block_hash: prev_hash,
            timestamp,
            transactions,
        }
        .into_pending_block()
    }
}
