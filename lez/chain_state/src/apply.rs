//! The single validate-then-apply entry point shared by the sequencer and the
//! indexer. Pure and storage-free: callers apply on a scratch clone of state and
//! commit only on `Ok`.

use std::collections::HashSet;

use common::{
    HashType,
    block::{Block, BlockMeta},
    transaction::{
        LeeTransaction, TxEvents, clock_invocation, fee_invocation, fee_refund_invocation,
        fee_reserve_invocation, validate_bridge_account_modification,
        validate_no_restricted_account_modification,
    },
};
use fee_core::{
    BlockFeeSummary,
    assess::{FeeTxView, fee_actual_base, fee_reserve},
    state::FeeState,
    validity::{accumulate_exec_gas, accumulate_stor_gas, validate_static_tx},
};
use lee::{GENESIS_BLOCK_ID, V03State};
use lee_core::{BlockId, Timestamp, program::TransactionEvent};

use crate::{
    classify::{ClassifyError, FeeClass, classify},
    ingest_error::BlockIngestError,
};

/// The parent the next block must chain on.
// `l1_slot` will be added here when the `ChainState` anchor layer lands.
#[derive(Debug, Clone)]
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
    Applied,
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
) -> Result<(), BlockIngestError> {
    validate_against_tip(tip, block)?;
    apply_block_to_state(block, state)?;
    Ok(())
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
    if !block.has_valid_producer_signature() {
        return Err(BlockIngestError::InvalidProducerSignature);
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
    if *clock_tx != clock_invocation(block.header.timestamp) {
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
    // settlement produced. Its reward target — a staked sequencer's ownership
    // account, already claimed by that sequencer's stake — rides inside the tx
    // (the account after the fixed fee accounts). The byte-compare pins the
    // summary and tx shape; authenticating the target as the block's true L1
    // producer is the follower's job, not this signer-free path the indexer
    // also runs.
    let producer_account = common::transaction::fee_invocation_producer(fee_tx)
        .ok_or(BlockIngestError::InvalidFeeTransaction)?;
    if *fee_tx != fee_invocation(summary, producer_account) {
        return Err(BlockIngestError::InvalidFeeTransaction);
    }

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
        &state
            .get_account_by_id(system_accounts::fee_state_account_id())
            .data
            .into_inner(),
    )
}

/// Derives the block fee summary the given user transactions settle to.
///
/// Runs the settlement on a scratch clone of `state`. What block builders
/// (and block-building tests) use to construct the forced fee transaction.
pub fn derive_block_summary(
    state: &V03State,
    transactions: &[LeeTransaction],
    block_id: BlockId,
    timestamp: Timestamp,
) -> Result<BlockFeeSummary, BlockIngestError> {
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
    Ok(summary)
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
    let class = classify(transaction, false, state).map_err(|err| match err {
        ClassifyError::Unserializable(err) => BlockIngestError::InvalidFeeClass {
            tx_index,
            reason: format!("unserializable transaction: {err}"),
        },
        ClassifyError::MissingFeeDeclaration => {
            BlockIngestError::MissingFeeDeclaration { tx_index }
        }
    })?;
    let events = match class {
        FeeClass::Exempt => {
            let diff = transaction
                .compute_state_diff(state, block_id, timestamp)
                .map_err(|err| BlockIngestError::StateTransition {
                    tx_index,
                    reason: format!("{:#}", anyhow::Error::from(err)),
                })?;

            // The builder guards user transactions off the restricted accounts;
            // the apply path must too, or a block author could drain them.
            validate_no_restricted_account_modification(state, &diff).map_err(|err| {
                BlockIngestError::RestrictedAccountModification {
                    tx_index,
                    reason: err.to_string(),
                }
            })?;

            // Private and deployment transactions never legitimately touch the
            // bridge, so any bridge diff from one is a drain attempt. Deposits
            // legitimately debit the bridge, so they stay unguarded here — a
            // forged empty-witness deposit still slips through by shape, which
            // only L1 deposit verification can close (#809).
            if matches!(
                transaction,
                LeeTransaction::PrivacyPreserving(_) | LeeTransaction::ProgramDeployment(_)
            ) {
                validate_bridge_account_modification(state, &diff, false).map_err(|err| {
                    BlockIngestError::RestrictedAccountModification {
                        tx_index,
                        reason: err.to_string(),
                    }
                })?;
            }

            state.apply_state_diff(diff)
        }
        FeeClass::Charged(view) => {
            let LeeTransaction::Public(public_tx) = transaction else {
                unreachable!("only public transactions classify as charged");
            };
            settle_charged_transaction(
                public_tx, &view, state, opening, block_id, timestamp, tx_index, summary,
            )?
        }
    };
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
    public_tx: &lee::PublicTransaction,
    view: &FeeTxView,
    state: &mut V03State,
    opening: &FeeState,
    block_id: BlockId,
    timestamp: Timestamp,
    tx_index: u64,
    summary: &mut BlockFeeSummary,
) -> Result<Vec<TransactionEvent>, BlockIngestError> {
    let fee_validity = |reason: String| BlockIngestError::InvalidFeeClass { tx_index, reason };
    let fee_restricted =
        |reason: String| BlockIngestError::RestrictedAccountModification { tx_index, reason };

    validate_static_tx(view, opening).map_err(|err| fee_validity(err.to_string()))?;
    if !lee::is_fee_authorized(public_tx.message(), public_tx.witness_set()) {
        return Err(fee_validity(
            "designated payer's authorization is missing".into(),
        ));
    }

    let payer = view.payer();

    // Phase 1: Reserve
    //
    // hold `reserved` from the payer in the inbox via `authenticated_transfer`,
    // authorized by the fee declaration.
    //
    // This does NOT advance the nonce, invalidates the tx if the payer cannot afford it.
    let reserved = fee_reserve(view, opening);
    let reserve_msg = fee_reserve_invocation(payer, reserved);
    let payer_authorized = HashSet::from([payer]);
    let reserve_diff = lee::ValidatedStateDiff::from_fee_settlement_invocation(
        reserve_msg.program_id,
        &reserve_msg.account_ids,
        &reserve_msg.instruction_data,
        &payer_authorized,
        state,
        block_id,
        timestamp,
    )
    .map_err(|err| fee_validity(format!("fee reserve failed: {err}")))?;
    // Reserve is a fee-internal move; its events are not the user's.
    drop(state.apply_state_diff(reserve_diff));

    // Phase 2: Action
    //
    // Runs the metered execution at `gas_limit`. The returned diff carries the
    // action's effects on success or only the signers' nonce advances on a
    // revert; either way the reserved fee stays committed. An authentication
    // failure is a malformed transaction that invalidates the whole block.
    let gas_limit = view.gas_limit();
    let (outcome, result) = lee::ValidatedStateDiff::from_public_transaction_metered(
        public_tx, state, block_id, timestamp, gas_limit,
    );
    let action_diff = result.map_err(|err| fee_validity(format!("fee action failed: {err}")))?;
    // r0 cycle count can overshoot, clamp to `gas_limit`
    let charged_cycles = outcome.cycles.min(gas_limit);

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

    // A charged transaction whose program touches the fee/clock/faucet accounts
    // is a drain attempt (the canonical fee invocation is the block tail,
    // byte-compared separately). A reverted action's diff is nonce-only and
    // passes trivially; a successful one is guarded here so followers do not
    // accept a leader's drain.
    validate_no_restricted_account_modification(state, &action_diff)
        .map_err(|err| fee_restricted(err.to_string()))?;
    validate_bridge_account_modification(state, &action_diff, true)
        .map_err(|err| fee_restricted(err.to_string()))?;
    // The action's events are the transaction's user-facing events.
    let action_events = state.apply_state_diff(action_diff);

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
            refund_msg.program_id,
            &refund_msg.account_ids,
            &refund_msg.instruction_data,
            &HashSet::new(),
            state,
            block_id,
            timestamp,
        )
        .map_err(|err| fee_validity(format!("fee refund failed: {err}")))?;
        // Refund is a fee-internal move; its events are not the user's.
        drop(state.apply_state_diff(refund_diff));
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
    use common::{
        block::HashableBlockData,
        test_utils::{
            create_transaction_native_token_transfer, produce_dummy_block,
            produce_dummy_empty_transaction, sequencer_sign_key_for_testing,
        },
    };
    use testnet_initial_state::{initial_pub_accounts_private_keys, initial_state};

    use super::*;

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
    fn producer_signature_must_verify() {
        let mut state = initial_state();
        let genesis = produce_dummy_block(1, None, vec![]);
        // Forge the producer: replace it with a different key and re-hash so
        // the hash check passes but the signature no longer verifies.
        let mut forged = genesis;
        forged.header.producer = lee::PublicKey::new_from_private_key(
            &lee::PrivateKey::try_new([9_u8; 32]).expect("valid key"),
        );
        forged.header.hash = forged.recompute_hash();
        let err = apply_block(None, &forged, &mut state).expect_err("should reject");
        assert!(matches!(err, BlockIngestError::InvalidProducerSignature));
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
        .into_pending_block(&sequencer_sign_key_for_testing());
        let err = apply_block(None, &block, &mut state).expect_err("should reject");
        assert!(matches!(err, BlockIngestError::EmptyBlock));
    }

    #[test]
    fn fee_state_advances_with_the_chain() {
        let mut state = initial_state();
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        let mut tip = tip_of(&genesis);
        for id in 2..=5_u64 {
            let block = produce_dummy_block(id, Some(tip.hash), vec![]);
            apply_block(Some(&tip), &block, &mut state).expect("block applies");
            tip = tip_of(&block);
        }

        let fee_state = fee_core::state::FeeState::from_bytes(
            &state
                .get_account_by_id(system_accounts::fee_state_account_id())
                .data
                .into_inner(),
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
                .balance,
            0
        );
        assert_eq!(
            state
                .get_account_by_id(system_accounts::fee_inbox_account_id())
                .balance,
            0
        );
    }

    #[test]
    fn missing_fee_tx_is_invalid_fee() {
        let mut state = initial_state();
        // Correct clock tail but no fee tx before it.
        let block = HashableBlockData {
            block_id: 1,
            prev_block_hash: HashType([0_u8; 32]),
            timestamp: 100,
            transactions: vec![
                produce_dummy_empty_transaction(),
                LeeTransaction::Public(clock_invocation(100)),
            ],
        }
        .into_pending_block(&sequencer_sign_key_for_testing());
        let err = apply_block(None, &block, &mut state).expect_err("should reject");
        assert!(matches!(err, BlockIngestError::InvalidFeeTransaction));
    }

    #[test]
    fn nonzero_fee_summary_is_invalid_fee() {
        let mut state = initial_state();
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
                    lee::AccountId::from(&lee::PublicKey::new_from_private_key(
                        &sequencer_sign_key_for_testing(),
                    )),
                )),
                LeeTransaction::Public(clock_invocation(100)),
            ],
        }
        .into_pending_block(&sequencer_sign_key_for_testing());
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
        .into_pending_block(&sequencer_sign_key_for_testing());
        let err = apply_block(None, &block, &mut state).expect_err("should reject");
        assert!(matches!(err, BlockIngestError::InvalidClockTransaction));
    }

    #[test]
    fn applies_transfers_and_advances_state() {
        let mut state = initial_state(true);
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();
        let initial_from = state.get_account_by_id(from).balance;
        let initial_to = state.get_account_by_id(to).balance;

        // Genesis (block 1): fee/clock only.
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        // Simulate the producer's stake: its reward account is claimed before
        // it produces, so the charged blocks below can credit it.
        common::test_utils::claim_producer_account(&mut state);
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
        assert_eq!(state.get_account_by_id(to).balance, initial_to + 100);
        let from_final = state.get_account_by_id(from).balance;
        let fees_paid = initial_from - 100 - from_final;
        assert!(fees_paid > 0, "charged transfers must pay a nonzero fee");

        let producer = lee::AccountId::from(&lee::PublicKey::new_from_private_key(
            &sequencer_sign_key_for_testing(),
        ));
        let escrow = state
            .get_account_by_id(system_accounts::fee_escrow_account_id())
            .balance;
        let producer_balance = state.get_account_by_id(producer).balance;
        let inbox = state
            .get_account_by_id(system_accounts::fee_inbox_account_id())
            .balance;
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
        let mut state = initial_state();
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");

        let accounts = initial_pub_accounts_private_keys();
        let attacker = accounts[0].account_id;
        let attacker_key = accounts[0].pub_sign_key.clone();
        let recipient = accounts[1].account_id;

        let opening = FeeState::from_bytes(
            &state
                .get_account_by_id(system_accounts::fee_state_account_id())
                .data
                .into_inner(),
        );

        // Accrue real revenue in the inbox with one legitimate charged transfer.
        let mut summary = BlockFeeSummary::default();
        let transfer =
            create_transaction_native_token_transfer(attacker, 0, recipient, 10, &attacker_key);
        settle_transaction(&transfer, &mut state, &opening, 2, 200, 0, &mut summary)
            .expect("the legitimate transfer settles");
        let inbox_revenue = state
            .get_account_by_id(system_accounts::fee_inbox_account_id())
            .balance;
        assert!(inbox_revenue > 0, "the transfer must have funded the inbox");

        // The drain: invoke the fee program's Refund to sweep the accrued inbox
        // revenue to the attacker. The guest accepts it — the fee program owns
        // the inbox it debits — producing a diff that modifies the restricted
        // inbox, which the apply-path guard must reject.
        let fee_program_id = fee_invocation(BlockFeeSummary::default(), attacker)
            .message()
            .program_id;
        let message = lee::public_transaction::Message::try_new_with_fees(
            fee_program_id,
            vec![system_accounts::fee_inbox_account_id(), attacker],
            vec![state.get_account_by_id(attacker).nonce],
            fee_core::Instruction::Refund {
                amount: inbox_revenue,
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
        let mut state = initial_state();
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");

        let accounts = initial_pub_accounts_private_keys();
        let sender = accounts[0].account_id;
        let sender_key = accounts[0].pub_sign_key.clone();
        let recipient = accounts[1].account_id;

        let opening = FeeState::from_bytes(
            &state
                .get_account_by_id(system_accounts::fee_state_account_id())
                .data
                .into_inner(),
        );
        let sender_before = state.get_account_by_id(sender).balance;
        let recipient_before = state.get_account_by_id(recipient).balance;

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
        assert_eq!(state.get_account_by_id(sender).balance, sender_before);
        assert_eq!(state.get_account_by_id(recipient).balance, recipient_before);
    }

    #[test]
    fn a_charged_action_that_reverts_is_charged_not_block_rejected() {
        let mut state = initial_state();
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");

        let accounts = initial_pub_accounts_private_keys();
        let payer = accounts[0].account_id;
        let payer_key = accounts[0].pub_sign_key.clone();
        let recipient = accounts[1].account_id;

        let opening = FeeState::from_bytes(
            &state
                .get_account_by_id(system_accounts::fee_state_account_id())
                .data
                .into_inner(),
        );

        let payer_before = state.get_account_by_id(payer).balance;
        let payer_nonce_before = u128::from(state.get_account_by_id(payer).nonce);
        let recipient_before = state.get_account_by_id(recipient).balance;

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
        assert_eq!(state.get_account_by_id(recipient).balance, recipient_before);
        // The nonce advanced, so the transaction cannot be replayed.
        assert_eq!(
            u128::from(state.get_account_by_id(payer).nonce),
            payer_nonce_before
                .checked_add(1)
                .expect("nonce + 1 fits u128"),
        );
        // The fee was charged: the payer paid, and it accrued as real revenue.
        assert!(
            state.get_account_by_id(payer).balance < payer_before,
            "the reverted action still pays a fee",
        );
        assert!(
            summary.revenue_base > 0,
            "the charged revert accrues real fee revenue",
        );
    }

    /// A block whose forced fee transaction carries the summary its user
    /// transactions actually settle to, signed by the shared test key.
    fn settled_block(
        id: u64,
        prev_hash: HashType,
        mut transactions: Vec<LeeTransaction>,
        state: &V03State,
    ) -> common::block::Block {
        let timestamp = id.saturating_mul(100);
        let summary = super::derive_block_summary(state, &transactions, id, timestamp)
            .expect("test transactions settle");
        let producer = lee::AccountId::from(&lee::PublicKey::new_from_private_key(
            &sequencer_sign_key_for_testing(),
        ));
        transactions.push(LeeTransaction::Public(fee_invocation(summary, producer)));
        transactions.push(LeeTransaction::Public(clock_invocation(timestamp)));
        HashableBlockData {
            block_id: id,
            prev_block_hash: prev_hash,
            timestamp,
            transactions,
        }
        .into_pending_block(&sequencer_sign_key_for_testing())
    }
}
