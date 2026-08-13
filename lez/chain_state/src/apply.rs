//! The single validate-then-apply entry point shared by the sequencer and the
//! indexer. Pure and storage-free: callers apply on a scratch clone of state and
//! commit only on `Ok`.

use common::{
    HashType,
    block::{Block, BlockMeta},
    transaction::{LeeTransaction, clock_invocation, is_full_vault_sweep, is_system_transaction},
};
use fee_core::{
    FeeError, FeeTxView, PayerId,
    params::{MAX_GAS_EXEC, MAX_GAS_STOR, PRIVATE_VERIFY_GAS, SMOOTHING_WINDOW},
};
use lee::{AccountId, GENESIS_BLOCK_ID, V03State, ValidatedStateDiff};

use crate::ingest_error::BlockIngestError;

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

/// What one transaction of a *committed* block did.
///
/// A block is either applied whole or rejected whole, so this never describes a rejection: a
/// reverted transaction is included, charged, and has its replay nonces advanced — only its
/// execution effects are dropped (SPECS §Block transition).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxApplyOutcome {
    /// Executed successfully; its diff is part of the new state.
    Applied,
    /// Included and charged, execution effects discarded.
    Reverted {
        /// The execution failure, rendered.
        reason: String,
    },
}

/// What a committed block did to the fee subsystem (SPECS §Block transition).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockApplySummary {
    /// One entry per non-clock transaction, in block order.
    pub tx_outcomes: Vec<TxApplyOutcome>,
    /// Total settled `fee_base` over the block's charged transactions.
    pub revenue_base: u128,
    /// Total tips over the block's charged transactions.
    pub revenue_tip: u128,
    /// Amount paid to the producer out of escrow this block.
    pub payout: u128,
    /// Execution gas the block consumed, over its non-system transactions.
    pub gas_used_exec: u64,
    /// Storage gas the block consumed, over its non-system transactions.
    pub gas_used_stor: u64,
}

impl BlockApplySummary {
    /// The summary of a block that charges nothing: the genesis block.
    const fn exempt(tx_outcomes: Vec<TxApplyOutcome>) -> Self {
        Self {
            tx_outcomes,
            revenue_base: 0,
            revenue_tip: 0,
            payout: 0,
            gas_used_exec: 0,
            gas_used_stor: 0,
        }
    }
}

/// One transaction's contribution to the two block gas totals. See [`cap_contribution`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapContribution {
    /// Execution gas, against `MAX_GAS_EXEC`.
    pub gas_exec: u64,
    /// Storage gas, against `MAX_GAS_STOR`.
    pub gas_stor: u64,
}

/// How the fee subsystem treats one transaction of a block.
enum FeeClass {
    /// Fee-exempt **and** cap-exempt: the sequencer's own injections (bridge-deposit mints,
    /// cross-zone dispatches), and every transaction of the genesis block. Rulings Q6/Q10; a
    /// decided deviation from SPECS invariant 6 as written.
    Exempt,
    /// Charged: a user-submitted public transaction. Carries its fee-relevant view.
    Charged(FeeTxView),
    /// Counted against both block caps, charged nothing, with a constant execution gas.
    ///
    /// Private transactions occupy the same block resources as anything else, so they must be
    /// capped, but the private fee path is not decided yet. Program deployments carry no nonces in
    /// their message, so a charged-but-failed deployment would stay re-includable for ever and
    /// drain its payer; charging them waits on a replay-protection design.
    // TBA(Q3): who a fully-shielded transaction's payer is.
    // TBA(INCREMENTIAL): the private fee mechanism itself (T5).
    // TBA(deployment-replay): `fee_core::DeploymentFeePolicy::PricedAsPublic` is the declared
    // intent, deliberately not consumed here yet.
    Uncharged {
        /// Execution gas charged against the block cap.
        gas_exec: u64,
        /// Storage gas charged against the block cap.
        gas_stor: u64,
    },
    /// Counted against both block caps, charged nothing, and its execution gas is *metered* rather
    /// than a constant: a full vault sweep (see [`is_full_vault_sweep`]). Uncharged, not uncapped —
    /// the same treatment the private and deployment exemptions get.
    ///
    /// A sweep that reverts is not settled, so its nonces advance only through its diff, i.e. only
    /// on success. It therefore stays replayable — at the cost of block cap space each time, and
    /// the builder drops failing transactions before they reach a block.
    // TBA(fee-bootstrap): see `is_full_vault_sweep`.
    UnchargedMetered {
        /// Storage gas charged against the block cap.
        gas_stor: u64,
    },
}

/// Validates `block` against `tip`, then applies it to `state`.
///
/// Mutates `state` in place, so callers pass a scratch clone and commit on `Ok`.
pub fn apply_block(
    tip: Option<&Tip>,
    block: &Block,
    state: &mut V03State,
) -> Result<BlockApplySummary, BlockIngestError> {
    validate_against_tip(tip, block)?;
    apply_block_to_state(block, state)
}

/// Checks that `block` is the valid continuation of `tip`.
///
/// In order: hash integrity, the producer's signature over it, block-id
/// continuity, then `prev_block_hash` linkage. A `None` tip (cold state)
/// expects the genesis block, which is validated exactly like any other block —
/// it is produced by a sequencer with its own signing key, so it carries a real
/// `producer` and a real signature.
pub fn validate_against_tip(tip: Option<&Tip>, block: &Block) -> Result<(), BlockIngestError> {
    let computed = block.recompute_hash();
    if computed != block.header.hash {
        return Err(BlockIngestError::HashMismatch {
            computed,
            header: block.header.hash,
        });
    }

    // The producer is inside the hashed content, so this ties the block to the
    // key it names: the hash cannot be re-pointed at another producer without
    // breaking the check above. Verified against the hash just recomputed
    // rather than through `is_signed_by`, which would hash the body a second
    // time. Nothing here pins a single key — each block is checked against the
    // producer it declares, so blocks from other sequencers validate too.
    if !block
        .header
        .signature
        .is_valid_for(&computed.0, &block.header.producer)
    {
        return Err(BlockIngestError::InvalidProducerSignature {
            producer: block.header.producer.clone(),
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
/// Implements SPECS §Block transition against the caller's working copy:
///
/// 1. static fee-validity and the storage cap, at the block's *opening* base fees;
/// 2. reserve → execute → dynamic execution cap → settle, per transaction in block order;
/// 3. distribute (escrow, window, carry) and credit the producer, as the last ledger effect;
/// 4. move both base fees to their values for the next block.
///
/// A transaction that reverts is charged and keeps its nonce advance; the block stays valid. A
/// failed reservation, a violated cap or a statically invalid transaction rejects the whole block.
///
/// # Panics
///
/// On a consensus fault (a payout exceeding the escrow, SPECS §Invariants #4). That is a halt
/// condition, not a rejection: it means the fee state was corrupted outside this transition, and
/// continuing would fork consensus.
pub fn apply_block_to_state(
    block: &Block,
    state: &mut V03State,
) -> Result<BlockApplySummary, BlockIngestError> {
    let (clock_tx, user_txs) = block
        .body
        .transactions
        .split_last()
        .ok_or(BlockIngestError::EmptyBlock)?;

    let LeeTransaction::Public(clock_tx) = clock_tx else {
        return Err(BlockIngestError::InvalidClockTransaction);
    };
    if *clock_tx != clock_invocation(block.header.timestamp) {
        return Err(BlockIngestError::InvalidClockTransaction);
    }

    let block_id = block.header.block_id;
    let timestamp = block.header.timestamp;
    let is_genesis = block_id == GENESIS_BLOCK_ID;

    // 1. The storage cap, before any work is done: serialized lengths are known in advance, so a
    // block that busts it is rejected without running a single zkVM session. Which transactions
    // *count* depends only on whether they are system transactions, never on ledger state.
    //
    // Per-transaction static fee-validity happens at each transaction's turn instead, immediately
    // before its reservation. It has to: whether a vault claim is the fee-exempt full sweep is a
    // question about the vault's balance *at that point in the block*, which is also how the
    // sequencer's builder asks it. Asking it once up front would let the two disagree, and the
    // sequencer would build blocks it then rejected itself.
    let opening = state.fee_state().clone();
    validate_block_storage_cap(user_txs, is_genesis)?;

    // 2. Reserve, execute, settle, in block order.
    let mut summary = BlockApplySummary::exempt(Vec::with_capacity(user_txs.len()));
    // Debit side of SPECS invariant 1, accumulated for the debug assertion below.
    let mut net_payer_debits: u128 = 0;

    for (tx_index, transaction) in user_txs.iter().enumerate() {
        let tx_index = u64::try_from(tx_index).expect("tx index fits in u64");
        match classify(transaction, is_genesis, state) {
            FeeClass::Exempt => {
                apply_uncharged(
                    transaction,
                    state,
                    block_id,
                    timestamp,
                    is_genesis,
                    tx_index,
                )?;
                summary.tx_outcomes.push(TxApplyOutcome::Applied);
            }
            FeeClass::Uncharged { gas_exec, gas_stor } => {
                summary.gas_used_exec = accumulate_exec_gas(summary.gas_used_exec, gas_exec)?;
                summary.gas_used_stor = summary
                    .gas_used_stor
                    .checked_add(gas_stor)
                    .expect("storage total is bounded by MAX_GAS_STOR, checked statically");
                apply_uncharged(
                    transaction,
                    state,
                    block_id,
                    timestamp,
                    is_genesis,
                    tx_index,
                )?;
                summary.tx_outcomes.push(TxApplyOutcome::Applied);
            }
            FeeClass::UnchargedMetered { gas_stor } => {
                let outcome = apply_uncharged(
                    transaction,
                    state,
                    block_id,
                    timestamp,
                    is_genesis,
                    tx_index,
                )?;
                summary.gas_used_exec = accumulate_exec_gas(summary.gas_used_exec, outcome.cycles)?;
                summary.gas_used_stor = summary
                    .gas_used_stor
                    .checked_add(gas_stor)
                    .expect("storage total is bounded by MAX_GAS_STOR, checked statically");
                summary.tx_outcomes.push(TxApplyOutcome::Applied);
            }
            FeeClass::Charged(view) => {
                let LeeTransaction::Public(public_tx) = transaction else {
                    unreachable!("only public transactions are classified as charged");
                };
                let charge = settle_charged_transaction(
                    public_tx,
                    &view,
                    state,
                    &opening,
                    block_id,
                    timestamp,
                    tx_index,
                    &mut summary,
                )?;
                net_payer_debits = net_payer_debits
                    .checked_add(charge)
                    .expect("block fee total is bounded by the total supply");
            }
        }
    }

    // The clock invocation is a system transaction: exempt, and applied last, as before — so it
    // still runs before the producer credit below, which must be the block's final ledger effect.
    state
        .transition_from_public_transaction(clock_tx, block_id, timestamp)
        .map_err(|err| BlockIngestError::StateTransition {
            tx_index: user_txs.len().try_into().expect("tx index fits in u64"),
            reason: format!("{:#}", anyhow::Error::from(err)),
        })?;

    // The genesis block is exempt in full: it collects nothing, so it neither pushes a window slot
    // nor moves a base fee, and the post-genesis fee state is exactly `FeeState::genesis()`.
    if is_genesis {
        return Ok(summary);
    }

    // 3. Distribute. Base fees go through the escrow and its 50-block payout window; tips go
    // straight to the producer. Both reach the producer only here, after every transaction has
    // settled, so neither can fund a transaction of this same block.
    summary.payout = state
        .distribute_block_revenue(summary.revenue_base)
        .unwrap_or_else(|err| consensus_fault(&err));
    let producer_credit = summary
        .payout
        .checked_add(summary.revenue_tip)
        .expect("producer credit is bounded by the total supply");
    state.credit_fee(AccountId::from(&block.header.producer), producer_credit);

    // 4. Base fees for the next block.
    state.update_base_fees(summary.gas_used_exec, summary.gas_used_stor);

    debug_assert_eq!(
        net_payer_debits,
        summary
            .revenue_base
            .checked_add(summary.revenue_tip)
            .expect("no overflow"),
        "SPECS invariant 1: payer debits net of released reservations must equal revenue"
    );
    debug_assert!(
        state.fee_state().payout_carry
            < u128::try_from(SMOOTHING_WINDOW).expect("SMOOTHING_WINDOW fits u128"),
        "SPECS invariant 4: payout_carry < SMOOTHING_WINDOW"
    );

    Ok(summary)
}

/// The fee-relevant view of a transaction that this transition would charge, or `None` if it is
/// fee-exempt (system, private or a deployment).
///
/// Exported so the sequencer's block builder classifies and prices exactly as the apply path does:
/// a block whose builder disagreed with `apply_block_to_state` would be rejected by its own
/// producer.
#[must_use]
pub fn charged_fee_view(transaction: &LeeTransaction, state: &V03State) -> Option<FeeTxView> {
    match classify(transaction, false, state) {
        FeeClass::Charged(view) => Some(view),
        FeeClass::Exempt | FeeClass::Uncharged { .. } | FeeClass::UnchargedMetered { .. } => None,
    }
}

/// What one transaction adds to the block's two gas totals, once its execution has metered
/// `cycles`. `None` when the transaction is cap-exempt.
///
/// Exported for the sequencer's block builder, which must stop filling a block *before* it busts a
/// cap the apply path would reject it for. Both callers go through [`classify`], so the exemption
/// table cannot drift between building and applying; the arms below mirror, one for one, what
/// `apply_block_to_state` accumulates.
///
/// `cycles` is ignored for the classes whose execution gas is a protocol constant, so a caller that
/// has not executed yet may pass anything for them.
#[must_use]
pub fn cap_contribution(
    transaction: &LeeTransaction,
    state: &V03State,
    cycles: u64,
) -> Option<CapContribution> {
    match classify(transaction, false, state) {
        FeeClass::Exempt => None,
        FeeClass::Charged(view) => Some(CapContribution {
            // The same clamp `settle_charged_transaction` applies: the executor may overshoot its
            // limit by the cost of the instruction that crosses the line.
            gas_exec: cycles.min(match view {
                FeeTxView::Public { gas_limit, .. } => gas_limit,
                FeeTxView::Private { .. } => MAX_GAS_EXEC,
            }),
            gas_stor: fee_core::gas_stor(&view),
        }),
        FeeClass::Uncharged { gas_exec, gas_stor } => Some(CapContribution { gas_exec, gas_stor }),
        FeeClass::UnchargedMetered { gas_stor } => Some(CapContribution {
            gas_exec: cycles,
            gas_stor,
        }),
    }
}

/// Static fee-validity, replay-burn and payer authorization for one charged transaction, at
/// `opening`.
///
/// The single gate both sides go through: the apply path calls it inside
/// [`settle_charged_transaction`], the sequencer's block builder calls it before it admits a
/// transaction, so a rule added here cannot be enforced by one and not the other.
///
/// # Errors
///
/// A rendered reason, for the builder to log and skip on.
pub fn check_charged_tx(
    public_tx: &lee::PublicTransaction,
    view: &FeeTxView,
    opening: &lee::FeeState,
) -> Result<(), String> {
    fee_core::validate_static_tx(view, opening).map_err(|err| format!("{err}"))?;
    // A charged transaction MUST burn at least one nonce. Fee authorization can come from the fee
    // witness alone, which carries no nonce of its own: a transaction with no signer signatures
    // would be charged to its payer, advance nothing on either the success or the revert path, and
    // stay includable byte-for-byte for ever — an unbounded drain on the payer. Only the signer
    // signatures buy replay protection, so a charged transaction must carry at least one.
    if public_tx
        .witness_set()
        .signatures_and_public_keys()
        .is_empty()
    {
        return Err(
            "a charged transaction must carry at least one signer signature, so that including it \
             burns a nonce: a fee witness alone consumes no replay protection"
                .to_owned(),
        );
    }
    // The D1 seam, through its one production caller: `lee` verifies the signatures and hands
    // `fee_core` the set of accounts whose fee authorization checked out; `fee_core` decides
    // membership and nothing else, so the rule stays where PLAN D1 put it and the crate stays pure.
    let authorized: Vec<PayerId> =
        lee::fee_authorized_account_ids(public_tx.message(), public_tx.witness_set())
            .iter()
            .map(|account_id| PayerId(*account_id.value()))
            .collect();
    let payer = public_tx.message().payer;
    fee_core::authorize_payer(PayerId(*payer.value()), &authorized)
        .map_err(|err| format!("{err} (payer {payer})"))?;
    Ok(())
}

/// The block's storage cap (SPECS §Fee-validity), checked before any execution.
///
/// Serialized lengths are known in advance, so a block that busts the cap is rejected without a
/// single zkVM session running. Only system transactions are excluded, and that is a structural
/// property — no ledger state is read here, so this pass is stable no matter how the block's own
/// transactions move balances.
fn validate_block_storage_cap(
    user_txs: &[LeeTransaction],
    is_genesis: bool,
) -> Result<(), BlockIngestError> {
    if is_genesis {
        return Ok(());
    }
    let mut total_stor: u128 = 0;
    for transaction in user_txs {
        if is_system_transaction(transaction) {
            continue;
        }
        total_stor = total_stor
            .checked_add(u128::from(wire_size(transaction)))
            .expect("per-tx storage gas fits u64, so the running total fits u128");
        if total_stor > u128::from(MAX_GAS_STOR) {
            return Err(BlockIngestError::GasCapExceeded {
                reason: format!(
                    "block storage total {total_stor} exceeds MAX_GAS_STOR {MAX_GAS_STOR}"
                ),
            });
        }
    }
    Ok(())
}

/// The fee class of a single transaction, against `state` as it stands at that transaction's turn.
fn classify(transaction: &LeeTransaction, is_genesis: bool, state: &V03State) -> FeeClass {
    // Genesis is seeded by the sequencer from its own config, not by users: its transactions pay
    // nothing and count against nothing.
    if is_genesis || is_system_transaction(transaction) {
        return FeeClass::Exempt;
    }
    if is_full_vault_sweep(transaction, state) {
        return FeeClass::UnchargedMetered {
            gas_stor: wire_size(transaction),
        };
    }
    match transaction {
        LeeTransaction::Public(public_tx) => FeeClass::Charged(FeeTxView::Public {
            payer: PayerId(*public_tx.message().payer.value()),
            gas_limit: public_tx.message().gas_limit,
            data_bytes: wire_size(transaction),
            tip: public_tx.message().tip,
            max_fee: public_tx.message().max_fee,
        }),
        // The wire format does not pad private transactions to a constant size yet, so their
        // storage gas is their real serialized length rather than `PRIVATE_GAS_STOR`; their
        // execution gas is the protocol constant already.
        // TBA(INCREMENTIAL): re-pin against the padded wire format (T3/T5).
        LeeTransaction::PrivacyPreserving(_) => FeeClass::Uncharged {
            gas_exec: PRIVATE_VERIFY_GAS,
            gas_stor: wire_size(transaction),
        },
        // A deployment runs no zkVM session, so it consumes no execution gas; its bytes are posted
        // to Bedrock like anything else's.
        LeeTransaction::ProgramDeployment(_) => FeeClass::Uncharged {
            gas_exec: 0,
            gas_stor: wire_size(transaction),
        },
    }
}

/// Runs one charged public transaction through reserve → execute → settle.
///
/// Returns what the payer paid in total (`fee_base + tip`), for the conservation assertion.
#[expect(
    clippy::too_many_arguments,
    reason = "one step of the block transition; splitting it would only move the arguments"
)]
fn settle_charged_transaction(
    public_tx: &lee::PublicTransaction,
    view: &FeeTxView,
    state: &mut V03State,
    opening: &lee::FeeState,
    block_id: u64,
    timestamp: u64,
    tx_index: u64,
    summary: &mut BlockApplySummary,
) -> Result<u128, BlockIngestError> {
    let FeeTxView::Public { gas_limit, tip, .. } = *view else {
        unreachable!("charged transactions carry a public fee view");
    };
    let payer = public_tx.message().payer;

    // Static fee-validity, immediately before this transaction's reservation and so before any of
    // its execution: field bounds, `fee_reserve <= max_fee` at the block's opening base fees, and
    // a payer whose signature covers this exact message.
    check_charged_tx(public_tx, view, opening)
        .map_err(|reason| BlockIngestError::FeeValidity { tx_index, reason })?;

    // Authentication before the reservation. A bad signature or a stale nonce is a *validity*
    // failure — such a transaction may not be included at all — where an execution failure is a
    // revert that still advances nonces. Deciding that up front is what keeps the revert path
    // from ever advancing the nonces of a transaction that was never authenticated.
    let signers =
        lee::authenticate_public_transaction_signers(public_tx, state).map_err(|err| {
            BlockIngestError::StateTransition {
                tx_index,
                reason: format!("{:#}", anyhow::Error::from(err)),
            }
        })?;

    // Reserve: the worst-case fee is held before any work is done, so execution sees a
    // deterministic balance and payment is guaranteed.
    let reserve = fee_core::fee_reserve(view, opening);
    state
        .debit_fee(payer, reserve)
        .map_err(|err| BlockIngestError::FeeValidity {
            tx_index,
            reason: format!("{:#}", anyhow::Error::from(err)),
        })?;

    // Execute under the transaction's own declared bound.
    let (outcome, result) = ValidatedStateDiff::from_public_transaction_metered(
        public_tx, state, block_id, timestamp, gas_limit,
    );
    // The executor tests its limit *between* instructions, so the outcome may exceed the budget by
    // the crossing instruction's cost. Clamp rather than treat it as a fault: SPECS' "cycles >
    // gas_limit is a consensus fault" does not hold for a real risc0 executor.
    let charged_cycles = outcome.cycles.min(gas_limit);

    summary.gas_used_exec = accumulate_exec_gas(summary.gas_used_exec, charged_cycles)?;
    summary.gas_used_stor = summary
        .gas_used_stor
        .checked_add(fee_core::gas_stor(view))
        .expect("storage total is bounded by MAX_GAS_STOR, checked statically");

    match result {
        Ok(diff) => {
            state.apply_state_diff(diff);
            summary.tx_outcomes.push(TxApplyOutcome::Applied);
        }
        Err(err) => {
            // Effects discarded, fee kept, replay protection consumed anyway: a
            // charged-but-reverted transaction must not be re-includable.
            state.advance_replay_nonces(&signers);
            summary.tx_outcomes.push(TxApplyOutcome::Reverted {
                reason: format!("{:#}", anyhow::Error::from(err)),
            });
        }
    }

    // Settle. Released *after* the diff, whose account post-states were computed from the
    // already-reserved balance.
    let fee_base = fee_core::fee_actual_base(charged_cycles, view, opening);
    let fee_total = fee_base
        .checked_add(u128::from(tip))
        .expect("fee total is bounded by the total supply");
    let released = reserve
        .checked_sub(fee_total)
        .expect("charged cycles are clamped to gas_limit, so the reserve covers the actual fee");
    state.credit_fee(payer, released);

    summary.revenue_base = summary
        .revenue_base
        .checked_add(fee_base)
        .expect("block revenue is bounded by the total supply");
    summary.revenue_tip = summary
        .revenue_tip
        .checked_add(u128::from(tip))
        .expect("block tips are bounded by the total supply");

    Ok(fee_total)
}

/// Applies a transaction that pays nothing: system, genesis, private or deployment.
///
/// A failure here still rejects the whole block, as before. Only *charged* transactions may
/// revert and stay included — an uncharged one that reverted would be free spam.
fn apply_uncharged(
    transaction: &LeeTransaction,
    state: &mut V03State,
    block_id: u64,
    timestamp: u64,
    is_genesis: bool,
    tx_index: u64,
) -> Result<lee::ExecutionOutcome, BlockIngestError> {
    let state_transition = |err: lee::error::LeeError| BlockIngestError::StateTransition {
        tx_index,
        reason: format!("{:#}", anyhow::Error::from(err)),
    };
    if is_genesis {
        let LeeTransaction::Public(public_tx) = transaction else {
            return Err(BlockIngestError::NonPublicGenesisTransaction);
        };
        return state
            .transition_from_public_transaction(public_tx, block_id, timestamp)
            .map_err(state_transition);
    }
    transaction
        .clone()
        // No `gas_limit` of their own, so the block cap is the only bound that applies.
        .execute_on_state(state, block_id, timestamp, MAX_GAS_EXEC)
        .map(|(_tx, outcome)| outcome)
        .map_err(state_transition)
}

/// Adds `amount` to the block's execution-gas total and enforces `MAX_GAS_EXEC`.
///
/// Dynamic, unlike the storage cap: metered cycles only exist after execution, so a block that
/// blows the execution cap is discovered mid-loop and rejected whole.
fn accumulate_exec_gas(running_total: u64, amount: u64) -> Result<u64, BlockIngestError> {
    fee_core::accumulate_gas_used(running_total, amount, MAX_GAS_EXEC).map_err(|err| {
        BlockIngestError::GasCapExceeded {
            reason: format!("{err}"),
        }
    })
}

/// Halts on a violated fee invariant (SPECS §Block transition: "a consensus fault is not a
/// rejection: it halts the node instead of producing a state").
fn consensus_fault(err: &FeeError) -> ! {
    panic!("consensus fault in the fee subsystem, refusing to produce a state: {err}");
}

/// The transaction's canonical serialized length: the bytes it contributes to the block payload
/// posted to Bedrock, tag included. Block framing is borne by the producer, not charged here.
fn wire_size(transaction: &LeeTransaction) -> u64 {
    let len = borsh::object_length(transaction)
        .expect("a transaction that was deserialized from a block re-serializes");
    u64::try_from(len).expect("a transaction's serialized length fits u64")
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::integer_division,
        clippy::integer_division_remainder_used,
        clippy::shadow_unrelated,
        reason = "these tests re-derive the payout split by hand and step a chain block by block"
    )]

    use common::{
        block::HashableBlockData,
        test_utils::{
            create_transaction_native_token_transfer, produce_dummy_block,
            produce_dummy_empty_transaction, sequencer_producer_key_for_testing,
            sequencer_sign_key_for_testing,
        },
    };
    use testnet_initial_state::{initial_pub_accounts_private_keys, initial_state};

    use super::*;

    fn tip_of(block: &Block) -> Tip {
        Tip::from(block)
    }

    /// Genesis-shaped block claiming `producer` and signed with `signing_key`,
    /// which the callers below deliberately let disagree.
    fn genesis_claiming(producer: &lee::PublicKey, signing_key: &lee::PrivateKey) -> Block {
        HashableBlockData {
            block_id: GENESIS_BLOCK_ID,
            prev_block_hash: HashType([0_u8; 32]),
            timestamp: 100,
            producer: producer.clone(),
            transactions: vec![LeeTransaction::Public(clock_invocation(100))],
        }
        .into_pending_block(signing_key)
    }

    #[test]
    fn signature_by_a_key_other_than_the_producer_is_rejected() {
        let mut state = initial_state();
        let impostor = lee::PrivateKey::try_new([11_u8; 32]).expect("valid key");
        // Names the honest sequencer as producer, but is signed by someone else.
        let block = genesis_claiming(&sequencer_producer_key_for_testing(), &impostor);

        let err = apply_block(None, &block, &mut state).expect_err("should reject");
        assert!(matches!(
            err,
            BlockIngestError::InvalidProducerSignature { .. }
        ));
    }

    #[test]
    fn block_from_another_producer_applies() {
        let mut state = initial_state();
        // Multi-sequencer: the check pins nothing, it only demands that the
        // signature is by whichever producer the header names.
        let other = lee::PrivateKey::try_new([11_u8; 32]).expect("valid key");
        let block = genesis_claiming(&lee::PublicKey::new_from_private_key(&other), &other);

        apply_block(None, &block, &mut state).expect("a well-signed foreign block applies");
    }

    #[test]
    fn genesis_applies_on_empty_tip() {
        let mut state = initial_state();
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
    }

    #[test]
    fn non_genesis_first_block_is_unexpected_id() {
        let mut state = initial_state();
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
        let mut state = initial_state();
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
        let mut state = initial_state();
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
        let mut state = initial_state();
        let mut genesis = produce_dummy_block(1, None, vec![]);
        // Tampering with the header invalidates the stored hash.
        genesis.header.timestamp = 999;
        let err = apply_block(None, &genesis, &mut state).expect_err("should reject");
        assert!(matches!(err, BlockIngestError::HashMismatch { .. }));
    }

    #[test]
    fn empty_block_rejected() {
        let mut state = initial_state();
        // A block with no transactions at all (not even the mandatory clock tx).
        let block = HashableBlockData {
            block_id: 1,
            prev_block_hash: HashType([0_u8; 32]),
            timestamp: 0,
            producer: sequencer_producer_key_for_testing(),
            transactions: vec![],
        }
        .into_pending_block(&sequencer_sign_key_for_testing());
        let err = apply_block(None, &block, &mut state).expect_err("should reject");
        assert!(matches!(err, BlockIngestError::EmptyBlock));
    }

    #[test]
    fn missing_clock_tail_is_invalid_clock() {
        let mut state = initial_state();
        // Last tx is not the expected clock invocation for the timestamp.
        let block = HashableBlockData {
            block_id: 1,
            prev_block_hash: HashType([0_u8; 32]),
            timestamp: 50,
            producer: sequencer_producer_key_for_testing(),
            transactions: vec![produce_dummy_empty_transaction()],
        }
        .into_pending_block(&sequencer_sign_key_for_testing());
        let err = apply_block(None, &block, &mut state).expect_err("should reject");
        assert!(matches!(err, BlockIngestError::InvalidClockTransaction));
    }

    #[test]
    fn applies_transfers_and_advances_state() {
        let mut state = initial_state();
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();
        let opening_from = state.get_account_by_id(from).balance;

        // Genesis (block 1): clock-only.
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        let mut tip = tip_of(&genesis);

        // Blocks 2..=11: one native transfer of 10 each (nonces 0..=9).
        let mut fees_paid = 0_u128;
        for i in 0..10_u64 {
            let tx = create_transaction_native_token_transfer(from, i.into(), to, 10, &sign_key);
            let block = produce_dummy_block(i + 2, Some(tip.hash), vec![tx]);
            let summary = apply_block(Some(&tip), &block, &mut state).expect("transfer applies");
            assert_eq!(summary.tx_outcomes, vec![TxApplyOutcome::Applied]);
            fees_paid += summary.revenue_base;
            tip = tip_of(&block);
        }

        // The recipient is untouched by fees; the sender pays them on top of what it sent.
        assert_eq!(state.get_account_by_id(to).balance, 2_000_000_000_100);
        assert_eq!(
            state.get_account_by_id(from).balance,
            opening_from - 100 - fees_paid
        );
        assert!(fees_paid > 0, "ten charged transfers must have paid a fee");
    }

    /// The T7 boundary test, flipped: the fee state is now driven by the block transition, and it
    /// moves exactly as the golden scenario says.
    #[test]
    fn fee_state_moves_exactly_per_the_golden_scenario() {
        let mut state = initial_state();
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        // Genesis is exempt in full: it collects nothing, pushes no window slot, moves no base fee.
        let genesis = produce_dummy_block(1, None, vec![]);
        let summary = apply_block(None, &genesis, &mut state).expect("genesis applies");
        assert_eq!(summary.revenue_base, 0);
        assert_eq!(summary.payout, 0);
        assert_eq!(
            state.fee_state(),
            &lee::FeeState::genesis().expect("valid fee parameters"),
            "the genesis block must leave the fee state exactly at genesis",
        );

        let tip = tip_of(&genesis);
        let tx = create_transaction_native_token_transfer(from, 0_u64.into(), to, 10, &sign_key);
        let block = produce_dummy_block(2, Some(tip.hash), vec![tx]);
        let summary = apply_block(Some(&tip), &block, &mut state).expect("transfer applies");

        // Hand-derivable against fee_core: revenue is the block's only charged transaction, priced
        // at the genesis base fees of 8 for both resources.
        let expected_revenue =
            u128::from(summary.gas_used_exec) * 8 + u128::from(summary.gas_used_stor) * 8;
        assert_eq!(summary.revenue_base, expected_revenue);
        assert_eq!(summary.revenue_tip, 0);

        // Distribution: one 50-slot window push, payout = floor(sum / 50), remainder carried.
        assert_eq!(summary.payout, expected_revenue / 50);
        let fee_state = state.fee_state();
        assert_eq!(fee_state.window[0], expected_revenue);
        assert_eq!(fee_state.cursor, 1);
        assert_eq!(fee_state.payout_carry, expected_revenue % 50);
        assert_eq!(fee_state.escrow, expected_revenue - summary.payout);

        // Both resources stayed far below target, so both base fees stay pinned at the minimum
        // (the down-step has no +1 floor, and they are already at `lo`).
        assert_eq!(fee_state.base_fee_exec, 8);
        assert_eq!(fee_state.base_fee_stor, 8);
    }

    /// The producer is credited last, so its payout and tips cannot fund a transaction in the very
    /// block that earned them — they are visible only to the next block.
    #[test]
    fn producer_credit_is_the_blocks_last_ledger_effect() {
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();
        let producer_key = sequencer_sign_key_for_testing();
        let producer = lee::AccountId::from(&sequencer_producer_key_for_testing());

        // Two transactions, the second of them paid for by the producer itself. Fund the producer
        // with *exactly* its reservation minus what this block will pay it, so the block is valid
        // if and only if the producer credit lands before that second reservation is taken.
        let funded =
            create_transaction_native_token_transfer(from, 0_u64.into(), to, 10, &sign_key);
        let by_producer =
            create_transaction_native_token_transfer(producer, 0_u64.into(), to, 10, &producer_key);
        let txs = vec![funded, by_producer.clone()];

        // Probe run: the producer is funded generously, so the block is valid and its payout and
        // the producer's reservation can both be read off. Neither depends on the producer's
        // balance, so they carry over to the run below.
        let build = |producer_balance: u128| {
            let mut state = initial_state();
            state.force_insert_account(
                producer,
                lee::Account {
                    program_owner: programs::authenticated_transfer().id(),
                    balance: producer_balance,
                    ..lee::Account::default()
                },
            );
            let genesis = produce_dummy_block(1, None, vec![]);
            apply_block(None, &genesis, &mut state).expect("genesis applies");
            let tip = tip_of(&genesis);
            let block = produce_dummy_block(2, Some(tip.hash), txs.clone());
            (state, tip, block)
        };

        let (mut probe_state, probe_tip, probe_block) = build(1_000_000_000_000);
        let opening = probe_state.fee_state().clone();
        let view = charged_fee_view(&by_producer, &probe_state)
            .expect("the producer's transfer is a charged transaction");
        let reserve = fee_core::fee_reserve(&view, &opening);
        let summary = apply_block(Some(&probe_tip), &probe_block, &mut probe_state)
            .expect("the well-funded block applies");
        let payout = summary.payout;
        assert!(
            payout > 0,
            "the block must pay the producer something, or this test proves nothing",
        );
        assert!(reserve > payout, "the shortfall must be a real one");

        // The real run: one payout short of affordable.
        let (mut state, tip, block) = build(reserve - payout);
        let err = apply_block(Some(&tip), &block, &mut state).expect_err(
            "the producer cannot fund its reservation out of a credit it has not been paid yet",
        );
        assert!(
            matches!(err, BlockIngestError::FeeValidity { tx_index: 1, .. }),
            "expected the producer's own transaction to fail its reservation, got {err:?}",
        );
    }

    /// Fees are charged to the block's *own* header producer, not to a pinned key: with several
    /// sequencers in rotation each block pays whoever produced it.
    #[test]
    fn each_block_credits_its_own_header_producer() {
        let mut state = initial_state();
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        let tip = tip_of(&genesis);

        // A block by a different producer, built by hand so the header names that other key.
        let other_key = lee::PrivateKey::try_new([11_u8; 32]).expect("valid key");
        let other_producer = lee::PublicKey::new_from_private_key(&other_key);
        let tx = create_transaction_native_token_transfer(from, 0_u64.into(), to, 10, &sign_key);
        let block = HashableBlockData {
            block_id: 2,
            prev_block_hash: tip.hash,
            timestamp: 200,
            producer: other_producer.clone(),
            transactions: vec![tx, LeeTransaction::Public(clock_invocation(200))],
        }
        .into_pending_block(&other_key);

        let default_producer = lee::AccountId::from(&sequencer_producer_key_for_testing());
        let before_default = state.get_account_by_id(default_producer).balance;
        let summary = apply_block(Some(&tip), &block, &mut state).expect("foreign block applies");

        assert!(summary.payout > 0, "the block must have collected revenue");
        assert_eq!(
            state
                .get_account_by_id(lee::AccountId::from(&other_producer))
                .balance,
            summary.payout + summary.revenue_tip,
        );
        assert_eq!(
            state.get_account_by_id(default_producer).balance,
            before_default,
            "the key that did not produce this block must be paid nothing",
        );
    }

    /// A transaction whose payer is not fee-authorized is statically invalid, and takes the block
    /// with it. `FeeFields::ZERO` designates `SYSTEM_PAYER`, which no key derives.
    #[test]
    fn a_transaction_with_an_unauthorized_payer_invalidates_the_block() {
        let mut state = initial_state();
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        let tip = tip_of(&genesis);
        let before = state.clone();

        let message = lee::public_transaction::Message::try_new(
            programs::authenticated_transfer().id(),
            vec![from, accounts[1].account_id],
            vec![0_u128.into()],
            authenticated_transfer_core::Instruction::Transfer { amount: 10 },
            lee::FeeFields::ZERO,
        )
        .expect("message builds");
        let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[&sign_key]);
        let tx = LeeTransaction::Public(lee::PublicTransaction::new(message, witness_set));
        let block = produce_dummy_block(2, Some(tip.hash), vec![tx]);

        let err = apply_block(Some(&tip), &block, &mut state).expect_err("should reject");
        assert!(matches!(
            err,
            BlockIngestError::FeeValidity { tx_index: 0, .. }
        ));
        assert_eq!(
            state.get_account_by_id(from).balance,
            before.get_account_by_id(from).balance,
            "a rejected block leaves balances untouched (SPECS invariant 7)",
        );
    }

    /// A charged transaction MUST burn a nonce, and only its *signer* signatures buy one.
    ///
    /// A transaction with no signer signatures at all is still charged (it is neither system-shaped
    /// nor a full sweep) and is still fee-authorized, because the fee witness alone satisfies that
    /// check. But `authenticate_public_transaction_signers` returns an empty signer list for it, so
    /// neither the revert path's `advance_replay_nonces` nor a successful diff advances anything —
    /// the identical bytes stay includable for ever, draining the sponsor once per block. Rejected
    /// outright, on both the apply path and the builder's gate.
    #[test]
    fn a_fee_witness_only_charged_transaction_is_rejected() {
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sponsor_key = lee::PrivateKey::try_new([33_u8; 32]).expect("valid key");
        let sponsor = lee::AccountId::from(&lee::PublicKey::new_from_private_key(&sponsor_key));

        let mut state = initial_state();
        state.force_insert_account(sponsor, funded_account(1_000_000_000_000));
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        let tip = tip_of(&genesis);
        let opening = state.fee_state().clone();
        let before_sponsor = state.get_account_by_id(sponsor).balance;

        // No signers whatsoever: an empty nonce list and an empty signature list, with the
        // sponsor's fee witness as the only authorization the transaction carries.
        let message = lee::public_transaction::Message::try_new(
            programs::authenticated_transfer().id(),
            vec![from, to],
            vec![],
            authenticated_transfer_core::Instruction::Transfer { amount: 10 },
            common::test_utils::test_fee_fields(sponsor),
        )
        .expect("message builds");
        let public_tx = lee::PublicTransaction::new(
            message.clone(),
            lee::public_transaction::WitnessSet::for_message(&message, &[])
                .with_fee_signer(&message, &sponsor_key),
        );
        let tx = LeeTransaction::Public(public_tx.clone());

        // It really is charged, and really is fee-authorized: what rejects it below is the
        // replay-burn rule, not one of the checks that were already there.
        let view = charged_fee_view(&tx, &state).expect("a fee-witness-only transfer is charged");
        assert!(
            lee::is_fee_authorized(public_tx.message(), public_tx.witness_set()),
            "the fee witness alone satisfies payer authorization, which is the hole",
        );

        let block = produce_dummy_block(2, Some(tip.hash), vec![tx]);
        let err = apply_block(Some(&tip), &block, &mut state).expect_err("should reject");
        let BlockIngestError::FeeValidity {
            tx_index: 0,
            reason,
        } = &err
        else {
            panic!("expected a fee-validity rejection at tx 0, got {err:?}");
        };
        assert!(
            reason.contains("signer signature"),
            "expected the replay-burn rule to name itself, got: {reason}",
        );
        assert_eq!(
            state.get_account_by_id(sponsor).balance,
            before_sponsor,
            "the sponsor must not be debited by a transaction that burns no nonce",
        );

        // The builder runs the same gate, so it skips such a transaction instead of building a
        // block it would then reject itself.
        assert!(
            check_charged_tx(&public_tx, &view, &opening).is_err(),
            "the builder's gate must reject it too",
        );
    }

    /// The ordinary sponsored shape — one signer plus the payer's fee witness — is untouched by the
    /// rule above: it applies, the SPONSOR pays, and the SIGNER's nonce is what inclusion burns.
    #[test]
    fn a_sponsored_transaction_charges_the_sponsor_and_burns_the_signers_nonce() {
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();
        let to = accounts[1].account_id;
        let sponsor_key = lee::PrivateKey::try_new([34_u8; 32]).expect("valid key");
        let sponsor = lee::AccountId::from(&lee::PublicKey::new_from_private_key(&sponsor_key));

        let mut state = initial_state();
        state.force_insert_account(sponsor, funded_account(1_000_000_000_000));
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        let tip = tip_of(&genesis);
        let before_sponsor = state.get_account_by_id(sponsor).balance;
        let before_from = state.get_account_by_id(from).balance;
        let before_nonce = state.get_account_by_id(from).nonce;

        let tx = sponsored_transfer(from, to, 0, 10, &sign_key, sponsor, &sponsor_key);
        let block = produce_dummy_block(2, Some(tip.hash), vec![tx]);
        let summary = apply_block(Some(&tip), &block, &mut state).expect("the block applies");

        assert_eq!(summary.tx_outcomes.as_slice(), [TxApplyOutcome::Applied]);
        assert!(summary.revenue_base > 0, "the transaction was charged");
        assert_eq!(
            state.get_account_by_id(sponsor).balance,
            before_sponsor - summary.revenue_base,
            "the sponsor pays the fee, not the signer",
        );
        assert_eq!(
            state.get_account_by_id(from).balance,
            before_from - 10,
            "the signer pays only what it sent",
        );
        assert_eq!(
            state.get_account_by_id(from).nonce.0,
            before_nonce.0 + 1,
            "inclusion burns the signer's nonce",
        );
        assert_eq!(
            state.get_account_by_id(sponsor).nonce.0,
            0,
            "the sponsor signs no nonce, so it has none to burn",
        );
    }

    /// Both authorization routes at once: the payer is one of the signers *and* a redundant fee
    /// witness for itself rides along. Q1 is "at least one route verified", not "exactly one", so
    /// this is accepted — the extra witness is merely a signature that also happens to check out.
    #[test]
    fn a_payer_that_is_both_a_signer_and_a_fee_witness_is_accepted() {
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();
        let to = accounts[1].account_id;

        let mut state = initial_state();
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        let tip = tip_of(&genesis);
        let before_nonce = state.get_account_by_id(from).nonce;

        // Payer == signer, and the same key signs the fee witness too.
        let tx = sponsored_transfer(from, to, 0, 10, &sign_key, from, &sign_key);
        let block = produce_dummy_block(2, Some(tip.hash), vec![tx]);
        let summary = apply_block(Some(&tip), &block, &mut state).expect("the block applies");

        assert_eq!(summary.tx_outcomes.as_slice(), [TxApplyOutcome::Applied]);
        assert!(summary.revenue_base > 0);
        assert_eq!(
            state.get_account_by_id(from).nonce.0,
            before_nonce.0 + 1,
            "a redundant fee witness changes nothing about the nonce burn",
        );
    }

    /// A payer that cannot cover its reservation invalidates the whole block, rather than being
    /// skipped: inclusion is the producer's choice and its consequence.
    #[test]
    fn a_payer_that_cannot_cover_its_reserve_invalidates_the_block() {
        let mut state = initial_state();
        let accounts = initial_pub_accounts_private_keys();
        let pauper_key = lee::PrivateKey::try_new([77_u8; 32]).expect("valid key");
        let pauper = lee::AccountId::from(&lee::PublicKey::new_from_private_key(&pauper_key));

        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        let tip = tip_of(&genesis);

        // A brand-new account: zero balance, so it cannot hold any reservation at all.
        let tx = create_transaction_native_token_transfer(
            pauper,
            0_u64.into(),
            accounts[0].account_id,
            1,
            &pauper_key,
        );
        let block = produce_dummy_block(2, Some(tip.hash), vec![tx]);

        let err = apply_block(Some(&tip), &block, &mut state).expect_err("should reject");
        assert!(matches!(
            err,
            BlockIngestError::FeeValidity { tx_index: 0, .. }
        ));
    }

    /// A transaction that reverts is charged, has its replay nonces advanced, and leaves the block
    /// valid — and the replay of that same transaction is then statically invalid on its nonce.
    #[test]
    fn a_reverted_transaction_is_charged_and_cannot_be_replayed() {
        let mut state = initial_state();
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        let tip = tip_of(&genesis);

        let before_balance = state.get_account_by_id(from).balance;
        let before_nonce = state.get_account_by_id(from).nonce;

        // Transferring more than the account holds makes the program fail, so the diff is
        // discarded — but the transaction was included and metered.
        let doomed =
            create_transaction_native_token_transfer(from, 0_u64.into(), to, u128::MAX, &sign_key);
        let block = produce_dummy_block(2, Some(tip.hash), vec![doomed.clone()]);
        let summary = apply_block(Some(&tip), &block, &mut state).expect("block stays valid");

        assert!(matches!(
            summary.tx_outcomes.as_slice(),
            [TxApplyOutcome::Reverted { .. }]
        ));
        assert!(summary.revenue_base > 0, "a revert is still charged");
        assert_eq!(
            state.get_account_by_id(from).balance,
            before_balance - summary.revenue_base,
            "the fee is kept, the transfer is not",
        );
        assert_eq!(
            state.get_account_by_id(from).nonce.0,
            before_nonce.0 + 1,
            "replay protection is consumed on inclusion, success or revert",
        );

        // The same bytes again: the nonce it declares is now stale, so it is no longer includable.
        let tip = tip_of(&block);
        let replay = produce_dummy_block(3, Some(tip.hash), vec![doomed]);
        let err = apply_block(Some(&tip), &replay, &mut state).expect_err("replay is rejected");
        assert!(matches!(err, BlockIngestError::StateTransition { .. }));
    }

    /// A transaction that halts at its own `gas_limit` is charged exactly that limit's worth of
    /// execution gas plus its full storage gas, and the block stays valid.
    #[test]
    fn an_out_of_gas_transaction_is_charged_its_full_gas_limit() {
        let mut state = initial_state();
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        let tip = tip_of(&genesis);
        let before_balance = state.get_account_by_id(from).balance;

        // A gas limit of 1 cannot fund a single session, so the transaction halts immediately.
        let starved = signed_transfer_with_fees(
            from,
            to,
            0,
            10,
            &sign_key,
            lee::FeeFields::new(from, 1, 0, u128::from(u64::MAX)),
        );
        let data_bytes = u128::try_from(borsh::object_length(&starved).expect("serializes"))
            .expect("a transaction's serialized length fits u128");
        let block = produce_dummy_block(2, Some(tip.hash), vec![starved]);
        let summary = apply_block(Some(&tip), &block, &mut state).expect("block stays valid");

        assert!(matches!(
            summary.tx_outcomes.as_slice(),
            [TxApplyOutcome::Reverted { .. }]
        ));
        // Halting out of gas means the transaction really consumed at least its whole budget, so
        // `min(cycles, gas_limit)` is `gas_limit` — here 1. Asserted as a constant, not read back
        // off `summary`: deriving the expectation from the value under test would pass just as
        // happily at zero, which is exactly the metering hole this pins shut.
        assert_eq!(
            summary.gas_used_exec, 1,
            "an out-of-gas transaction is charged its full gas limit against the block cap",
        );
        // charged = min(cycles, gas_limit) * base_fee_exec + data_bytes * base_fee_stor.
        let expected = 8 + data_bytes * 8;
        assert_eq!(summary.revenue_base, expected);
        assert_eq!(
            state.get_account_by_id(from).balance,
            before_balance - expected,
        );
    }

    /// A guest panic — how a LEZ program signals a revert today — is charged and capped at the
    /// transaction's **whole `gas_limit`**, and the block stays valid.
    ///
    /// The executor bails without a `SessionInfo`, so the failing session's own cycles are gone and
    /// the bound the payer declared is the only sound price. Asserted exactly, against constants
    /// rather than values read back off `summary`, because the number is the point: metering this
    /// at the sessions that *completed* would bill a single-session revert at zero execution gas
    /// and let it ride the block's execution cap for free.
    ///
    /// TBA(revert-metering): the guest exit-code refactor (`.claude/lez-fees/EXIT-CODES.md`) makes
    /// a cooperative program's revert exit with a code, which halts as `Ok(SessionInfo)` and bills
    /// its real cycles — this test flips to that number then. The full-budget arm itself stays for
    /// ever, for programs that panic rather than exit.
    #[test]
    fn a_guest_panic_revert_is_charged_its_whole_gas_limit() {
        let mut state = initial_state();
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        let tip = tip_of(&genesis);
        let before_balance = state.get_account_by_id(from).balance;

        // A gas limit well below the default, so the charge below cannot be mistaken for a
        // coincidence with anything the transfer really costs (~82,000 cycles).
        let gas_limit: u64 = 1_000_000;
        let doomed = signed_transfer_with_fees(
            from,
            to,
            0,
            u128::MAX,
            &sign_key,
            lee::FeeFields::new(from, gas_limit, 0, u128::from(u64::MAX)),
        );
        let data_bytes = u128::try_from(borsh::object_length(&doomed).expect("serializes"))
            .expect("a transaction's serialized length fits u128");
        let block = produce_dummy_block(2, Some(tip.hash), vec![doomed]);
        let summary = apply_block(Some(&tip), &block, &mut state).expect("block stays valid");

        assert!(matches!(
            summary.tx_outcomes.as_slice(),
            [TxApplyOutcome::Reverted { .. }]
        ));
        assert_eq!(
            summary.gas_used_exec, gas_limit,
            "a panicking session is capped at the whole budget it was granted",
        );
        assert_eq!(
            summary.gas_used_stor,
            u64::try_from(data_bytes).expect("fits"),
            "a revert still occupies its bytes in the block",
        );
        // charged = gas_limit * base_fee_exec + data_bytes * base_fee_stor, both base fees at the
        // genesis minimum of 8.
        let expected = u128::from(gas_limit) * 8 + data_bytes * 8;
        assert_eq!(summary.revenue_base, expected);
        assert_eq!(
            state.get_account_by_id(from).balance,
            before_balance - expected,
        );

        // The builder sizes the same transaction the same way — this is the shape most likely to
        // drift, because the cycle count it is sized from does not exist.
        assert_eq!(
            cap_contribution(
                &block.body.transactions[0],
                &initial_state(),
                summary.gas_used_exec
            )
            .expect("a charged transaction is not cap-exempt")
            .gas_exec,
            gas_limit,
        );
    }

    /// `cap_contribution` — what the block builder sizes a block with — must equal what applying
    /// that same block actually accumulates. A drift here is a sequencer that builds blocks its own
    /// apply path rejects.
    ///
    /// Checked one transaction at a time so the equality is attributable, and over three fee
    /// classes: charged (metered against a `gas_limit`), uncharged-metered (a full vault sweep) and
    /// exempt (a clock invocation, which must contribute nothing).
    #[test]
    fn cap_contribution_matches_what_applying_the_block_accumulates() {
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let sweeper_key = lee::PrivateKey::try_new([55_u8; 32]).expect("valid key");
        let sweeper = lee::AccountId::from(&lee::PublicKey::new_from_private_key(&sweeper_key));
        let vault_id = vault_core::compute_vault_account_id(programs::vault().id(), sweeper);

        let cases = [
            (
                "charged transfer",
                signed_transfer_with_fees(
                    from,
                    to,
                    0,
                    10,
                    &sign_key,
                    common::test_utils::test_fee_fields(from),
                ),
            ),
            (
                "full vault sweep",
                vault_claim(sweeper, vault_id, 500_000_000, 0, &sweeper_key),
            ),
        ];

        for (label, tx) in cases {
            let mut state = initial_state();
            state.force_insert_account(
                vault_id,
                lee::Account {
                    program_owner: programs::authenticated_transfer().id(),
                    balance: 500_000_000,
                    ..lee::Account::default()
                },
            );
            let genesis = produce_dummy_block(1, None, vec![]);
            apply_block(None, &genesis, &mut state).expect("genesis applies");
            let tip = tip_of(&genesis);

            // The builder sizes against the working state at the transaction's turn, which for a
            // one-transaction block is the block's opening state — the same one `classify` is
            // handed here.
            let opening_state = state.clone();
            let block = produce_dummy_block(2, Some(tip.hash), vec![tx.clone()]);
            let summary = apply_block(Some(&tip), &block, &mut state).expect("applies");
            assert_eq!(
                summary.tx_outcomes.as_slice(),
                [TxApplyOutcome::Applied],
                "{label} must succeed for this comparison to mean anything",
            );

            let contribution = cap_contribution(&tx, &opening_state, summary.gas_used_exec)
                .unwrap_or_else(|| panic!("{label} is not cap-exempt"));
            assert_eq!(
                contribution.gas_exec, summary.gas_used_exec,
                "{label}: builder and apply disagree on execution gas",
            );
            assert_eq!(
                contribution.gas_stor, summary.gas_used_stor,
                "{label}: builder and apply disagree on storage gas",
            );
        }

        let state = initial_state();
        assert!(
            cap_contribution(
                &bridge_deposit_mint(to, 1_000, [7_u8; 32]),
                &state,
                u64::MAX
            )
            .is_none(),
            "a system transaction contributes to neither cap, whatever it metered",
        );
    }

    /// System transactions are exempt from fees *and* from both caps: a block carrying one leaves
    /// balances and the escrow exactly where an empty block would.
    #[test]
    fn system_transactions_are_free_and_consume_no_cap_budget() {
        let mut state = initial_state();

        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        let tip = tip_of(&genesis);

        // A clock-only block: the clock invocation is the archetypal system transaction.
        let block = produce_dummy_block(2, Some(tip.hash), vec![]);
        let summary = apply_block(Some(&tip), &block, &mut state).expect("applies");

        assert_eq!(summary.revenue_base, 0);
        assert_eq!(summary.revenue_tip, 0);
        assert_eq!(summary.gas_used_exec, 0, "system gas is not counted");
        assert_eq!(summary.gas_used_stor, 0, "system bytes are not counted");
        assert_eq!(state.fee_state().escrow, 0);
    }

    /// A full vault sweep is the ledger's bootstrap transaction: it is fee-exempt, because the
    /// account it funds has nothing to pay with until it lands. It still consumes cap budget, and
    /// its nonce advances the ordinary way, through its diff.
    #[test]
    fn a_full_vault_sweep_is_exempt_but_capped() {
        let sweeper_key = lee::PrivateKey::try_new([55_u8; 32]).expect("valid key");
        let sweeper = lee::AccountId::from(&lee::PublicKey::new_from_private_key(&sweeper_key));
        let vault_id = vault_core::compute_vault_account_id(programs::vault().id(), sweeper);

        // The shape genesis and bridge deposits leave behind: funds in the vault, nothing on the
        // account itself.
        let mut state = initial_state();
        state.force_insert_account(
            vault_id,
            lee::Account {
                program_owner: programs::authenticated_transfer().id(),
                balance: 500_000_000,
                ..lee::Account::default()
            },
        );

        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        let tip = tip_of(&genesis);
        assert_eq!(state.get_account_by_id(sweeper).balance, 0);

        let claim = vault_claim(sweeper, vault_id, 500_000_000, 0, &sweeper_key);
        let block = produce_dummy_block(2, Some(tip.hash), vec![claim]);
        let summary = apply_block(Some(&tip), &block, &mut state).expect("the sweep applies");

        assert_eq!(summary.revenue_base, 0, "a full sweep is not charged");
        assert_eq!(state.fee_state().escrow, 0);
        assert!(
            summary.gas_used_exec > 0 && summary.gas_used_stor > 0,
            "uncharged is not uncapped: the sweep still consumes cap budget",
        );
        assert_eq!(state.get_account_by_id(sweeper).balance, 500_000_000);
        assert_eq!(
            state.get_account_by_id(sweeper).nonce.0,
            1,
            "a successful sweep advances its nonce through its diff, like any other transaction",
        );
    }

    /// A partial claim is an ordinary charged transaction, so an account with nothing on it cannot
    /// pay for one — only the full sweep bootstraps.
    #[test]
    fn a_partial_vault_claim_is_charged() {
        let sweeper_key = lee::PrivateKey::try_new([56_u8; 32]).expect("valid key");
        let sweeper = lee::AccountId::from(&lee::PublicKey::new_from_private_key(&sweeper_key));
        let vault_id = vault_core::compute_vault_account_id(programs::vault().id(), sweeper);

        let mut state = initial_state();
        state.force_insert_account(
            vault_id,
            lee::Account {
                program_owner: programs::authenticated_transfer().id(),
                balance: 500_000_000,
                ..lee::Account::default()
            },
        );
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        let tip = tip_of(&genesis);

        // One unit short of the vault balance: charged, and unaffordable at a zero balance.
        let claim = vault_claim(sweeper, vault_id, 499_999_999, 0, &sweeper_key);
        let block = produce_dummy_block(2, Some(tip.hash), vec![claim]);
        let err = apply_block(Some(&tip), &block, &mut state).expect_err("should reject");
        assert!(matches!(
            err,
            BlockIngestError::FeeValidity { tx_index: 0, .. }
        ));
    }

    /// A block whose cumulative metered cycles exceed `MAX_GAS_EXEC` is rejected whole, and the
    /// resources are not fungible: a storage surplus does not offset an execution deficit.
    #[test]
    fn a_block_over_the_execution_cap_is_rejected_whole() {
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let build = |count: u64, state: &mut V03State| {
            let genesis = produce_dummy_block(1, None, vec![]);
            apply_block(None, &genesis, state).expect("genesis applies");
            let tip = tip_of(&genesis);
            let txs: Vec<_> = (0..count)
                .map(|nonce| {
                    create_transaction_native_token_transfer(from, nonce.into(), to, 10, &sign_key)
                })
                .collect();
            (tip.clone(), produce_dummy_block(2, Some(tip.hash), txs))
        };

        // Measure one transfer, then build a block of however many it takes to go over. Measured
        // rather than hard-coded: the cost of a transfer moves whenever its program does, and a
        // stale constant would quietly stop testing the cap.
        let mut probe = initial_state();
        let (tip, one) = build(1, &mut probe);
        let per_tx = apply_block(Some(&tip), &one, &mut probe)
            .expect("one transfer applies")
            .gas_used_exec;
        assert!(per_tx > 0, "a transfer must meter something");
        let over_the_cap = (MAX_GAS_EXEC / per_tx) + 1;

        let mut state = initial_state();
        let (tip, block) = build(over_the_cap, &mut state);
        let err = apply_block(Some(&tip), &block, &mut state)
            .expect_err("a block over the execution cap must be rejected");
        assert!(
            matches!(err, BlockIngestError::GasCapExceeded { .. }),
            "expected a gas-cap rejection, got {err:?}",
        );
        // `state` is scratch here, as the entry point's contract requires: the transactions that
        // did fit are still in it, and the caller is the one that throws it away on `Err`.

        // One transaction fewer, and the same block applies — so it is the cap that rejected it.
        let mut state = initial_state();
        let (tip, block) = build(over_the_cap - 1, &mut state);
        let summary = apply_block(Some(&tip), &block, &mut state)
            .expect("a block just under the execution cap applies");
        assert!(summary.gas_used_exec <= MAX_GAS_EXEC);
    }

    /// The storage cap is checked *before* a single zkVM session runs, so a block that busts it is
    /// rejected without executing anything.
    ///
    /// Driven through the real `apply_block`, not the helper: what matters is that the pass sits
    /// ahead of the execution loop in `apply_block_to_state`.
    #[test]
    fn a_block_over_the_storage_cap_is_rejected_before_any_execution() {
        let tx = produce_dummy_empty_transaction();
        let per_tx = u64::try_from(borsh::object_length(&tx).expect("serializes")).expect("fits");
        let over_the_cap = (MAX_GAS_STOR / per_tx) + 1;

        let mut state = initial_state();
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        let tip = tip_of(&genesis);
        let before = state.clone();

        // Every one of these is the same transaction, which would fail its replay check the moment
        // it executed. None of them gets that far.
        let block = produce_dummy_block(
            2,
            Some(tip.hash),
            std::iter::repeat_n(tx, usize::try_from(over_the_cap).expect("fits")).collect(),
        );
        let err = apply_block(Some(&tip), &block, &mut state)
            .expect_err("a block over the storage cap must be rejected");
        let BlockIngestError::GasCapExceeded { reason } = &err else {
            panic!("expected a gas-cap rejection, got {err:?}");
        };
        assert!(
            reason.contains("storage"),
            "expected the storage cap to be the one that fired, got: {reason}",
        );
        assert_eq!(
            borsh::to_vec(&state).expect("state serializes"),
            borsh::to_vec(&before).expect("state serializes"),
            "nothing executed, so nothing moved",
        );
    }

    /// A private transaction counts against both caps and is charged nothing.
    ///
    /// Asserted through the classification the block transition and the block builder both use, so
    /// it needs no valid proof: the point is the fee class, not the cryptography.
    #[test]
    fn a_private_transaction_is_capped_but_not_charged() {
        let state = initial_state();
        let tx = dummy_private_transaction();

        assert!(
            charged_fee_view(&tx, &state).is_none(),
            "a private transaction is not charged",
        );
        let contribution =
            cap_contribution(&tx, &state, u64::MAX).expect("but it is not cap-exempt either");
        assert_eq!(
            contribution.gas_exec, PRIVATE_VERIFY_GAS,
            "its execution gas is the protocol constant, not what it metered",
        );
        assert_eq!(
            contribution.gas_stor,
            u64::try_from(borsh::object_length(&tx).expect("serializes")).expect("fits"),
            "and its storage gas is its real wire size",
        );
    }

    /// A program deployment counts against the storage cap and is charged nothing, driven through
    /// a real block so the ledger effect is checked too.
    #[test]
    fn a_deployment_is_capped_but_not_charged() {
        let accounts = initial_pub_accounts_private_keys();
        let deployer = accounts[0].account_id;

        let mut state = initial_state();
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        let tip = tip_of(&genesis);
        let before_balance = state.get_account_by_id(deployer).balance;
        let before_escrow = state.fee_state().escrow;

        let tx = deployment_transaction();
        let wire = u64::try_from(borsh::object_length(&tx).expect("serializes")).expect("fits");
        assert!(
            charged_fee_view(&tx, &state).is_none(),
            "a deployment is not charged",
        );

        let block = produce_dummy_block(2, Some(tip.hash), vec![tx]);
        let summary = apply_block(Some(&tip), &block, &mut state).expect("the deployment applies");

        assert_eq!(summary.tx_outcomes.as_slice(), [TxApplyOutcome::Applied]);
        assert_eq!(summary.revenue_base, 0, "nothing was charged");
        assert_eq!(summary.revenue_tip, 0);
        assert_eq!(
            summary.gas_used_exec, 0,
            "a deployment runs no zkVM session",
        );
        assert_eq!(
            summary.gas_used_stor, wire,
            "but its bytes are posted to Bedrock like anything else's",
        );
        assert_eq!(
            state.get_account_by_id(deployer).balance,
            before_balance,
            "no payer was debited",
        );
        assert_eq!(state.fee_state().escrow, before_escrow);
    }

    /// The other system shape — a sequencer-injected bridge-deposit mint, which unlike the clock
    /// travels inside the block body — is fee- and cap-exempt.
    ///
    /// Asserted through the classification the block transition and the block builder share rather
    /// than by executing the mint: the bridge guest artifact in `artifacts/` does not currently
    /// deserialize a `bridge_core::Instruction::Deposit` built from this workspace's `bridge_core`
    /// (`DeserializeUnexpectedEnd`), which is a build-artifact problem of its own and nothing to do
    /// with the fee class under test here. See the task report.
    #[test]
    fn a_bridge_deposit_mint_is_free_and_consumes_no_cap_budget() {
        let state = initial_state();
        let recipient = initial_pub_accounts_private_keys()[1].account_id;
        let mint = bridge_deposit_mint(recipient, 1_000, [7_u8; 32]);

        assert!(
            charged_fee_view(&mint, &state).is_none(),
            "a system transaction is not charged",
        );
        assert!(
            cap_contribution(&mint, &state, u64::MAX).is_none(),
            "and it consumes no cap budget, whatever it metered",
        );

        // The exemption is the *unsigned* shape, not the instruction: the same mint with a user's
        // signature on it is an ordinary charged transaction. This is what stops a user minting
        // themselves free, uncapped block space.
        let LeeTransaction::Public(public_tx) = &mint else {
            unreachable!("the mint is a public transaction");
        };
        let signer = lee::PrivateKey::try_new([9_u8; 32]).expect("valid key");
        let forged = LeeTransaction::Public(lee::PublicTransaction::new(
            public_tx.message().clone(),
            lee::public_transaction::WitnessSet::for_message(public_tx.message(), &[&signer]),
        ));
        assert!(
            cap_contribution(&forged, &state, 0).is_some(),
            "a signed deposit-shaped transaction must be capped like any other",
        );
    }

    /// The producer's payout lands in an account `credit_fee` materialized: non-zero balance,
    /// `program_owner` still the default. Nothing can adopt such an account afterwards, so a
    /// producer that is paid *before* it initializes its account can never spend what it earned.
    ///
    /// Both halves are pinned here because the difference is operational, not cryptographic:
    ///
    /// * A producer that initializes first — which needs a sponsor, since it has nothing to pay the
    ///   initialization's own fee with — owns its account, and every later payout is spendable.
    /// * A producer that does not is stuck. `Initialize` asserts the account is untouched, and a
    ///   `Transfer` to it violates the execution rule that a post-state may only carry the default
    ///   owner if the pre-state was a default account. The claim `Transfer` emits never gets
    ///   applied, because output validation runs first.
    ///
    /// Left as it is rather than fixed here: every candidate fix changes program semantics or the
    /// claim rules. See the task-8 report for the options.
    #[test]
    fn a_producers_payout_is_spendable_only_if_it_initialized_first() {
        let accounts = initial_pub_accounts_private_keys();
        let sponsor = accounts[0].account_id;
        let sponsor_key = accounts[0].pub_sign_key.clone();
        let other = accounts[1].account_id;
        let producer_key = sequencer_sign_key_for_testing();
        let producer = lee::AccountId::from(&sequencer_producer_key_for_testing());

        // A block that pays the producer, from a state the caller chooses.
        let charged_block = |nonce: u128, id: u64, prev: HashType, sign_key: &lee::PrivateKey| {
            let tx = create_transaction_native_token_transfer(sponsor, nonce, other, 10, sign_key);
            produce_dummy_block(id, Some(prev), vec![tx])
        };

        // --- The working route: initialize before earning anything. -------------------------
        let mut state = initial_state();
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        let tip = tip_of(&genesis);

        // The producer signs its own initialization; the sponsor pays for it, because the producer
        // has nothing yet. This is the whole reason the fee witness exists.
        let message = lee::public_transaction::Message::try_new(
            programs::authenticated_transfer().id(),
            vec![producer],
            vec![0_u128.into()],
            authenticated_transfer_core::Instruction::Initialize,
            common::test_utils::test_fee_fields(sponsor),
        )
        .expect("message builds");
        let init = LeeTransaction::Public(lee::PublicTransaction::new(
            message.clone(),
            lee::public_transaction::WitnessSet::for_message(&message, &[&producer_key])
                .with_fee_signer(&message, &sponsor_key),
        ));
        let block = produce_dummy_block(2, Some(tip.hash), vec![init]);
        let summary = apply_block(Some(&tip), &block, &mut state).expect("the block is valid");
        assert_eq!(
            summary.tx_outcomes.as_slice(),
            [TxApplyOutcome::Applied],
            "a sponsored initialization of a pristine producer account must succeed",
        );
        assert_eq!(
            state.get_account_by_id(producer).program_owner,
            programs::authenticated_transfer().id(),
        );

        let tip = tip_of(&block);
        let before_payout = state.get_account_by_id(producer).balance;
        let block = charged_block(0, 3, tip.hash, &sponsor_key);
        let summary = apply_block(Some(&tip), &block, &mut state).expect("applies");
        let earned = state.get_account_by_id(producer).balance;
        assert_eq!(
            earned - before_payout,
            summary.payout,
            "the producer was paid this block's payout",
        );
        assert!(earned > 0);

        // A payout is a fiftieth of one block's revenue, which is far below a transaction's own
        // reservation, so top the producer up before it spends — which is itself the point: an
        // initialized producer account is an ordinary account that can both receive and send.
        let tip = tip_of(&block);
        let top_up: u128 = 100_000_000;
        let fund = create_transaction_native_token_transfer(
            sponsor,
            1_u128,
            producer,
            top_up,
            &sponsor_key,
        );
        let block = produce_dummy_block(4, Some(tip.hash), vec![fund]);
        let summary = apply_block(Some(&tip), &block, &mut state).expect("valid");
        assert_eq!(summary.tx_outcomes.as_slice(), [TxApplyOutcome::Applied]);

        let tip = tip_of(&block);
        let before_other = state.get_account_by_id(other).balance;
        let producer_balance = state.get_account_by_id(producer).balance;
        assert!(
            producer_balance > top_up,
            "the balance the producer is about to spend includes the payout it earned",
        );
        // Nonce 1: the initialization above consumed the producer's first.
        let spend = create_transaction_native_token_transfer(
            producer,
            1_u128,
            other,
            earned,
            &producer_key,
        );
        let block = produce_dummy_block(5, Some(tip.hash), vec![spend]);
        let summary = apply_block(Some(&tip), &block, &mut state).expect("valid");
        assert_eq!(summary.tx_outcomes.as_slice(), [TxApplyOutcome::Applied]);
        assert_eq!(
            state.get_account_by_id(other).balance,
            before_other + earned,
            "an initialized producer can spend what it earned",
        );

        // --- The dead route: earn first, and the account can never be adopted. ---------------
        let mut state = initial_state();
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        let tip = tip_of(&genesis);
        let block = charged_block(0, 2, tip.hash, &sponsor_key);
        apply_block(Some(&tip), &block, &mut state).expect("applies");
        let tip = tip_of(&block);

        assert!(state.get_account_by_id(producer).balance > 0);
        assert_eq!(
            state.get_account_by_id(producer).program_owner,
            lee_core::program::DEFAULT_PROGRAM_ID,
            "credit_fee materialized the account without an owner",
        );

        // `Initialize` asserts the account is untouched.
        let message = lee::public_transaction::Message::try_new(
            programs::authenticated_transfer().id(),
            vec![producer],
            vec![0_u128.into()],
            authenticated_transfer_core::Instruction::Initialize,
            common::test_utils::test_fee_fields(sponsor),
        )
        .expect("message builds");
        let init = LeeTransaction::Public(lee::PublicTransaction::new(
            message.clone(),
            lee::public_transaction::WitnessSet::for_message(&message, &[&producer_key])
                .with_fee_signer(&message, &sponsor_key),
        ));
        let block = produce_dummy_block(3, Some(tip.hash), vec![init]);
        let summary = apply_block(Some(&tip), &block, &mut state).expect("the block stays valid");
        assert!(
            matches!(
                summary.tx_outcomes.as_slice(),
                [TxApplyOutcome::Reverted { .. }]
            ),
            "initializing an account that already holds a payout must revert, got {:?}",
            summary.tx_outcomes,
        );
        let tip = tip_of(&block);

        // And a transfer *to* it, co-signed by it, cannot claim it either.
        let message = lee::public_transaction::Message::try_new(
            programs::authenticated_transfer().id(),
            vec![sponsor, producer],
            // Both signers are at nonce 1: the sponsor from the charged block, the producer from
            // the reverted initialization — a revert consumes replay protection too.
            vec![1_u128.into(), 1_u128.into()],
            authenticated_transfer_core::Instruction::Transfer { amount: 1 },
            common::test_utils::test_fee_fields(sponsor),
        )
        .expect("message builds");
        let adopt = LeeTransaction::Public(lee::PublicTransaction::new(
            message.clone(),
            lee::public_transaction::WitnessSet::for_message(
                &message,
                &[&sponsor_key, &producer_key],
            ),
        ));
        let block = produce_dummy_block(4, Some(tip.hash), vec![adopt]);
        let summary = apply_block(Some(&tip), &block, &mut state).expect("the block stays valid");
        assert!(
            matches!(
                summary.tx_outcomes.as_slice(),
                [TxApplyOutcome::Reverted { .. }]
            ),
            "a transfer cannot adopt an account that already holds a balance, got {:?}",
            summary.tx_outcomes,
        );
        assert_eq!(
            state.get_account_by_id(producer).program_owner,
            lee_core::program::DEFAULT_PROGRAM_ID,
            "the payout stays stranded",
        );
    }

    // Indexer/sequencer replay parity is tested where the indexer actually replays:
    // `indexer_core::block_store::tests::indexer_reproduces_the_sequencers_fee_state_across_a_revert`
    // drives the real `accept_block` (RocksDB, breakpoints, state reconstruction) over a chain that
    // includes a reverted transaction, and compares its fee state and accounts against a state
    // built here. A test in this module could only call `apply_block_to_state` twice and show that
    // it is deterministic, which is what this one used to do.

    // Helpers for the fee tests.

    /// An ordinary spendable account holding `balance`: what an initialized payer looks like.
    fn funded_account(balance: u128) -> lee::Account {
        lee::Account {
            program_owner: programs::authenticated_transfer().id(),
            balance,
            ..lee::Account::default()
        }
    }

    /// A transfer signed by `sign_key` but paid for by `payer`, whose fee witness rides along.
    /// `payer` may be the signer itself, which is the both-routes case.
    fn sponsored_transfer(
        from: lee::AccountId,
        to: lee::AccountId,
        nonce: u128,
        amount: u128,
        sign_key: &lee::PrivateKey,
        payer: lee::AccountId,
        payer_key: &lee::PrivateKey,
    ) -> LeeTransaction {
        let message = lee::public_transaction::Message::try_new(
            programs::authenticated_transfer().id(),
            vec![from, to],
            vec![nonce.into()],
            authenticated_transfer_core::Instruction::Transfer { amount },
            common::test_utils::test_fee_fields(payer),
        )
        .expect("message builds");
        let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[sign_key])
            .with_fee_signer(&message, payer_key);
        LeeTransaction::Public(lee::PublicTransaction::new(message, witness_set))
    }

    fn signed_transfer_with_fees(
        from: lee::AccountId,
        to: lee::AccountId,
        nonce: u128,
        amount: u128,
        sign_key: &lee::PrivateKey,
        fees: lee::FeeFields,
    ) -> LeeTransaction {
        let message = lee::public_transaction::Message::try_new(
            programs::authenticated_transfer().id(),
            vec![from, to],
            vec![nonce.into()],
            authenticated_transfer_core::Instruction::Transfer { amount },
            fees,
        )
        .expect("message builds");
        let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[sign_key]);
        LeeTransaction::Public(lee::PublicTransaction::new(message, witness_set))
    }

    /// A syntactically well-formed privacy-preserving transaction with a placeholder proof.
    ///
    /// Good enough for everything that classifies or *counts* a private transaction, none of which
    /// looks at the proof: the fee class of a private transaction is structural.
    fn dummy_private_transaction() -> LeeTransaction {
        use lee::privacy_preserving_transaction::{
            Message, PrivacyPreservingTransaction, WitnessSet, circuit::Proof,
        };
        use lee_core::program::{BlockValidityWindow, TimestampValidityWindow};

        let message = Message {
            public_actions: vec![],
            nonces: vec![],
            private_actions: vec![],
            block_validity_window: BlockValidityWindow::new_unbounded(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
        };
        LeeTransaction::PrivacyPreserving(PrivacyPreservingTransaction::new(
            message,
            WitnessSet::from_raw_parts(vec![], Proof::from_inner(vec![])),
        ))
    }

    /// A program-deployment transaction that deploys cleanly.
    fn deployment_transaction() -> LeeTransaction {
        let message = lee::program_deployment_transaction::Message::new(
            programs::pinata().elf().to_owned(),
            lee::FeeFields::ZERO,
        );
        LeeTransaction::ProgramDeployment(lee::ProgramDeploymentTransaction::new(
            message,
            lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
        ))
    }

    /// The sequencer's own bridge-deposit mint: unsigned, which is what makes it a system
    /// transaction rather than a shape any user could submit. Mirrors
    /// `sequencer_core::build_bridge_deposit_tx_from_event`.
    fn bridge_deposit_mint(
        recipient_id: lee::AccountId,
        amount: u64,
        l1_deposit_op_id: [u8; 32],
    ) -> LeeTransaction {
        let bridge_program_id = programs::bridge().id();
        let vault_program_id = programs::vault().id();
        let message = lee::public_transaction::Message::try_new(
            bridge_program_id,
            vec![
                system_accounts::bridge_account_id(),
                vault_core::compute_vault_account_id(vault_program_id, recipient_id),
                bridge_core::deposit_receipt_account_id(bridge_program_id, l1_deposit_op_id),
            ],
            vec![],
            bridge_core::Instruction::Deposit {
                l1_deposit_op_id,
                vault_program_id,
                recipient_id,
                amount,
            },
            lee::FeeFields::ZERO,
        )
        .expect("deposit message builds");
        LeeTransaction::Public(lee::PublicTransaction::new(
            message,
            lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
        ))
    }

    /// A `vault::Claim` of `amount`, paid for by the owner (which is what makes a *partial* claim
    /// charged and a full sweep exempt).
    fn vault_claim(
        owner: lee::AccountId,
        vault_id: lee::AccountId,
        amount: u128,
        nonce: u128,
        sign_key: &lee::PrivateKey,
    ) -> LeeTransaction {
        let message = lee::public_transaction::Message::try_new(
            programs::vault().id(),
            vec![owner, vault_id],
            vec![nonce.into()],
            vault_core::Instruction::Claim { amount },
            common::test_utils::test_fee_fields(owner),
        )
        .expect("message builds");
        let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[sign_key]);
        LeeTransaction::Public(lee::PublicTransaction::new(message, witness_set))
    }
}
