//! The single validate-then-apply entry point shared by the sequencer and the
//! indexer. Pure and storage-free: callers apply on a scratch clone of state and
//! commit only on `Ok`.

use common::{
    HashType,
    block::Block,
    transaction::{LeeTransaction, clock_invocation},
};
use lee::{GENESIS_BLOCK_ID, V03State};

use crate::ingest_error::BlockIngestError;

/// The parent the next block must chain on.
// `l1_slot` will be added here when the `ChainState` anchor layer lands.
#[derive(Debug, Clone)]
pub struct Tip {
    pub block_id: u64,
    pub hash: HashType,
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
fn validate_against_tip(tip: Option<&Tip>, block: &Block) -> Result<(), BlockIngestError> {
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
fn apply_block_to_state(block: &Block, state: &mut V03State) -> Result<(), BlockIngestError> {
    let (clock_tx, user_txs) = block
        .body
        .transactions
        .split_last()
        .ok_or(BlockIngestError::EmptyBlock)?;

    let expected_clock = LeeTransaction::Public(clock_invocation(block.header.timestamp));
    if *clock_tx != expected_clock {
        return Err(BlockIngestError::InvalidClockTransaction);
    }

    let is_genesis = block.header.block_id == GENESIS_BLOCK_ID;
    for (tx_index, transaction) in user_txs.iter().enumerate() {
        let state_transition = |err: anyhow::Error| BlockIngestError::StateTransition {
            tx_index: tx_index.try_into().expect("tx index fits in u64"),
            reason: format!("{err:#}"),
        };
        if is_genesis {
            let LeeTransaction::Public(public_tx) = transaction else {
                return Err(BlockIngestError::NonPublicGenesisTransaction);
            };
            state
                .transition_from_public_transaction(
                    public_tx,
                    block.header.block_id,
                    block.header.timestamp,
                )
                .map_err(|err| state_transition(err.into()))?;
        } else {
            transaction
                .clone()
                .execute_on_state(state, block.header.block_id, block.header.timestamp)
                .map_err(|err| state_transition(err.into()))?;
        }
    }

    let LeeTransaction::Public(clock_public_tx) = clock_tx else {
        return Err(BlockIngestError::InvalidClockTransaction);
    };
    state
        .transition_from_public_transaction(
            clock_public_tx,
            block.header.block_id,
            block.header.timestamp,
        )
        .map_err(|err| BlockIngestError::StateTransition {
            tx_index: user_txs.len().try_into().expect("tx index fits in u64"),
            reason: format!("{:#}", anyhow::Error::from(err)),
        })?;

    Ok(())
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
        Tip {
            block_id: block.header.block_id,
            hash: block.header.hash,
        }
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

        // Genesis (block 1): clock-only.
        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        let mut tip = tip_of(&genesis);

        // Blocks 2..=11: one native transfer of 10 each (nonces 0..=9).
        for i in 0..10_u64 {
            let tx = create_transaction_native_token_transfer(from, i.into(), to, 10, &sign_key);
            let block = produce_dummy_block(i + 2, Some(tip.hash), vec![tx]);
            apply_block(Some(&tip), &block, &mut state).expect("transfer applies");
            tip = tip_of(&block);
        }

        assert_eq!(state.get_account_by_id(from).balance, 9900);
        assert_eq!(state.get_account_by_id(to).balance, 20100);
    }
}
