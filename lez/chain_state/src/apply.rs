//! The single validate-then-apply entry point shared by the sequencer and the
//! indexer. Pure and storage-free: callers apply on a scratch clone of state and
//! commit only on `Ok`.

use common::{
    HashType,
    block::{Block, BlockMeta},
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
pub fn apply_block_to_state(block: &Block, state: &mut V03State) -> Result<(), BlockIngestError> {
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

    state
        .transition_from_public_transaction(clock_tx, block.header.block_id, block.header.timestamp)
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

    #[test]
    fn fee_state_is_untouched_by_block_application() {
        // The fee state is carried by consensus state but not yet driven by the
        // block transition: applying blocks must leave it exactly at genesis.
        // The block transition (T8) flips this deliberately.
        let mut state = initial_state();
        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let genesis = produce_dummy_block(1, None, vec![]);
        apply_block(None, &genesis, &mut state).expect("genesis applies");
        let tip = tip_of(&genesis);

        let tx = create_transaction_native_token_transfer(from, 0_u64.into(), to, 10, &sign_key);
        let block = produce_dummy_block(2, Some(tip.hash), vec![tx]);
        apply_block(Some(&tip), &block, &mut state).expect("transfer applies");

        assert_eq!(
            state.fee_state(),
            &lee::FeeState::genesis().expect("valid fee parameters")
        );
    }
}
