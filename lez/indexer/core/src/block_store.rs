use std::{path::Path, sync::Arc};

use anyhow::{Context as _, Result};
use common::{
    HashType,
    block::{BedrockStatus, Block, BlockHeader},
    transaction::{LeeTransaction, clock_invocation},
};
use lee::{Account, AccountId, GENESIS_BLOCK_ID, V03State};
use lee_core::BlockId;
use log::warn;
use logos_blockchain_core::header::HeaderId;
use logos_blockchain_zone_sdk::Slot;
use storage::{BREAKPOINT_INTERVAL, indexer::RocksDBIO};
use tokio::sync::RwLock;

use crate::{ingest_error::BlockIngestError, stall_reason::StallReason};

struct Tip {
    block_id: u64,
    hash: HashType,
}

/// Outcome of feeding a parsed L2 block to the validated tip.
pub enum AcceptOutcome {
    /// Chained and applied; tip and L1 read cursor both advance.
    Applied,
    /// A duplicate re-delivery of the current tip. Just L2 advances.
    AlreadyApplied,
    /// Did not chain or failed to apply; tip stays frozen, stall recorded.
    Parked(BlockIngestError),
    /// Chained but failed to apply, possibly transiently
    /// ([`BlockIngestError::is_retryable`]); nothing recorded, tip and state
    /// untouched. The caller retries and parks via
    /// [`IndexerStore::record_stall`] once it gives up.
    ApplyFailed(BlockIngestError),
}

#[derive(Clone)]
pub struct IndexerStore {
    dbio: Arc<RocksDBIO>,
    current_state: Arc<RwLock<V03State>>,
}

impl IndexerStore {
    /// Starting database at the start of new chain.
    /// Creates files if necessary.
    pub fn open_db(location: &Path) -> Result<Self> {
        #[cfg(not(feature = "testnet"))]
        let initial_state = testnet_initial_state::initial_state();

        #[cfg(feature = "testnet")]
        let initial_state = testnet_initial_state::initial_state_testnet();

        let dbio = RocksDBIO::open_or_create(location, &initial_state)?;

        let current_state = dbio.final_state()?;

        Ok(Self {
            dbio: Arc::new(dbio),
            current_state: Arc::new(RwLock::new(current_state)),
        })
    }

    pub fn last_observed_l1_lib_header(&self) -> Result<Option<HeaderId>> {
        Ok(self
            .dbio
            .get_meta_last_observed_l1_lib_header_in_db()?
            .map(HeaderId::from))
    }

    pub fn get_last_block_id(&self) -> Result<Option<u64>> {
        self.dbio.get_meta_last_block_id_in_db().map_err(Into::into)
    }

    pub fn get_block_at_id(&self, id: u64) -> Result<Option<Block>> {
        Ok(self.dbio.get_block(id)?)
    }

    pub fn get_block_batch(&self, before: Option<BlockId>, limit: u64) -> Result<Vec<Block>> {
        Ok(self.dbio.get_block_batch(before, limit)?)
    }

    pub fn get_transaction_by_hash(&self, tx_hash: [u8; 32]) -> Result<Option<LeeTransaction>> {
        let Some(block_id) = self.dbio.get_block_id_by_tx_hash(tx_hash)? else {
            return Ok(None);
        };
        let Some(block) = self.get_block_at_id(block_id)? else {
            return Ok(None);
        };
        Ok(block
            .body
            .transactions
            .into_iter()
            .find(|enc_tx| enc_tx.hash().0 == tx_hash))
    }

    pub fn get_block_by_hash(&self, hash: [u8; 32]) -> Result<Option<Block>> {
        let Some(id) = self.dbio.get_block_id_by_hash(hash)? else {
            return Ok(None);
        };
        self.get_block_at_id(id)
    }

    pub fn get_transactions_by_account(
        &self,
        acc_id: [u8; 32],
        offset: u64,
        limit: u64,
    ) -> Result<Vec<LeeTransaction>> {
        Ok(self.dbio.get_acc_transactions(acc_id, offset, limit)?)
    }

    pub fn genesis_id(&self) -> Result<Option<u64>> {
        self.dbio
            .get_meta_first_block_id_in_db()
            .map_err(Into::into)
    }

    pub fn last_block(&self) -> Result<Option<u64>> {
        self.dbio.get_meta_last_block_id_in_db().map_err(Into::into)
    }

    pub fn get_state_at_block(&self, block_id: u64) -> Result<V03State> {
        Ok(self.dbio.calculate_state_for_id(block_id)?)
    }

    pub fn get_zone_cursor(&self) -> Result<Option<Slot>> {
        let Some(bytes) = self.dbio.get_zone_sdk_indexer_cursor_bytes()? else {
            return Ok(None);
        };
        let cursor: Slot = serde_json::from_slice(&bytes)
            .context("Failed to deserialize stored zone-sdk indexer cursor")?;
        Ok(Some(cursor))
    }

    pub fn set_zone_cursor(&self, cursor: &Slot) -> Result<()> {
        let bytes =
            serde_json::to_vec(cursor).context("Failed to serialize zone-sdk indexer cursor")?;
        self.dbio.put_zone_sdk_indexer_cursor_bytes(&bytes)?;
        Ok(())
    }

    /// The L1 inscription slot of the validated tip, written atomically with it
    /// by [`Self::accept_block`]. `None` on a cold store or one written before
    /// the slot was recorded.
    pub fn get_tip_slot(&self) -> Result<Option<Slot>> {
        Ok(self.dbio.get_meta_tip_slot_in_db()?.map(Slot::from))
    }

    pub fn get_stall_reason(&self) -> Result<Option<StallReason>> {
        let Some(bytes) = self.dbio.get_stall_reason_bytes()? else {
            return Ok(None);
        };
        let stall: Option<StallReason> =
            serde_json::from_slice(&bytes).context("Failed to deserialize stored stall reason")?;
        Ok(stall)
    }

    pub fn set_stall_reason(&self, stall: &Option<StallReason>) -> Result<()> {
        let bytes = serde_json::to_vec(stall).context("Failed to serialize stall reason")?;
        self.dbio.put_stall_reason_bytes(&bytes)?;
        Ok(())
    }

    /// Clears a recorded stall marker if one is present, skipping the write otherwise.
    fn clear_stall_if_present(&self) -> Result<()> {
        if self.get_stall_reason()?.is_some() {
            self.set_stall_reason(&None)?;
        }
        Ok(())
    }

    /// Recalculation of final state directly from DB.
    ///
    /// Used for indexer healthcheck.
    pub fn recalculate_final_state(&self) -> Result<V03State> {
        Ok(self.dbio.final_state()?)
    }

    pub async fn account_current_state(&self, account_id: &AccountId) -> Result<Account> {
        Ok(self
            .current_state
            .read()
            .await
            .get_account_by_id(*account_id))
    }

    pub fn account_state_at_block(&self, account_id: &AccountId, block_id: u64) -> Result<Account> {
        Ok(self
            .get_state_at_block(block_id)?
            .get_account_by_id(*account_id))
    }

    /// The last successfully applied block, or `None` on a cold store.
    /// Read fresh from the store each call.
    fn validated_tip(&self) -> Result<Option<Tip>> {
        let Some(block_id) = self.dbio.get_meta_last_block_id_in_db()? else {
            return Ok(None);
        };
        let Some(block) = self.dbio.get_block(block_id)? else {
            return Ok(None);
        };
        Ok(Some(Tip {
            block_id,
            hash: block.header.hash,
        }))
    }

    /// Record the stall reason.
    ///
    /// - First stall is stored verbatim
    /// - Subsequent stalls only bump `orphans_since`, preserving the original cause.
    pub fn record_stall(
        &self,
        header: Option<&BlockHeader>,
        l1_slot: Slot,
        error: BlockIngestError,
    ) -> Result<()> {
        let stall = match self.get_stall_reason()? {
            Some(mut existing) => {
                existing.orphans_since = existing.orphans_since.saturating_add(1);
                existing
            }
            None => StallReason {
                // need to map out of `header` because they are not ser/de
                block_id: header.map(|h| h.block_id),
                block_hash: header.map(|h| h.hash),
                prev_block_hash: header.map(|h| h.prev_block_hash),
                first_seen: header.map(|h| h.timestamp),
                l1_slot,
                error,
                orphans_since: 0,
            },
        };
        self.set_stall_reason(&Some(stall))
    }

    /// Validates `block` against the tip and, if it chains, applies it atomically
    /// (scratch clone, commit only on full success) and advances the tip. On any
    /// failure records the stall and returns `Parked` without touching state.
    pub async fn accept_block(&self, block: &Block, l1_slot: Slot) -> Result<AcceptOutcome> {
        let tip = self.validated_tip()?;

        // Re-delivery of an already-applied block is idempotent, not a divergence
        if let Some(tip) = &tip
            && block.header.block_id <= tip.block_id
            && let Some(stored) = self.get_block_at_id(block.header.block_id)?
            && stored.header.hash == block.header.hash
        {
            return Ok(AcceptOutcome::AlreadyApplied);
        }

        if let Err(err) = validate_against_tip(tip.as_ref(), block) {
            self.record_stall(Some(&block.header), l1_slot, err.clone())?;
            return Ok(AcceptOutcome::Parked(err));
        }

        // TODO: we use scratch state to be atomic, but need to revisit how expensive a clone is
        let mut scratch = self.current_state.read().await.clone();
        if let Err(err) = apply_block_to_scratch(block, &mut scratch) {
            if err.is_retryable() {
                return Ok(AcceptOutcome::ApplyFailed(err));
            }
            self.record_stall(Some(&block.header), l1_slot, err.clone())?;
            return Ok(AcceptOutcome::Parked(err));
        }

        let mut stored = block.clone();
        stored.bedrock_status = BedrockStatus::Finalized;
        let breakpoint = block
            .header
            .block_id
            .is_multiple_of(BREAKPOINT_INTERVAL.into())
            .then_some(&scratch);
        self.dbio
            .put_block(&stored, [0_u8; 32], l1_slot.into_inner(), breakpoint)
            .context("Failed to persist accepted block")?;

        // Commit in-memory state (infallible) only after the DB write succeeded.
        *self.current_state.write().await = scratch;
        // Best-effort: the block is durably applied, so a failed stall clear must not
        // fail the apply. It self-heals on the next clear.
        if let Err(err) = self.clear_stall_if_present() {
            warn!("Failed to clear stall marker after applying block: {err:#}");
        }
        Ok(AcceptOutcome::Applied)
    }
}

/// Checks that `block` is the valid continuation of `tip`: hash integrity,
/// then block-id continuity, then `prev_block_hash` linkage. A `None` tip
/// (cold store) expects the genesis block.
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
/// [`BlockIngestError`] so the caller can park rather than crash. Operates on a
/// scratch state; the caller commits only on `Ok`.
fn apply_block_to_scratch(block: &Block, state: &mut V03State) -> Result<(), BlockIngestError> {
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
mod stall_reason_tests {
    use common::HashType;

    use super::*;
    use crate::{ingest_error::BlockIngestError, stall_reason::StallReason};

    #[tokio::test]
    async fn stall_reason_roundtrips_and_clears() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = IndexerStore::open_db(dir.path()).expect("open store");

        assert!(store.get_stall_reason().expect("get").is_none());

        let stall = StallReason {
            block_id: Some(7),
            block_hash: Some(HashType([1_u8; 32])),
            prev_block_hash: Some(HashType([2_u8; 32])),
            l1_slot: Slot::from(42),
            error: BlockIngestError::StateTransition {
                tx_index: 0,
                reason: "boom".to_owned(),
            },
            first_seen: Some(99),
            orphans_since: 3,
        };
        store.set_stall_reason(&Some(stall)).expect("set stall");

        let got = store.get_stall_reason().expect("get").expect("present");
        assert_eq!(got.block_id, Some(7));
        assert_eq!(got.orphans_since, 3);
        assert!(matches!(
            got.error,
            BlockIngestError::StateTransition { .. }
        ));
        assert_eq!(got.block_hash, Some(HashType([1_u8; 32])));
        assert_eq!(got.prev_block_hash, Some(HashType([2_u8; 32])));
        assert_eq!(got.l1_slot, Slot::from(42));
        assert_eq!(got.first_seen, Some(99));

        store.set_stall_reason(&None).expect("clear");
        assert!(store.get_stall_reason().expect("get").is_none());
    }
}

#[cfg(test)]
mod tests {
    use common::test_utils::{create_transaction_native_token_transfer, produce_dummy_block};
    use tempfile::tempdir;
    use testnet_initial_state::initial_pub_accounts_private_keys;

    use super::*;

    #[test]
    fn correct_startup() {
        let home = tempdir().unwrap();

        let storage = IndexerStore::open_db(home.as_ref()).unwrap();

        let final_id = storage.get_last_block_id().unwrap();

        assert_eq!(final_id, None);
    }

    #[tokio::test]
    async fn accept_block_applies_transfers_and_advances_tip() {
        let home = tempdir().unwrap();
        let store = IndexerStore::open_db(home.as_ref()).unwrap();

        let initial_accounts = initial_pub_accounts_private_keys();
        let from = initial_accounts[0].account_id;
        let to = initial_accounts[1].account_id;
        let sign_key = initial_accounts[0].pub_sign_key.clone();

        // Genesis (block 1): clock-only.
        let genesis = produce_dummy_block(1, None, vec![]);
        let mut prev_hash = genesis.header.hash;
        assert!(matches!(
            store.accept_block(&genesis, Slot::from(0)).await.unwrap(),
            AcceptOutcome::Applied
        ));

        // Blocks 2..=11: one native transfer of 10 each (nonces 0..=9).
        for i in 0..10_u64 {
            let tx = create_transaction_native_token_transfer(from, i.into(), to, 10, &sign_key);
            let block = produce_dummy_block(i + 2, Some(prev_hash), vec![tx]);
            prev_hash = block.header.hash;
            assert!(matches!(
                store.accept_block(&block, Slot::from(0)).await.unwrap(),
                AcceptOutcome::Applied
            ));
        }

        assert_eq!(
            store.account_current_state(&from).await.unwrap().balance,
            9900
        );
        assert_eq!(
            store.account_current_state(&to).await.unwrap().balance,
            20100
        );
        // Tip advanced to the last applied block; a clean run leaves no stall.
        assert_eq!(store.get_last_block_id().unwrap(), Some(11));
        assert!(store.get_stall_reason().unwrap().is_none());
    }

    #[tokio::test]
    async fn account_state_at_block_reflects_history() {
        let home = tempdir().unwrap();
        let store = IndexerStore::open_db(home.as_ref()).unwrap();

        let initial_accounts = initial_pub_accounts_private_keys();
        let from = initial_accounts[0].account_id;
        let to = initial_accounts[1].account_id;
        let sign_key = initial_accounts[0].pub_sign_key.clone();

        let genesis = produce_dummy_block(1, None, vec![]);
        let mut prev_hash = genesis.header.hash;
        store.accept_block(&genesis, Slot::from(0)).await.unwrap();

        for i in 0..10_u64 {
            let tx = create_transaction_native_token_transfer(from, i.into(), to, 10, &sign_key);
            let block = produce_dummy_block(i + 2, Some(prev_hash), vec![tx]);
            prev_hash = block.header.hash;
            store.accept_block(&block, Slot::from(0)).await.unwrap();
        }

        // State at block N is inclusive of block N.
        // Block 1 (genesis, clock-only): no transfers yet.
        assert_eq!(
            store.account_state_at_block(&from, 1).unwrap().balance,
            10000
        );
        assert_eq!(store.account_state_at_block(&to, 1).unwrap().balance, 20000);
        // Through block 5: 4 transfers applied (blocks 2..=5).
        assert_eq!(
            store.account_state_at_block(&from, 5).unwrap().balance,
            9960
        );
        assert_eq!(store.account_state_at_block(&to, 5).unwrap().balance, 20040);
        // Through block 9: 8 transfers applied (blocks 2..=9).
        assert_eq!(
            store.account_state_at_block(&from, 9).unwrap().balance,
            9920
        );
        assert_eq!(store.account_state_at_block(&to, 9).unwrap().balance, 20080);
    }
}

#[cfg(test)]
mod accept_tests {
    use common::{HashType, block::HashableBlockData, test_utils::produce_dummy_block};

    use super::*;
    use crate::ingest_error::BlockIngestError;

    fn signing_key() -> lee::PrivateKey {
        lee::PrivateKey::try_new([7_u8; 32]).expect("valid key")
    }

    // A block with a correct hash but empty body — enough to exercise the
    // acceptance checks (id/link/hash), which run before any state application.
    fn valid_hash_block(block_id: u64, prev: HashType) -> common::block::Block {
        HashableBlockData {
            block_id,
            prev_block_hash: prev,
            timestamp: 0,
            transactions: vec![],
        }
        .into_pending_block(&signing_key())
    }

    #[tokio::test]
    async fn non_genesis_first_block_parks_with_unexpected_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = IndexerStore::open_db(dir.path()).expect("open store");

        let block = valid_hash_block(2, HashType([0_u8; 32]));
        let outcome = store
            .accept_block(&block, Slot::from(0))
            .await
            .expect("accept");

        assert!(matches!(
            outcome,
            AcceptOutcome::Parked(BlockIngestError::UnexpectedBlockId {
                expected: 1,
                got: 2
            })
        ));
        let stall = store.get_stall_reason().expect("get").expect("present");
        assert_eq!(stall.block_id, Some(2));
        assert_eq!(stall.orphans_since, 0);
    }

    #[tokio::test]
    async fn hash_mismatch_parks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = IndexerStore::open_db(dir.path()).expect("open store");

        let mut block = valid_hash_block(1, HashType([0_u8; 32]));
        block.header.timestamp = 999; // invalidates the stored hash

        let outcome = store
            .accept_block(&block, Slot::from(0))
            .await
            .expect("accept");
        assert!(matches!(
            outcome,
            AcceptOutcome::Parked(BlockIngestError::HashMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn second_break_bumps_orphan_count_and_keeps_first() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = IndexerStore::open_db(dir.path()).expect("open store");

        let first = valid_hash_block(2, HashType([0_u8; 32]));
        store
            .accept_block(&first, Slot::from(0))
            .await
            .expect("accept");
        let second = valid_hash_block(3, HashType([0_u8; 32]));
        store
            .accept_block(&second, Slot::from(0))
            .await
            .expect("accept");

        let stall = store.get_stall_reason().expect("get").expect("present");
        assert_eq!(stall.block_id, Some(2), "first stall preserved");
        assert_eq!(stall.orphans_since, 1, "second break counted as orphan");
    }

    #[tokio::test]
    async fn deserialize_break_records_stall_without_header() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = IndexerStore::open_db(dir.path()).expect("open store");

        store
            .record_stall(
                None,
                Slot::from(0),
                BlockIngestError::Deserialize("bad bytes".to_owned()),
            )
            .expect("record");

        let stall = store.get_stall_reason().expect("get").expect("present");
        assert_eq!(stall.block_id, None);
        assert!(matches!(stall.error, BlockIngestError::Deserialize(_)));
    }

    #[tokio::test]
    async fn parks_then_recovers_on_valid_continuation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = IndexerStore::open_db(dir.path()).expect("open store");

        // Genesis (block 1, clock-only) applies and advances the tip.
        let genesis = produce_dummy_block(1, None, vec![]);
        assert!(matches!(
            store.accept_block(&genesis, Slot::from(0)).await.unwrap(),
            AcceptOutcome::Applied
        ));

        // A block that skips ahead (id 3 while the tip is 1) parks the indexer.
        let bad = produce_dummy_block(3, Some(genesis.header.hash), vec![]);
        assert!(matches!(
            store.accept_block(&bad, Slot::from(0)).await.unwrap(),
            AcceptOutcome::Parked(BlockIngestError::UnexpectedBlockId {
                expected: 2,
                got: 3
            })
        ));
        assert!(
            store.get_stall_reason().unwrap().is_some(),
            "indexer should be parked after the bad block"
        );
        assert_eq!(
            store.get_last_block_id().unwrap(),
            Some(1),
            "validated tip must stay frozen at genesis while parked"
        );

        // The valid continuation (block 2 chaining on genesis) recovers the chain.
        let next = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        assert!(matches!(
            store.accept_block(&next, Slot::from(0)).await.unwrap(),
            AcceptOutcome::Applied
        ));
        assert!(
            store.get_stall_reason().unwrap().is_none(),
            "stall reason must clear on recovery"
        );
        assert_eq!(
            store.get_last_block_id().unwrap(),
            Some(2),
            "tip must advance to the recovered block"
        );
    }

    #[tokio::test]
    async fn accept_block_records_tip_inscription_slot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = IndexerStore::open_db(dir.path()).expect("open store");

        assert_eq!(store.get_tip_slot().expect("get"), None);

        let genesis = produce_dummy_block(1, None, vec![]);
        store
            .accept_block(&genesis, Slot::from(1_000))
            .await
            .expect("accept");
        assert_eq!(store.get_tip_slot().expect("get"), Some(Slot::from(1_000)));

        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        store
            .accept_block(&block2, Slot::from(1_005))
            .await
            .expect("accept");
        assert_eq!(store.get_tip_slot().expect("get"), Some(Slot::from(1_005)));

        // A parked block freezes the tip, so its slot must not advance either.
        let bad = produce_dummy_block(4, Some(block2.header.hash), vec![]);
        assert!(matches!(
            store.accept_block(&bad, Slot::from(1_010)).await.unwrap(),
            AcceptOutcome::Parked(_)
        ));
        assert_eq!(store.get_tip_slot().expect("get"), Some(Slot::from(1_005)));

        // Neither must a re-delivered old block move it.
        assert!(matches!(
            store
                .accept_block(&genesis, Slot::from(1_015))
                .await
                .unwrap(),
            AcceptOutcome::AlreadyApplied
        ));
        assert_eq!(store.get_tip_slot().expect("get"), Some(Slot::from(1_005)));
    }

    #[tokio::test]
    async fn redelivered_tip_block_is_idempotent_not_parked() {
        use testnet_initial_state::initial_pub_accounts_private_keys;

        let dir = tempfile::tempdir().expect("tempdir");
        let store = IndexerStore::open_db(dir.path()).expect("open store");

        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let genesis = produce_dummy_block(1, None, vec![]);
        store
            .accept_block(&genesis, Slot::from(0))
            .await
            .expect("accept genesis");

        // Block 2: a single transfer of 10.
        let tx = common::test_utils::create_transaction_native_token_transfer(
            from, 0, to, 10, &sign_key,
        );
        let block = produce_dummy_block(2, Some(genesis.header.hash), vec![tx]);
        assert!(matches!(
            store.accept_block(&block, Slot::from(0)).await.unwrap(),
            AcceptOutcome::Applied
        ));
        let balance_after = store.account_current_state(&from).await.unwrap().balance;

        // Re-deliver the exact same block: idempotent skip, no state change, no park.
        assert!(matches!(
            store.accept_block(&block, Slot::from(0)).await.unwrap(),
            AcceptOutcome::AlreadyApplied
        ));
        assert_eq!(
            store.account_current_state(&from).await.unwrap().balance,
            balance_after,
            "re-delivered block must not be applied twice"
        );
        assert_eq!(
            store.get_last_block_id().unwrap(),
            Some(2),
            "tip must stay at the already-applied block"
        );
        assert!(
            store.get_stall_reason().unwrap().is_none(),
            "a benign duplicate must not park the indexer"
        );
    }

    #[tokio::test]
    async fn redelivered_block_below_tip_is_idempotent_not_parked() {
        use testnet_initial_state::initial_pub_accounts_private_keys;

        let dir = tempfile::tempdir().expect("tempdir");
        let store = IndexerStore::open_db(dir.path()).expect("open store");

        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        // Build a short chain: genesis (1) -> block 2 -> block 3, so the tip is 3.
        let genesis = produce_dummy_block(1, None, vec![]);
        store
            .accept_block(&genesis, Slot::from(0))
            .await
            .expect("accept genesis");

        let tx2 = common::test_utils::create_transaction_native_token_transfer(
            from, 0, to, 10, &sign_key,
        );
        let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![tx2]);
        assert!(matches!(
            store.accept_block(&block2, Slot::from(0)).await.unwrap(),
            AcceptOutcome::Applied
        ));

        let tx3 = common::test_utils::create_transaction_native_token_transfer(
            from, 1, to, 10, &sign_key,
        );
        let block3 = produce_dummy_block(3, Some(block2.header.hash), vec![tx3]);
        assert!(matches!(
            store.accept_block(&block3, Slot::from(0)).await.unwrap(),
            AcceptOutcome::Applied
        ));

        let balance_after = store.account_current_state(&from).await.unwrap().balance;

        // Re-deliver block 2 (id below the tip): a re-delivery, not a divergence.
        assert!(matches!(
            store.accept_block(&block2, Slot::from(0)).await.unwrap(),
            AcceptOutcome::AlreadyApplied
        ));
        assert_eq!(
            store.account_current_state(&from).await.unwrap().balance,
            balance_after,
            "re-delivered block below the tip must not be applied again"
        );
        assert_eq!(
            store.get_last_block_id().unwrap(),
            Some(3),
            "tip must stay at the current head"
        );
        assert!(
            store.get_stall_reason().unwrap().is_none(),
            "a benign re-delivery must not park the indexer"
        );
    }

    #[tokio::test]
    async fn accept_block_snapshots_state_at_breakpoint_interval() {
        use testnet_initial_state::initial_pub_accounts_private_keys;

        let dir = tempfile::tempdir().expect("tempdir");
        let store = IndexerStore::open_db(dir.path()).expect("open store");

        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let genesis = produce_dummy_block(1, None, vec![]);
        assert!(matches!(
            store.accept_block(&genesis, Slot::from(0)).await.unwrap(),
            AcceptOutcome::Applied
        ));
        let mut prev_hash = genesis.header.hash;

        // Blocks 2..=101: one transfer of 1 each; block 100 crosses the interval.
        for i in 0..100_u64 {
            let tx = common::test_utils::create_transaction_native_token_transfer(
                from,
                i.into(),
                to,
                1,
                &sign_key,
            );
            let block = produce_dummy_block(i + 2, Some(prev_hash), vec![tx]);
            prev_hash = block.header.hash;
            assert!(matches!(
                store.accept_block(&block, Slot::from(0)).await.unwrap(),
                AcceptOutcome::Applied
            ));
        }

        // Snapshot at block 100 = genesis + 99 transfers, written with the block.
        let bp1 = store.dbio.get_breakpoint(1).expect("breakpoint 1 present");
        assert_eq!(bp1.get_account_by_id(from).balance, 10000 - 99);
        assert_eq!(store.dbio.get_meta_last_breakpoint_id().unwrap(), Some(1));

        // The #605 restart: reopening past the boundary must work.
        drop(store);
        let reopened = IndexerStore::open_db(dir.path()).expect("reopen");
        assert_eq!(reopened.last_block().unwrap(), Some(101));
    }

    #[tokio::test]
    async fn transient_apply_failure_returns_apply_failed_without_stall() {
        use testnet_initial_state::initial_pub_accounts_private_keys;

        let dir = tempfile::tempdir().expect("tempdir");
        let store = IndexerStore::open_db(dir.path()).expect("open store");

        let accounts = initial_pub_accounts_private_keys();
        let from = accounts[0].account_id;
        let to = accounts[1].account_id;
        let sign_key = accounts[0].pub_sign_key.clone();

        let genesis = produce_dummy_block(1, None, vec![]);
        store
            .accept_block(&genesis, Slot::from(0))
            .await
            .expect("accept genesis");

        // Overdraft: rejected during execution → StateTransition → retryable.
        let tx = common::test_utils::create_transaction_native_token_transfer(
            from,
            0,
            to,
            1_000_000_000,
            &sign_key,
        );
        let block = produce_dummy_block(2, Some(genesis.header.hash), vec![tx]);
        let outcome = store.accept_block(&block, Slot::from(0)).await.unwrap();

        assert!(matches!(
            outcome,
            AcceptOutcome::ApplyFailed(BlockIngestError::StateTransition { .. })
        ));
        assert!(
            store.get_stall_reason().unwrap().is_none(),
            "retryable failure must not persist a stall"
        );
        assert_eq!(store.get_last_block_id().unwrap(), Some(1), "tip frozen");
    }
}
