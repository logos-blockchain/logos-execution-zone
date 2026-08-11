use std::{collections::HashMap, path::Path, sync::Arc};

use anyhow::{Context as _, Result};
use common::{
    HashType,
    block::{Block, BlockMeta},
    transaction::LeeTransaction,
};
use lee::V03State;
use lee_core::BlockId;
use log::info;
use logos_blockchain_zone_sdk::{Slot, sequencer::SequencerCheckpoint};
use storage::sequencer::{
    RocksDBIO,
    sequencer_cells::{
        PeerZoneKey, PendingDepositEventRecord, WithdrawalReconciliationKey, ZoneAnchorRecord,
    },
};
pub use storage::{DbResult, sequencer::DbDump};

pub struct SequencerStore {
    dbio: Arc<RocksDBIO>,
    // TODO: Consider adding the hashmap to the database for faster recovery.
    tx_hash_to_block_map: HashMap<HashType, BlockId>,
    genesis_id: u64,
    signing_key: lee::PrivateKey,
    /// Derived from `signing_key` once, since every block produced carries it
    /// and deriving it is an elliptic-curve multiplication.
    producer_key: lee::PublicKey,
}

impl SequencerStore {
    /// Open existing database at the given location. Fails if no database is found.
    pub fn open_db(location: &Path, signing_key: lee::PrivateKey) -> DbResult<Self> {
        let dbio = Arc::new(RocksDBIO::open(location)?);
        Self::from_dbio_and_signing_key(dbio, signing_key)
    }

    /// Create a fresh rocksdb at `location` from `dump`.
    pub fn restore_db_from_dump(
        location: &Path,
        dump: &DbDump,
        signing_key: lee::PrivateKey,
    ) -> DbResult<Self> {
        let dbio = Arc::new(RocksDBIO::restore_from_dump(location, dump)?);
        Self::from_dbio_and_signing_key(dbio, signing_key)
    }

    /// Starting database at the start of new chain.
    /// Creates files if necessary.
    ///
    /// ATTENTION: Will overwrite genesis block.
    pub fn create_db_with_genesis(
        location: &Path,
        genesis_block: &Block,
        genesis_state: &V03State,
        signing_key: lee::PrivateKey,
    ) -> DbResult<Self> {
        let dbio = Arc::new(RocksDBIO::create(location, genesis_block, genesis_state)?);
        let genesis_id = dbio.get_meta_first_block_in_db()?;
        let tx_hash_to_block_map = block_to_transactions_map(genesis_block);

        Ok(Self {
            dbio,
            tx_hash_to_block_map,
            genesis_id,
            producer_key: lee::PublicKey::new_from_private_key(&signing_key),
            signing_key,
        })
    }

    fn from_dbio_and_signing_key(
        dbio: Arc<RocksDBIO>,
        signing_key: lee::PrivateKey,
    ) -> DbResult<Self> {
        let genesis_id = dbio.get_meta_first_block_in_db()?;
        let last_id = dbio.latest_block_meta()?.map(|meta| meta.id);

        let mut tx_hash_to_block_map = HashMap::new();

        if let Some(last_id) = last_id {
            info!("Preparing block cache");
            for i in genesis_id..=last_id {
                let block = dbio
                    .get_block(i)?
                    .expect("Block should be present in the database");

                tx_hash_to_block_map.extend(block_to_transactions_map(&block));
            }
            info!(
                "Block cache prepared. Total blocks in cache: {}",
                tx_hash_to_block_map.len()
            );
        }

        Ok(Self {
            dbio,
            tx_hash_to_block_map,
            genesis_id,
            producer_key: lee::PublicKey::new_from_private_key(&signing_key),
            signing_key,
        })
    }

    /// Shared handle to the underlying rocksdb. Used to persist the zone-sdk
    /// checkpoint from the sequencer's drive task without needing &mut to the
    /// store.
    #[must_use]
    pub fn dbio(&self) -> Arc<RocksDBIO> {
        Arc::clone(&self.dbio)
    }

    pub fn get_block_at_id(&self, id: u64) -> DbResult<Option<Block>> {
        self.dbio.get_block(id)
    }

    pub fn delete_block_at_id(&mut self, block_id: u64) -> DbResult<()> {
        self.dbio.delete_block(block_id)
    }

    pub fn mark_block_as_finalized(&mut self, block_id: u64) -> DbResult<()> {
        self.dbio.mark_block_as_finalized(block_id)
    }

    /// Returns the transaction corresponding to the given hash, if it exists in the blockchain.
    #[must_use]
    pub fn get_transaction_by_hash(&self, hash: HashType) -> Option<(LeeTransaction, BlockId)> {
        let block_id = *self.tx_hash_to_block_map.get(&hash)?;
        let block = self
            .get_block_at_id(block_id)
            .ok()
            .flatten()
            .expect("Block should be present since the hash is in the map");
        for transaction in block.body.transactions {
            if transaction.hash() == hash {
                return Some((transaction, block_id));
            }
        }
        panic!(
            "Transaction hash was in the map but transaction was not found in the block. This should never happen."
        );
    }

    pub fn latest_block_meta(&self) -> DbResult<Option<BlockMeta>> {
        self.dbio.latest_block_meta()
    }

    #[must_use]
    pub const fn genesis_id(&self) -> u64 {
        self.genesis_id
    }

    #[must_use]
    pub const fn signing_key(&self) -> &lee::PrivateKey {
        &self.signing_key
    }

    /// Public key this sequencer stamps into `header.producer`, matching
    /// [`Self::signing_key`].
    #[must_use]
    pub const fn producer_key(&self) -> &lee::PublicKey {
        &self.producer_key
    }

    pub fn get_all_blocks(&self) -> impl Iterator<Item = DbResult<Block>> {
        self.dbio.get_all_blocks()
    }

    pub(crate) fn update(
        &mut self,
        block: &Block,
        withdrawals: &[WithdrawalReconciliationKey],
        state: &V03State,
        checkpoint: Option<&[u8]>,
    ) -> DbResult<()> {
        let new_transactions_map = block_to_transactions_map(block);
        self.dbio
            .atomic_update(block, withdrawals, state, checkpoint)?;
        self.tx_hash_to_block_map.extend(new_transactions_map);
        Ok(())
    }

    pub fn get_lee_state(&self) -> DbResult<V03State> {
        self.dbio.get_lee_state()
    }

    /// Remove the persisted zone-sdk checkpoint so the next startup is treated as a fresh start.
    pub fn delete_zone_checkpoint(&self) -> DbResult<()> {
        self.dbio.delete_zone_sdk_checkpoint_bytes()
    }

    /// Reset every stored block to `Pending` so the next fresh start republishes the whole chain.
    pub fn reset_all_blocks_to_pending(&self) -> DbResult<()> {
        self.dbio.reset_all_blocks_to_pending()
    }

    /// Single-blob [`DbDump`] of the whole store; restore with [`Self::restore_db_from_dump`].
    pub fn dump(&self) -> DbResult<DbDump> {
        self.dbio.dump_all()
    }

    pub fn get_zone_checkpoint(&self) -> Result<Option<SequencerCheckpoint>> {
        let Some(bytes) = self.dbio.get_zone_sdk_checkpoint_bytes()? else {
            return Ok(None);
        };
        let checkpoint: SequencerCheckpoint = serde_json::from_slice(&bytes)
            .context("Failed to deserialize stored zone-sdk checkpoint")?;
        Ok(Some(checkpoint))
    }

    /// Persists `checkpoint` on its own. Only valid when the effects it covers
    /// are already durable — otherwise it must ride in the same write as them,
    /// via [`storage::sequencer::StoreUpdate`].
    pub fn set_zone_checkpoint(&self, checkpoint: &SequencerCheckpoint) -> Result<()> {
        self.dbio
            .put_zone_sdk_checkpoint_bytes(&checkpoint_bytes(checkpoint)?)?;
        Ok(())
    }

    /// The last channel block read back and verified from Bedrock (L1 slot +
    /// `id`/`hash`), or `None` before any block has been read from the channel.
    pub fn get_zone_anchor(&self) -> DbResult<Option<ZoneAnchorRecord>> {
        self.dbio.get_zone_anchor()
    }

    pub fn set_zone_anchor(&self, anchor: &ZoneAnchorRecord) -> DbResult<()> {
        self.dbio.put_zone_anchor(anchor)
    }

    /// The highest block id ever inscribed on the channel by this sequencer,
    /// or `None` before it has published anything.
    pub fn published_high_water(&self) -> DbResult<Option<u64>> {
        self.dbio.published_high_water()
    }

    /// Raises the published high water mark to `block_id`, never lowering it.
    pub fn raise_published_high_water(&self, block_id: u64) -> DbResult<()> {
        self.dbio.raise_published_high_water(block_id)
    }

    pub fn get_pending_deposit_events(&self) -> DbResult<Vec<PendingDepositEventRecord>> {
        self.dbio.get_pending_deposit_events()
    }
}

/// The checkpoint's on-disk encoding. `serde_json` because `SequencerCheckpoint`
/// derives serde but not borsh; paired with `get_zone_checkpoint`'s decode.
pub(crate) fn checkpoint_bytes(checkpoint: &SequencerCheckpoint) -> Result<Vec<u8>> {
    serde_json::to_vec(checkpoint).context("Failed to serialize zone-sdk checkpoint")
}

pub(crate) fn block_to_transactions_map(block: &Block) -> HashMap<HashType, u64> {
    block
        .body
        .transactions
        .iter()
        .map(|transaction| (transaction.hash(), block.header.block_id))
        .collect()
}

/// A cross-zone watcher's delivery floor on `peer_zone`'s channel.
///
/// The highest slot every message of which was delivered, or `None` before it
/// has delivered anything from that peer. Stored as a little-endian `u64`.
///
/// Free functions rather than only [`SequencerStore`] methods because each
/// watcher runs as its own spawned task and holds an `Arc<RocksDBIO>`;
/// `SequencerStore` is not `Clone`.
pub fn get_cross_zone_peer_floor(dbio: &RocksDBIO, peer_zone: PeerZoneKey) -> Result<Option<Slot>> {
    let Some(bytes) = dbio.get_cross_zone_peer_floor_bytes(peer_zone)? else {
        return Ok(None);
    };
    let bytes: [u8; 8] = bytes.as_slice().try_into().with_context(|| {
        format!(
            "Stored cross-zone peer floor is {} bytes, expected 8",
            bytes.len()
        )
    })?;
    Ok(Some(Slot::new(u64::from_le_bytes(bytes))))
}

pub fn set_cross_zone_peer_floor(
    dbio: &RocksDBIO,
    peer_zone: PeerZoneKey,
    floor: Slot,
) -> Result<()> {
    dbio.put_cross_zone_peer_floor_bytes(peer_zone, &floor.to_le_bytes())?;
    Ok(())
}

/// Drops the stored floor so the watcher reads `peer_zone`'s channel from the
/// peer's genesis again.
pub fn clear_cross_zone_peer_floor(dbio: &RocksDBIO, peer_zone: PeerZoneKey) -> Result<()> {
    dbio.delete_cross_zone_peer_floor(peer_zone)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use common::{
        block::HashableBlockData,
        test_utils::{sequencer_producer_key_for_testing, sequencer_sign_key_for_testing},
    };
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn get_transaction_by_hash() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path();

        let signing_key = sequencer_sign_key_for_testing();

        let genesis_block_hashable_data = HashableBlockData {
            block_id: 0,
            prev_block_hash: HashType([0; 32]),
            timestamp: 0,
            producer: sequencer_producer_key_for_testing(),
            transactions: vec![],
        };

        let genesis_block = genesis_block_hashable_data.into_pending_block(&signing_key);
        // Start an empty node store
        let mut node_store = SequencerStore::create_db_with_genesis(
            path,
            &genesis_block,
            &testnet_initial_state::initial_state(),
            signing_key,
        )
        .unwrap();

        let tx = common::test_utils::produce_dummy_empty_transaction();
        let block = common::test_utils::produce_dummy_block(1, None, vec![tx.clone()]);

        // Try retrieve a tx that's not in the chain yet.
        let retrieved_tx = node_store.get_transaction_by_hash(tx.hash());
        assert_eq!(None, retrieved_tx);
        // Add the block with the transaction
        let dummy_state = V03State::new();
        node_store.update(&block, &[], &dummy_state, None).unwrap();
        // Try again
        let output = node_store.get_transaction_by_hash(tx.hash());
        assert_eq!(Some((tx, 1)), output);
    }

    #[test]
    fn latest_block_meta_returns_genesis_meta_initially() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path();

        let signing_key = sequencer_sign_key_for_testing();

        let genesis_block_hashable_data = HashableBlockData {
            block_id: 0,
            prev_block_hash: HashType([0; 32]),
            timestamp: 0,
            producer: sequencer_producer_key_for_testing(),
            transactions: vec![],
        };

        let genesis_block = genesis_block_hashable_data.into_pending_block(&signing_key);
        let genesis_hash = genesis_block.header.hash;

        let node_store = SequencerStore::create_db_with_genesis(
            path,
            &genesis_block,
            &testnet_initial_state::initial_state(),
            signing_key,
        )
        .unwrap();

        // Verify that initially the latest block hash equals genesis hash
        let latest_meta = node_store.latest_block_meta().unwrap().unwrap();
        assert_eq!(latest_meta.hash, genesis_hash);
    }

    #[test]
    fn latest_block_meta_updates_after_new_block() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path();

        let signing_key = sequencer_sign_key_for_testing();

        let genesis_block_hashable_data = HashableBlockData {
            block_id: 0,
            prev_block_hash: HashType([0; 32]),
            timestamp: 0,
            producer: sequencer_producer_key_for_testing(),
            transactions: vec![],
        };

        let genesis_block = genesis_block_hashable_data.into_pending_block(&signing_key);
        let mut node_store = SequencerStore::create_db_with_genesis(
            path,
            &genesis_block,
            &testnet_initial_state::initial_state(),
            signing_key,
        )
        .unwrap();

        // Add a new block
        let tx = common::test_utils::produce_dummy_empty_transaction();
        let block = common::test_utils::produce_dummy_block(1, None, vec![tx]);
        let block_hash = block.header.hash;

        let dummy_state = V03State::new();
        node_store.update(&block, &[], &dummy_state, None).unwrap();

        // Verify that the latest block meta now equals the new block's hash
        let latest_meta = node_store.latest_block_meta().unwrap().unwrap();
        assert_eq!(latest_meta.hash, block_hash);
    }

    #[test]
    fn mark_block_finalized() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path();

        let signing_key = sequencer_sign_key_for_testing();

        let genesis_block_hashable_data = HashableBlockData {
            block_id: 0,
            prev_block_hash: HashType([0; 32]),
            timestamp: 0,
            producer: sequencer_producer_key_for_testing(),
            transactions: vec![],
        };

        let genesis_block = genesis_block_hashable_data.into_pending_block(&signing_key);
        let mut node_store = SequencerStore::create_db_with_genesis(
            path,
            &genesis_block,
            &testnet_initial_state::initial_state(),
            signing_key,
        )
        .unwrap();

        // Add a new block with Pending status
        let tx = common::test_utils::produce_dummy_empty_transaction();
        let block = common::test_utils::produce_dummy_block(1, None, vec![tx]);
        let block_id = block.header.block_id;

        let dummy_state = V03State::new();
        node_store.update(&block, &[], &dummy_state, None).unwrap();

        // Verify initial status is Pending
        let retrieved_block = node_store.get_block_at_id(block_id).unwrap().unwrap();
        assert!(matches!(
            retrieved_block.bedrock_status,
            common::block::BedrockStatus::Pending
        ));

        // Mark block as finalized
        node_store.mark_block_as_finalized(block_id).unwrap();

        // Verify status is now Finalized
        let finalized_block = node_store.get_block_at_id(block_id).unwrap().unwrap();
        assert!(matches!(
            finalized_block.bedrock_status,
            common::block::BedrockStatus::Finalized
        ));
    }

    #[test]
    fn open_existing_db_caches_transactions() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path();

        let signing_key = sequencer_sign_key_for_testing();

        let genesis_block_hashable_data = HashableBlockData {
            block_id: 0,
            prev_block_hash: HashType([0; 32]),
            timestamp: 0,
            producer: sequencer_producer_key_for_testing(),
            transactions: vec![],
        };

        let genesis_block = genesis_block_hashable_data.into_pending_block(&signing_key);
        let tx = common::test_utils::produce_dummy_empty_transaction();
        {
            // Create a scope to drop the first store after creating the db
            let mut node_store = SequencerStore::create_db_with_genesis(
                path,
                &genesis_block,
                &testnet_initial_state::initial_state(),
                signing_key.clone(),
            )
            .unwrap();

            // Add a new block
            let block = common::test_utils::produce_dummy_block(1, None, vec![tx.clone()]);
            node_store
                .update(&block, &[], &V03State::new(), None)
                .unwrap();
        }

        // Re-open the store and verify that the transaction is still retrievable (which means it
        // was cached correctly)
        let node_store = SequencerStore::open_db(path, signing_key).unwrap();
        let output = node_store.get_transaction_by_hash(tx.hash());
        assert_eq!(Some((tx, 1)), output);
    }
}
