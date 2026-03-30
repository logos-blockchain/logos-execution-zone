use std::{collections::HashMap, path::Path};

use anyhow::Result;
use common::{
    HashType,
    block::{Block, BlockMeta, MantleMsgId},
    transaction::NSSATransaction,
};
use nssa::V03State;
use storage::{error::DbError, sequencer::RocksDBIO};

pub struct SequencerStore {
    dbio: RocksDBIO,
    // TODO: Consider adding the hashmap to the database for faster recovery.
    tx_hash_to_block_map: HashMap<HashType, u64>,
    genesis_id: u64,
    signing_key: nssa::PrivateKey,
}

impl SequencerStore {
    /// Starting database at the start of new chain.
    /// Creates files if necessary.
    ///
    /// ATTENTION: Will overwrite genesis block.
    pub fn open_db_with_genesis(
        location: &Path,
        genesis_block: &Block,
        genesis_msg_id: MantleMsgId,
        signing_key: nssa::PrivateKey,
    ) -> Result<Self> {
        let tx_hash_to_block_map = block_to_transactions_map(genesis_block);

        let dbio = RocksDBIO::open_or_create(location, genesis_block, genesis_msg_id)?;

        let genesis_id = dbio.get_meta_first_block_in_db()?;

        Ok(Self {
            dbio,
            tx_hash_to_block_map,
            genesis_id,
            signing_key,
        })
    }

    pub fn get_block_at_id(&self, id: u64) -> Result<Option<Block>, DbError> {
        self.dbio.get_block(id)
    }

    pub fn delete_block_at_id(&mut self, block_id: u64) -> Result<()> {
        Ok(self.dbio.delete_block(block_id)?)
    }

    pub fn mark_block_as_finalized(&mut self, block_id: u64) -> Result<()> {
        Ok(self.dbio.mark_block_as_finalized(block_id)?)
    }

    /// Returns the transaction corresponding to the given hash, if it exists in the blockchain.
    pub fn get_transaction_by_hash(&self, hash: HashType) -> Option<NSSATransaction> {
        let block_id = *self.tx_hash_to_block_map.get(&hash)?;
        let block = self
            .get_block_at_id(block_id)
            .ok()
            .flatten()
            .expect("Block should be present since the hash is in the map");
        for transaction in block.body.transactions {
            if transaction.hash() == hash {
                return Some(transaction);
            }
        }
        panic!(
            "Transaction hash was in the map but transaction was not found in the block. This should never happen."
        );
    }

    pub fn latest_block_meta(&self) -> Result<BlockMeta> {
        Ok(self.dbio.latest_block_meta()?)
    }

    pub const fn genesis_id(&self) -> u64 {
        self.genesis_id
    }

    pub const fn signing_key(&self) -> &nssa::PrivateKey {
        &self.signing_key
    }

    pub fn get_all_blocks(&self) -> impl Iterator<Item = Result<Block>> {
        self.dbio.get_all_blocks().map(|res| Ok(res?))
    }

    pub(crate) fn update(
        &mut self,
        block: &Block,
        msg_id: MantleMsgId,
        state: &V03State,
    ) -> Result<()> {
        let new_transactions_map = block_to_transactions_map(block);
        self.dbio.atomic_update(block, msg_id, state)?;
        self.tx_hash_to_block_map.extend(new_transactions_map);
        Ok(())
    }

    pub fn get_nssa_state(&self) -> Option<V03State> {
        self.dbio.get_nssa_state().ok()
    }
}

pub(crate) fn block_to_transactions_map(block: &Block) -> HashMap<HashType, u64> {
    block
        .body
        .transactions
        .iter()
        .map(|transaction| (transaction.hash(), block.header.block_id))
        .collect()
}

#[cfg(test)]
mod tests {
    #![expect(clippy::shadow_unrelated, reason = "We don't care about it in tests")]

    use common::{block::HashableBlockData, test_utils::sequencer_sign_key_for_testing};
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
            transactions: vec![],
        };

        let genesis_block = genesis_block_hashable_data.into_pending_block(&signing_key, [0; 32]);
        // Start an empty node store
        let mut node_store =
            SequencerStore::open_db_with_genesis(path, &genesis_block, [0; 32], signing_key)
                .unwrap();

        let tx = common::test_utils::produce_dummy_empty_transaction();
        let block = common::test_utils::produce_dummy_block(1, None, vec![tx.clone()]);

        // Try retrieve a tx that's not in the chain yet.
        let retrieved_tx = node_store.get_transaction_by_hash(tx.hash());
        assert_eq!(None, retrieved_tx);
        // Add the block with the transaction
        let dummy_state = V03State::new_with_genesis_accounts(&[], &[]);
        node_store.update(&block, [1; 32], &dummy_state).unwrap();
        // Try again
        let retrieved_tx = node_store.get_transaction_by_hash(tx.hash());
        assert_eq!(Some(tx), retrieved_tx);
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
            transactions: vec![],
        };

        let genesis_block = genesis_block_hashable_data.into_pending_block(&signing_key, [0; 32]);
        let genesis_hash = genesis_block.header.hash;

        let node_store =
            SequencerStore::open_db_with_genesis(path, &genesis_block, [0; 32], signing_key)
                .unwrap();

        // Verify that initially the latest block hash equals genesis hash
        let latest_meta = node_store.latest_block_meta().unwrap();
        assert_eq!(latest_meta.hash, genesis_hash);
        assert_eq!(latest_meta.msg_id, [0; 32]);
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
            transactions: vec![],
        };

        let genesis_block = genesis_block_hashable_data.into_pending_block(&signing_key, [0; 32]);
        let mut node_store =
            SequencerStore::open_db_with_genesis(path, &genesis_block, [0; 32], signing_key)
                .unwrap();

        // Add a new block
        let tx = common::test_utils::produce_dummy_empty_transaction();
        let block = common::test_utils::produce_dummy_block(1, None, vec![tx]);
        let block_hash = block.header.hash;
        let block_msg_id = [1; 32];

        let dummy_state = V03State::new_with_genesis_accounts(&[], &[]);
        node_store
            .update(&block, block_msg_id, &dummy_state)
            .unwrap();

        // Verify that the latest block meta now equals the new block's hash and msg_id
        let latest_meta = node_store.latest_block_meta().unwrap();
        assert_eq!(latest_meta.hash, block_hash);
        assert_eq!(latest_meta.msg_id, block_msg_id);
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
            transactions: vec![],
        };

        let genesis_block = genesis_block_hashable_data.into_pending_block(&signing_key, [0; 32]);
        let mut node_store =
            SequencerStore::open_db_with_genesis(path, &genesis_block, [0; 32], signing_key)
                .unwrap();

        // Add a new block with Pending status
        let tx = common::test_utils::produce_dummy_empty_transaction();
        let block = common::test_utils::produce_dummy_block(1, None, vec![tx]);
        let block_id = block.header.block_id;

        let dummy_state = V03State::new_with_genesis_accounts(&[], &[]);
        node_store.update(&block, [1; 32], &dummy_state).unwrap();

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
}
