use std::collections::HashMap;

use common::{HashType, block::Block};
use lee_core::BlockId;

#[derive(Default)]
pub struct TransactionIndex {
    tx_to_block: HashMap<HashType, BlockId>,
    block_to_txs: HashMap<BlockId, Vec<HashType>>,
}

impl TransactionIndex {
    /// Extend index from block removing old data if it existed for `block`.
    pub fn update_from_block(&mut self, block: &Block) {
        self.delete_block(block.header.block_id);

        for tx in &block.body.transactions {
            let tx_hash = tx.hash();
            self.tx_to_block.insert(tx_hash, block.header.block_id);
            self.block_to_txs
                .entry(block.header.block_id)
                .or_default()
                .push(tx_hash);
        }
    }

    /// Delete all transactions associated with `block_id` from the index.
    pub fn delete_block(&mut self, block_id: BlockId) {
        if let Some(txs) = self.block_to_txs.remove(&block_id) {
            for tx_hash in txs {
                self.tx_to_block.remove(&tx_hash);
            }
        }
    }

    /// Get the block id for a transaction hash if it exists in the index.
    pub fn block_for_tx(&self, tx_hash: &HashType) -> Option<BlockId> {
        self.tx_to_block.get(tx_hash).copied()
    }

    /// Get the number of transactions in the index.
    pub fn transaction_count(&self) -> usize {
        self.tx_to_block.len()
    }
}

#[cfg(test)]
mod tests {
    use common::test_utils::{produce_dummy_block, produce_dummy_empty_transaction};

    use super::*;

    #[test]
    fn update_from_block() {
        let mut index = TransactionIndex::default();
        let block = create_test_block(1, 3);

        index.update_from_block(&block);

        assert_eq!(index.transaction_count(), 3);
    }

    #[test]
    fn update_from_block_replaces_existing() {
        let mut index = TransactionIndex::default();
        let block1 = create_test_block(1, 2);
        let block2 = create_test_block(1, 2);

        index.update_from_block(&block1);
        assert_eq!(index.transaction_count(), 2);

        index.update_from_block(&block2);
        assert_eq!(index.transaction_count(), 2);
    }

    #[test]
    fn block_for_tx() {
        let mut index = TransactionIndex::default();
        let block = create_test_block(1, 3);

        index.update_from_block(&block);

        assert_eq!(
            index.block_for_tx(&block.body.transactions[0].hash()),
            Some(1)
        );
        assert_eq!(index.block_for_tx(&HashType::default()), None);
    }

    #[test]
    fn delete_block() {
        let mut index = TransactionIndex::default();
        let block = create_test_block(1, 3);

        index.update_from_block(&block);
        assert_eq!(index.transaction_count(), 3);

        index.delete_block(1);
        assert_eq!(index.transaction_count(), 0);
    }

    #[test]
    fn transaction_count() {
        let mut index = TransactionIndex::default();
        assert_eq!(index.transaction_count(), 0);

        let block1 = create_test_block(1, 2);
        index.update_from_block(&block1);
        assert_eq!(index.transaction_count(), 2);

        let block2 = create_test_block(2, 3);
        index.update_from_block(&block2);
        assert_eq!(index.transaction_count(), 4);
    }

    fn create_test_block(block_id: u64, tx_count: usize) -> Block {
        // -2 for the auto-inserted fee and clock tail transactions
        let transactions = std::iter::repeat_with(produce_dummy_empty_transaction)
            .take(tx_count.saturating_sub(2))
            .collect();
        produce_dummy_block(block_id, None, transactions)
    }
}
