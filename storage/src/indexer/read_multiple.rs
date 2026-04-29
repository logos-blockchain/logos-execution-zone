use common::transaction::NSSATransaction;

use super::{Block, DbError, DbResult, RocksDBIO};

#[expect(clippy::multiple_inherent_impl, reason = "Readability")]
impl RocksDBIO {
    pub fn get_block_batch(&self, before: Option<u64>, limit: u64) -> DbResult<Vec<Block>> {
        let mut seq = vec![];

        // Determine the starting block ID
        let start_block_id = if let Some(before_id) = before {
            before_id.saturating_sub(1)
        } else {
            // Get the latest block ID
            self.get_meta_last_block_in_db()?
        };

        for i in 0..limit {
            let block_id = start_block_id.saturating_sub(i);
            if block_id == 0 {
                break;
            }
            seq.push(block_id);
        }

        self.get_block_batch_seq(seq.into_iter())
    }

    /// Get block batch from a sequence.
    ///
    /// Currently assumes non-decreasing sequence.
    ///
    /// `ToDo`: Add suport of arbitrary sequences.
    pub fn get_block_batch_seq(&self, seq: impl Iterator<Item = u64>) -> DbResult<Vec<Block>> {
        let cf_block = self.block_column();

        // Keys setup
        let mut keys = vec![];
        for block_id in seq {
            keys.push((
                &cf_block,
                borsh::to_vec(&block_id).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize block id".to_owned()),
                    )
                })?,
            ));
        }

        let multi_get_res = self.db.multi_get_cf(keys);

        // Keys parsing
        let mut block_batch = vec![];
        for res in multi_get_res {
            let res = res.map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

            let block = if let Some(data) = res {
                Ok(borsh::from_slice::<Block>(&data).map_err(|serr| {
                    DbError::borsh_cast_message(
                        serr,
                        Some("Failed to deserialize block data".to_owned()),
                    )
                })?)
            } else {
                // Block not found, assuming that previous one was the last
                break;
            }?;

            block_batch.push(block);
        }

        Ok(block_batch)
    }

    /// Get block ids by txs.
    ///
    /// `ToDo`: There may be multiple transactions in one block
    /// so this method can take redundant reads.
    /// Need to update signature and implementation.
    fn get_block_ids_by_tx_vec(&self, tx_vec: &[[u8; 32]]) -> DbResult<Vec<u64>> {
        let cf_tti = self.tx_hash_to_id_column();

        // Keys setup
        let mut keys = vec![];
        for tx_hash in tx_vec {
            keys.push((
                &cf_tti,
                borsh::to_vec(tx_hash).map_err(|err| {
                    DbError::borsh_cast_message(err, Some("Failed to serialize tx_hash".to_owned()))
                })?,
            ));
        }

        let multi_get_res = self.db.multi_get_cf(keys);

        // Keys parsing
        let mut block_id_batch = vec![];
        for res in multi_get_res {
            let res = res
                .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?
                .ok_or_else(|| {
                    DbError::db_interaction_error(
                        "Tx to block id mapping do not contain transaction from vec".to_owned(),
                    )
                })?;

            let block_id = {
                Ok(borsh::from_slice::<u64>(&res).map_err(|serr| {
                    DbError::borsh_cast_message(
                        serr,
                        Some("Failed to deserialize block id".to_owned()),
                    )
                })?)
            }?;

            block_id_batch.push(block_id);
        }

        Ok(block_id_batch)
    }

    // Account

    pub(crate) fn get_acc_transaction_hashes(
        &self,
        acc_id: [u8; 32],
        offset: u64,
        limit: u64,
    ) -> DbResult<Vec<[u8; 32]>> {
        let cf_att = self.account_id_to_tx_hash_column();
        let mut tx_batch = vec![];

        // Keys preparation
        let mut keys = vec![];
        for tx_id in offset
            ..offset
                .checked_add(limit)
                .expect("Transaction limit should be lesser than u64::MAX")
        {
            let mut prefix = borsh::to_vec(&acc_id).map_err(|berr| {
                DbError::borsh_cast_message(berr, Some("Failed to serialize account id".to_owned()))
            })?;
            let suffix = borsh::to_vec(&tx_id).map_err(|berr| {
                DbError::borsh_cast_message(berr, Some("Failed to serialize tx id".to_owned()))
            })?;

            prefix.extend_from_slice(&suffix);

            keys.push((&cf_att, prefix));
        }

        let multi_get_res = self.db.multi_get_cf(keys);

        for res in multi_get_res {
            let res = res.map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

            let tx_hash = if let Some(data) = res {
                Ok(borsh::from_slice::<[u8; 32]>(&data).map_err(|serr| {
                    DbError::borsh_cast_message(
                        serr,
                        Some("Failed to deserialize tx_hash".to_owned()),
                    )
                })?)
            } else {
                // Tx hash not found, assuming that previous one was the last
                break;
            }?;

            tx_batch.push(tx_hash);
        }

        Ok(tx_batch)
    }

    pub fn get_acc_transactions(
        &self,
        acc_id: [u8; 32],
        offset: u64,
        limit: u64,
    ) -> DbResult<Vec<NSSATransaction>> {
        let mut tx_batch = vec![];

        let tx_hashes = self.get_acc_transaction_hashes(acc_id, offset, limit)?;

        let associated_blocks_multi_get = self
            .get_block_batch_seq(self.get_block_ids_by_tx_vec(&tx_hashes)?.into_iter())?
            .into_iter()
            .zip(tx_hashes);

        for (block, tx_hash) in associated_blocks_multi_get {
            let transaction = block
                .body
                .transactions
                .iter()
                .find(|tx| tx.hash().0 == tx_hash)
                .ok_or_else(|| {
                    DbError::db_interaction_error(format!(
                        "Missing transaction in block {} with hash {:#?}",
                        block.header.block_id, tx_hash
                    ))
                })?;

            tx_batch.push(transaction.clone());
        }

        Ok(tx_batch)
    }
}
