use std::collections::HashMap;

use rocksdb::WriteBatch;

use super::{BREAKPOINT_INTERVAL, Block, DbError, DbResult, RocksDBIO};
use crate::{
    DBIO as _,
    cells::shared_cells::{FirstBlockCell, FirstBlockSetCell, LastBlockCell},
    indexer::indexer_cells::{
        AccNumTxCell, BlockHashToBlockIdMapCell, LastBreakpointIdCell, LastObservedL1LibHeaderCell,
        TxHashToBlockIdMapCell,
    },
};

#[expect(clippy::multiple_inherent_impl, reason = "Readability")]
impl RocksDBIO {
    // Accounts meta

    pub(crate) fn update_acc_meta_batch(
        &self,
        acc_id: [u8; 32],
        num_tx: u64,
        write_batch: &mut WriteBatch,
    ) -> DbResult<()> {
        self.put_batch(&AccNumTxCell(num_tx), acc_id, write_batch)
    }

    // Mappings

    pub fn put_block_id_by_hash_batch(
        &self,
        hash: [u8; 32],
        block_id: u64,
        write_batch: &mut WriteBatch,
    ) -> DbResult<()> {
        self.put_batch(&BlockHashToBlockIdMapCell(block_id), hash, write_batch)
    }

    pub fn put_block_id_by_tx_hash_batch(
        &self,
        tx_hash: [u8; 32],
        block_id: u64,
        write_batch: &mut WriteBatch,
    ) -> DbResult<()> {
        self.put_batch(&TxHashToBlockIdMapCell(block_id), tx_hash, write_batch)
    }

    // Account

    pub fn put_account_transactions(
        &self,
        acc_id: [u8; 32],
        tx_hashes: &[[u8; 32]],
    ) -> DbResult<()> {
        let acc_num_tx = self.get_acc_meta_num_tx(acc_id)?.unwrap_or(0);
        let cf_att = self.account_id_to_tx_hash_column();
        let mut write_batch = WriteBatch::new();

        for (tx_id, tx_hash) in tx_hashes.iter().enumerate() {
            let put_id = acc_num_tx
                .checked_add(tx_id.try_into().expect("Must fit into u64"))
                .expect("Tx count should be lesser that u64::MAX");

            let mut prefix = borsh::to_vec(&acc_id).map_err(|berr| {
                DbError::borsh_cast_message(berr, Some("Failed to serialize account id".to_owned()))
            })?;
            let suffix = borsh::to_vec(&put_id).map_err(|berr| {
                DbError::borsh_cast_message(berr, Some("Failed to serialize tx id".to_owned()))
            })?;

            prefix.extend_from_slice(&suffix);

            write_batch.put_cf(
                &cf_att,
                prefix,
                borsh::to_vec(tx_hash).map_err(|berr| {
                    DbError::borsh_cast_message(
                        berr,
                        Some("Failed to serialize tx hash".to_owned()),
                    )
                })?,
            );
        }

        self.update_acc_meta_batch(
            acc_id,
            acc_num_tx
                .checked_add(tx_hashes.len().try_into().expect("Must fit into u64"))
                .expect("Tx count should be lesser that u64::MAX"),
            &mut write_batch,
        )?;

        self.db.write(write_batch).map_err(|rerr| {
            DbError::rocksdb_cast_message(rerr, Some("Failed to write batch".to_owned()))
        })
    }

    pub fn put_account_transactions_dependant(
        &self,
        acc_id: [u8; 32],
        tx_hashes: &[[u8; 32]],
        write_batch: &mut WriteBatch,
    ) -> DbResult<()> {
        let acc_num_tx = self.get_acc_meta_num_tx(acc_id)?.unwrap_or(0);
        let cf_att = self.account_id_to_tx_hash_column();

        for (tx_id, tx_hash) in tx_hashes.iter().enumerate() {
            let put_id = acc_num_tx
                .checked_add(tx_id.try_into().expect("Must fit into u64"))
                .expect("Tx count should be lesser that u64::MAX");

            let mut prefix = borsh::to_vec(&acc_id).map_err(|berr| {
                DbError::borsh_cast_message(berr, Some("Failed to serialize account id".to_owned()))
            })?;
            let suffix = borsh::to_vec(&put_id).map_err(|berr| {
                DbError::borsh_cast_message(berr, Some("Failed to serialize tx id".to_owned()))
            })?;

            prefix.extend_from_slice(&suffix);

            write_batch.put_cf(
                &cf_att,
                prefix,
                borsh::to_vec(tx_hash).map_err(|berr| {
                    DbError::borsh_cast_message(
                        berr,
                        Some("Failed to serialize tx hash".to_owned()),
                    )
                })?,
            );
        }

        self.update_acc_meta_batch(
            acc_id,
            acc_num_tx
                .checked_add(tx_hashes.len().try_into().expect("Must fit into u64"))
                .expect("Tx count should be lesser that u64::MAX"),
            write_batch,
        )?;

        Ok(())
    }

    // Meta

    pub fn put_meta_first_block_in_db_batch(
        &self,
        block: &Block,
        write_batch: &mut WriteBatch,
    ) -> DbResult<()> {
        self.put_batch(&FirstBlockCell(block.header.block_id), (), write_batch)
    }

    pub fn put_meta_last_block_in_db_batch(
        &self,
        block_id: u64,
        write_batch: &mut WriteBatch,
    ) -> DbResult<()> {
        self.put_batch(&LastBlockCell(block_id), (), write_batch)
    }

    pub fn put_meta_last_observed_l1_lib_header_in_db_batch(
        &self,
        l1_lib_header: [u8; 32],
        write_batch: &mut WriteBatch,
    ) -> DbResult<()> {
        self.put_batch(&LastObservedL1LibHeaderCell(l1_lib_header), (), write_batch)
    }

    pub fn put_meta_last_breakpoint_id_batch(
        &self,
        br_id: u64,
        write_batch: &mut WriteBatch,
    ) -> DbResult<()> {
        self.put_batch(&LastBreakpointIdCell(br_id), (), write_batch)
    }

    pub fn put_meta_is_first_block_set_batch(&self, write_batch: &mut WriteBatch) -> DbResult<()> {
        self.put_batch(&FirstBlockSetCell(true), (), write_batch)
    }

    // Block

    pub fn put_block(&self, block: &Block, l1_lib_header: [u8; 32]) -> DbResult<()> {
        let cf_block = self.block_column();
        let last_curr_block = self.get_meta_last_block_id_in_db()?.unwrap_or(0);
        let mut write_batch = WriteBatch::default();

        write_batch.put_cf(
            &cf_block,
            borsh::to_vec(&block.header.block_id).map_err(|err| {
                DbError::borsh_cast_message(err, Some("Failed to serialize block id".to_owned()))
            })?,
            borsh::to_vec(block).map_err(|err| {
                DbError::borsh_cast_message(err, Some("Failed to serialize block data".to_owned()))
            })?,
        );

        if block.header.block_id > last_curr_block {
            self.put_meta_last_block_in_db_batch(block.header.block_id, &mut write_batch)?;
            self.put_meta_last_observed_l1_lib_header_in_db_batch(l1_lib_header, &mut write_batch)?;
        }
        if last_curr_block == 0 {
            self.put_meta_first_block_in_db_batch(block, &mut write_batch)?;
            self.put_meta_is_first_block_set_batch(&mut write_batch)?;
        }

        self.put_block_id_by_hash_batch(
            block.header.hash.into(),
            block.header.block_id,
            &mut write_batch,
        )?;

        let mut acc_to_tx_map: HashMap<[u8; 32], Vec<[u8; 32]>> = HashMap::new();

        for tx in &block.body.transactions {
            let tx_hash = tx.hash();

            self.put_block_id_by_tx_hash_batch(
                tx_hash.into(),
                block.header.block_id,
                &mut write_batch,
            )?;

            let acc_ids = tx
                .affected_public_account_ids()
                .into_iter()
                .map(nssa::AccountId::into_value)
                .collect::<Vec<_>>();

            for acc_id in acc_ids {
                acc_to_tx_map
                    .entry(acc_id)
                    .and_modify(|tx_hashes| tx_hashes.push(tx_hash.into()))
                    .or_insert_with(|| vec![tx_hash.into()]);
            }
        }

        #[expect(
            clippy::iter_over_hash_type,
            reason = "RocksDB will keep ordering persistent"
        )]
        for (acc_id, tx_hashes) in acc_to_tx_map {
            self.put_account_transactions_dependant(acc_id, &tx_hashes, &mut write_batch)?;
        }

        self.db.write(write_batch).map_err(|rerr| {
            DbError::rocksdb_cast_message(rerr, Some("Failed to write batch".to_owned()))
        })?;

        if block
            .header
            .block_id
            .is_multiple_of(BREAKPOINT_INTERVAL.into())
        {
            self.put_next_breakpoint()?;
        }

        Ok(())
    }
}
