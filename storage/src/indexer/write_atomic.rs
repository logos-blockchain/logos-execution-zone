use std::collections::HashMap;

use rocksdb::WriteBatch;

use super::{
    Arc, BREAKPOINT_INTERVAL, Block, BoundColumnFamily, DB_META_FIRST_BLOCK_IN_DB_KEY,
    DB_META_FIRST_BLOCK_SET_KEY, DB_META_LAST_BLOCK_IN_DB_KEY, DB_META_LAST_BREAKPOINT_ID,
    DB_META_LAST_OBSERVED_L1_LIB_HEADER_ID_IN_DB_KEY, DbError, DbResult, RocksDBIO,
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
        let cf_ameta = self.account_meta_column();

        write_batch.put_cf(
            &cf_ameta,
            borsh::to_vec(&acc_id).map_err(|err| {
                DbError::borsh_cast_message(err, Some("Failed to serialize account id".to_owned()))
            })?,
            borsh::to_vec(&num_tx).map_err(|err| {
                DbError::borsh_cast_message(
                    err,
                    Some("Failed to serialize acc metadata".to_owned()),
                )
            })?,
        );

        Ok(())
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

    pub fn put_meta_first_block_in_db_batch(&self, block: &Block) -> DbResult<()> {
        let cf_meta = self.meta_column();
        self.db
            .put_cf(
                &cf_meta,
                borsh::to_vec(&DB_META_FIRST_BLOCK_IN_DB_KEY).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize DB_META_FIRST_BLOCK_IN_DB_KEY".to_owned()),
                    )
                })?,
                borsh::to_vec(&block.header.block_id).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize first block id".to_owned()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

        self.put_block(block, [0; 32])?;
        Ok(())
    }

    pub fn put_meta_last_block_in_db_batch(
        &self,
        block_id: u64,
        write_batch: &mut WriteBatch,
    ) -> DbResult<()> {
        let cf_meta = self.meta_column();
        write_batch.put_cf(
            &cf_meta,
            borsh::to_vec(&DB_META_LAST_BLOCK_IN_DB_KEY).map_err(|err| {
                DbError::borsh_cast_message(
                    err,
                    Some("Failed to serialize DB_META_LAST_BLOCK_IN_DB_KEY".to_owned()),
                )
            })?,
            borsh::to_vec(&block_id).map_err(|err| {
                DbError::borsh_cast_message(
                    err,
                    Some("Failed to serialize last block id".to_owned()),
                )
            })?,
        );
        Ok(())
    }

    pub fn put_meta_last_observed_l1_lib_header_in_db_batch(
        &self,
        l1_lib_header: [u8; 32],
        write_batch: &mut WriteBatch,
    ) -> DbResult<()> {
        let cf_meta = self.meta_column();
        write_batch.put_cf(
            &cf_meta,
            borsh::to_vec(&DB_META_LAST_OBSERVED_L1_LIB_HEADER_ID_IN_DB_KEY).map_err(|err| {
                DbError::borsh_cast_message(
                    err,
                    Some(
                        "Failed to serialize DB_META_LAST_OBSERVED_L1_LIB_HEADER_ID_IN_DB_KEY"
                            .to_owned(),
                    ),
                )
            })?,
            borsh::to_vec(&l1_lib_header).map_err(|err| {
                DbError::borsh_cast_message(
                    err,
                    Some("Failed to serialize last l1 block header".to_owned()),
                )
            })?,
        );
        Ok(())
    }

    pub fn put_meta_last_breakpoint_id_batch(
        &self,
        br_id: u64,
        write_batch: &mut WriteBatch,
    ) -> DbResult<()> {
        let cf_meta = self.meta_column();
        write_batch.put_cf(
            &cf_meta,
            borsh::to_vec(&DB_META_LAST_BREAKPOINT_ID).map_err(|err| {
                DbError::borsh_cast_message(
                    err,
                    Some("Failed to serialize DB_META_LAST_BREAKPOINT_ID".to_owned()),
                )
            })?,
            borsh::to_vec(&br_id).map_err(|err| {
                DbError::borsh_cast_message(
                    err,
                    Some("Failed to serialize last block id".to_owned()),
                )
            })?,
        );
        Ok(())
    }

    pub fn put_meta_is_first_block_set_batch(&self, write_batch: &mut WriteBatch) -> DbResult<()> {
        let cf_meta = self.meta_column();
        write_batch.put_cf(
            &cf_meta,
            borsh::to_vec(&DB_META_FIRST_BLOCK_SET_KEY).map_err(|err| {
                DbError::borsh_cast_message(
                    err,
                    Some("Failed to serialize DB_META_FIRST_BLOCK_SET_KEY".to_owned()),
                )
            })?,
            [1_u8; 1],
        );
        Ok(())
    }

    // Block

    pub fn put_block(&self, block: &Block, l1_lib_header: [u8; 32]) -> DbResult<()> {
        let cf_block = self.block_column();
        let cf_hti = self.hash_to_id_column();
        let cf_tti: Arc<BoundColumnFamily<'_>> = self.tx_hash_to_id_column();
        let last_curr_block = self.get_meta_last_block_in_db()?;
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

        write_batch.put_cf(
            &cf_hti,
            borsh::to_vec(&block.header.hash).map_err(|err| {
                DbError::borsh_cast_message(err, Some("Failed to serialize block hash".to_owned()))
            })?,
            borsh::to_vec(&block.header.block_id).map_err(|err| {
                DbError::borsh_cast_message(err, Some("Failed to serialize block id".to_owned()))
            })?,
        );

        let mut acc_to_tx_map: HashMap<[u8; 32], Vec<[u8; 32]>> = HashMap::new();

        for tx in &block.body.transactions {
            let tx_hash = tx.hash();

            write_batch.put_cf(
                &cf_tti,
                borsh::to_vec(&tx_hash).map_err(|err| {
                    DbError::borsh_cast_message(err, Some("Failed to serialize tx hash".to_owned()))
                })?,
                borsh::to_vec(&block.header.block_id).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize block id".to_owned()),
                    )
                })?,
            );

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
