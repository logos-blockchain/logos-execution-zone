use super::*;

impl RocksDBIO {
    //Meta

    pub fn get_meta_first_block_in_db(&self) -> DbResult<u64> {
        let cf_meta = self.meta_column();
        let res = self
            .db
            .get_cf(
                &cf_meta,
                borsh::to_vec(&DB_META_FIRST_BLOCK_IN_DB_KEY).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize DB_META_FIRST_BLOCK_IN_DB_KEY".to_string()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

        if let Some(data) = res {
            Ok(borsh::from_slice::<u64>(&data).map_err(|err| {
                DbError::borsh_cast_message(
                    err,
                    Some("Failed to deserialize first block".to_string()),
                )
            })?)
        } else {
            Err(DbError::db_interaction_error(
                "First block not found".to_string(),
            ))
        }
    }

    pub fn get_meta_last_block_in_db(&self) -> DbResult<u64> {
        let cf_meta = self.meta_column();
        let res = self
            .db
            .get_cf(
                &cf_meta,
                borsh::to_vec(&DB_META_LAST_BLOCK_IN_DB_KEY).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize DB_META_LAST_BLOCK_IN_DB_KEY".to_string()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

        if let Some(data) = res {
            Ok(borsh::from_slice::<u64>(&data).map_err(|err| {
                DbError::borsh_cast_message(
                    err,
                    Some("Failed to deserialize last block".to_string()),
                )
            })?)
        } else {
            Err(DbError::db_interaction_error(
                "Last block not found".to_string(),
            ))
        }
    }

    pub fn get_meta_last_observed_l1_lib_header_in_db(&self) -> DbResult<Option<[u8; 32]>> {
        let cf_meta = self.meta_column();
        let res = self
            .db
            .get_cf(
                &cf_meta,
                borsh::to_vec(&DB_META_LAST_OBSERVED_L1_LIB_HEADER_ID_IN_DB_KEY).map_err(
                    |err| {
                        DbError::borsh_cast_message(
                        err,
                        Some(
                            "Failed to serialize DB_META_LAST_OBSERVED_L1_LIB_HEADER_ID_IN_DB_KEY"
                                .to_string(),
                        ),
                    )
                    },
                )?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

        res.map(|data| {
            borsh::from_slice::<[u8; 32]>(&data).map_err(|err| {
                DbError::borsh_cast_message(
                    err,
                    Some("Failed to deserialize last l1 lib header".to_string()),
                )
            })
        })
        .transpose()
    }

    pub fn get_meta_is_first_block_set(&self) -> DbResult<bool> {
        let cf_meta = self.meta_column();
        let res = self
            .db
            .get_cf(
                &cf_meta,
                borsh::to_vec(&DB_META_FIRST_BLOCK_SET_KEY).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize DB_META_FIRST_BLOCK_SET_KEY".to_string()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

        Ok(res.is_some())
    }

    pub fn get_meta_last_breakpoint_id(&self) -> DbResult<u64> {
        let cf_meta = self.meta_column();
        let res = self
            .db
            .get_cf(
                &cf_meta,
                borsh::to_vec(&DB_META_LAST_BREAKPOINT_ID).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize DB_META_LAST_BREAKPOINT_ID".to_string()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

        if let Some(data) = res {
            Ok(borsh::from_slice::<u64>(&data).map_err(|err| {
                DbError::borsh_cast_message(
                    err,
                    Some("Failed to deserialize last breakpoint id".to_string()),
                )
            })?)
        } else {
            Err(DbError::db_interaction_error(
                "Last breakpoint id not found".to_string(),
            ))
        }
    }

    //Block

    pub fn get_block(&self, block_id: u64) -> DbResult<Block> {
        let cf_block = self.block_column();
        let res = self
            .db
            .get_cf(
                &cf_block,
                borsh::to_vec(&block_id).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize block id".to_string()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

        if let Some(data) = res {
            Ok(borsh::from_slice::<Block>(&data).map_err(|serr| {
                DbError::borsh_cast_message(
                    serr,
                    Some("Failed to deserialize block data".to_string()),
                )
            })?)
        } else {
            Err(DbError::db_interaction_error(
                "Block on this id not found".to_string(),
            ))
        }
    }

    pub fn get_block_batch(&self, before: Option<u64>, limit: u64) -> DbResult<Vec<Block>> {
        let cf_block = self.block_column();
        let mut block_batch = vec![];

        // Determine the starting block ID
        let start_block_id = if let Some(before_id) = before {
            before_id.saturating_sub(1)
        } else {
            // Get the latest block ID
            self.get_meta_last_block_in_db()?
        };

        // ToDo: Multi get this

        for i in 0..limit {
            let block_id = start_block_id.saturating_sub(i);
            if block_id == 0 {
                break;
            }

            let res = self
                .db
                .get_cf(
                    &cf_block,
                    borsh::to_vec(&block_id).map_err(|err| {
                        DbError::borsh_cast_message(
                            err,
                            Some("Failed to serialize block id".to_string()),
                        )
                    })?,
                )
                .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

            let block = if let Some(data) = res {
                Ok(borsh::from_slice::<Block>(&data).map_err(|serr| {
                    DbError::borsh_cast_message(
                        serr,
                        Some("Failed to deserialize block data".to_string()),
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

    //State

    pub fn get_breakpoint(&self, br_id: u64) -> DbResult<V02State> {
        let cf_br = self.breakpoint_column();
        let res = self
            .db
            .get_cf(
                &cf_br,
                borsh::to_vec(&br_id).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize breakpoint id".to_string()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

        if let Some(data) = res {
            Ok(borsh::from_slice::<V02State>(&data).map_err(|serr| {
                DbError::borsh_cast_message(
                    serr,
                    Some("Failed to deserialize breakpoint data".to_string()),
                )
            })?)
        } else {
            Err(DbError::db_interaction_error(
                "Breakpoint on this id not found".to_string(),
            ))
        }
    }

    pub fn put_next_breakpoint(&self) -> DbResult<()> {
        let last_block = self.get_meta_last_block_in_db()?;
        let next_breakpoint_id = self.get_meta_last_breakpoint_id()? + 1;
        let block_to_break_id = next_breakpoint_id * BREAKPOINT_INTERVAL;

        if block_to_break_id <= last_block {
            let next_breakpoint = self.calculate_state_for_id(block_to_break_id)?;

            self.put_breakpoint(next_breakpoint_id, next_breakpoint)?;
            self.put_meta_last_breakpoint_id(next_breakpoint_id)
        } else {
            Err(DbError::db_interaction_error(
                "Breakpoint not yet achieved".to_string(),
            ))
        }
    }

    // Mappings

    pub fn get_block_id_by_hash(&self, hash: [u8; 32]) -> DbResult<u64> {
        let cf_hti = self.hash_to_id_column();
        let res = self
            .db
            .get_cf(
                &cf_hti,
                borsh::to_vec(&hash).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize block hash".to_string()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

        if let Some(data) = res {
            Ok(borsh::from_slice::<u64>(&data).map_err(|serr| {
                DbError::borsh_cast_message(
                    serr,
                    Some("Failed to deserialize block id".to_string()),
                )
            })?)
        } else {
            Err(DbError::db_interaction_error(
                "Block on this hash not found".to_string(),
            ))
        }
    }

    pub fn get_block_id_by_tx_hash(&self, tx_hash: [u8; 32]) -> DbResult<u64> {
        let cf_tti = self.tx_hash_to_id_column();
        let res = self
            .db
            .get_cf(
                &cf_tti,
                borsh::to_vec(&tx_hash).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize transaction hash".to_string()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

        if let Some(data) = res {
            Ok(borsh::from_slice::<u64>(&data).map_err(|serr| {
                DbError::borsh_cast_message(
                    serr,
                    Some("Failed to deserialize block id".to_string()),
                )
            })?)
        } else {
            Err(DbError::db_interaction_error(
                "Block for this tx hash not found".to_string(),
            ))
        }
    }

    // Accounts meta

    pub(crate) fn get_acc_meta_num_tx(&self, acc_id: [u8; 32]) -> DbResult<Option<u64>> {
        let cf_ameta = self.account_meta_column();
        let res = self.db.get_cf(&cf_ameta, acc_id).map_err(|rerr| {
            DbError::rocksdb_cast_message(rerr, Some("Failed to read from acc meta cf".to_string()))
        })?;

        res.map(|data| {
            borsh::from_slice::<u64>(&data).map_err(|serr| {
                DbError::borsh_cast_message(serr, Some("Failed to deserialize num tx".to_string()))
            })
        })
        .transpose()
    }

    // Account

    fn get_acc_transaction_hashes(
        &self,
        acc_id: [u8; 32],
        offset: u64,
        limit: u64,
    ) -> DbResult<Vec<[u8; 32]>> {
        let cf_att = self.account_id_to_tx_hash_column();
        let mut tx_batch = vec![];

        // ToDo: Multi get this

        for tx_id in offset..(offset + limit) {
            let mut prefix = borsh::to_vec(&acc_id).map_err(|berr| {
                DbError::borsh_cast_message(
                    berr,
                    Some("Failed to serialize account id".to_string()),
                )
            })?;
            let suffix = borsh::to_vec(&tx_id).map_err(|berr| {
                DbError::borsh_cast_message(berr, Some("Failed to serialize tx id".to_string()))
            })?;

            prefix.extend_from_slice(&suffix);

            let res = self
                .db
                .get_cf(&cf_att, prefix)
                .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

            let tx_hash = if let Some(data) = res {
                Ok(borsh::from_slice::<[u8; 32]>(&data).map_err(|serr| {
                    DbError::borsh_cast_message(
                        serr,
                        Some("Failed to deserialize tx_hash".to_string()),
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

        for tx_hash in self.get_acc_transaction_hashes(acc_id, offset, limit)? {
            let block_id = self.get_block_id_by_tx_hash(tx_hash)?;
            let block = self.get_block(block_id)?;

            let transaction = block
                .body
                .transactions
                .iter()
                .find(|tx| tx.hash().0 == tx_hash)
                .ok_or(DbError::db_interaction_error(format!(
                    "Missing transaction in block {} with hash {:#?}",
                    block.header.block_id, tx_hash
                )))?;

            tx_batch.push(transaction.clone());
        }

        Ok(tx_batch)
    }
}