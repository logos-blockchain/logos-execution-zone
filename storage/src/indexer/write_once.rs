use super::*;

impl RocksDBIO {
    //Meta

    pub fn put_meta_first_block_in_db(&self, block: Block) -> DbResult<()> {
        let cf_meta = self.meta_column();
        self.db
            .put_cf(
                &cf_meta,
                borsh::to_vec(&DB_META_FIRST_BLOCK_IN_DB_KEY).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize DB_META_FIRST_BLOCK_IN_DB_KEY".to_string()),
                    )
                })?,
                borsh::to_vec(&block.header.block_id).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize first block id".to_string()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

        self.put_block(block, [0; 32])?;
        Ok(())
    }

    pub fn put_meta_last_block_in_db(&self, block_id: u64) -> DbResult<()> {
        let cf_meta = self.meta_column();
        self.db
            .put_cf(
                &cf_meta,
                borsh::to_vec(&DB_META_LAST_BLOCK_IN_DB_KEY).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize DB_META_LAST_BLOCK_IN_DB_KEY".to_string()),
                    )
                })?,
                borsh::to_vec(&block_id).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize last block id".to_string()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;
        Ok(())
    }

    pub fn put_meta_last_observed_l1_lib_header_in_db(
        &self,
        l1_lib_header: [u8; 32],
    ) -> DbResult<()> {
        let cf_meta = self.meta_column();
        self.db
            .put_cf(
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
                borsh::to_vec(&l1_lib_header).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize last l1 block header".to_string()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;
        Ok(())
    }

    pub fn put_meta_last_breakpoint_id(&self, br_id: u64) -> DbResult<()> {
        let cf_meta = self.meta_column();
        self.db
            .put_cf(
                &cf_meta,
                borsh::to_vec(&DB_META_LAST_BREAKPOINT_ID).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize DB_META_LAST_BREAKPOINT_ID".to_string()),
                    )
                })?,
                borsh::to_vec(&br_id).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize last block id".to_string()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;
        Ok(())
    }

    pub fn put_meta_is_first_block_set(&self) -> DbResult<()> {
        let cf_meta = self.meta_column();
        self.db
            .put_cf(
                &cf_meta,
                borsh::to_vec(&DB_META_FIRST_BLOCK_SET_KEY).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize DB_META_FIRST_BLOCK_SET_KEY".to_string()),
                    )
                })?,
                [1u8; 1],
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;
        Ok(())
    }

    //Block

    pub fn put_block(&self, block: Block, l1_lib_header: [u8; 32]) -> DbResult<()> {
        let cf_block = self.block_column();
        let cf_hti = self.hash_to_id_column();
        let cf_tti: Arc<BoundColumnFamily<'_>> = self.tx_hash_to_id_column();

        // ToDo: rewrite this with write batching

        self.db
            .put_cf(
                &cf_block,
                borsh::to_vec(&block.header.block_id).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize block id".to_string()),
                    )
                })?,
                borsh::to_vec(&block).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize block data".to_string()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

        let last_curr_block = self.get_meta_last_block_in_db()?;

        if block.header.block_id > last_curr_block {
            self.put_meta_last_block_in_db(block.header.block_id)?;
            self.put_meta_last_observed_l1_lib_header_in_db(l1_lib_header)?;
        }

        self.db
            .put_cf(
                &cf_hti,
                borsh::to_vec(&block.header.hash).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize block hash".to_string()),
                    )
                })?,
                borsh::to_vec(&block.header.block_id).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize block id".to_string()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

        let mut acc_to_tx_map: HashMap<[u8; 32], Vec<[u8; 32]>> = HashMap::new();

        for tx in block.body.transactions {
            let tx_hash = tx.hash();

            self.db
                .put_cf(
                    &cf_tti,
                    borsh::to_vec(&tx_hash).map_err(|err| {
                        DbError::borsh_cast_message(
                            err,
                            Some("Failed to serialize tx hash".to_string()),
                        )
                    })?,
                    borsh::to_vec(&block.header.block_id).map_err(|err| {
                        DbError::borsh_cast_message(
                            err,
                            Some("Failed to serialize block id".to_string()),
                        )
                    })?,
                )
                .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

            let acc_ids = tx
                .affected_public_account_ids()
                .into_iter()
                .map(|account_id| account_id.into_value())
                .collect::<Vec<_>>();

            for acc_id in acc_ids {
                acc_to_tx_map
                    .entry(acc_id)
                    .and_modify(|tx_hashes| tx_hashes.push(tx_hash.into()))
                    .or_insert(vec![tx_hash.into()]);
            }
        }

        for (acc_id, tx_hashes) in acc_to_tx_map {
            self.put_account_transactions(acc_id, tx_hashes)?;
        }

        if block.header.block_id.is_multiple_of(BREAKPOINT_INTERVAL) {
            self.put_next_breakpoint()?;
        }

        Ok(())
    }

    //State

    pub fn put_breakpoint(&self, br_id: u64, breakpoint: V02State) -> DbResult<()> {
        let cf_br = self.breakpoint_column();

        self.db
            .put_cf(
                &cf_br,
                borsh::to_vec(&br_id).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize breakpoint id".to_string()),
                    )
                })?,
                borsh::to_vec(&breakpoint).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize breakpoint data".to_string()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))
    }
}