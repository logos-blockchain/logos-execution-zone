use super::{
    BREAKPOINT_INTERVAL, DB_META_FIRST_BLOCK_SET_KEY, DB_META_LAST_BLOCK_IN_DB_KEY,
    DB_META_LAST_BREAKPOINT_ID, DB_META_LAST_OBSERVED_L1_LIB_HEADER_ID_IN_DB_KEY, DbError,
    DbResult, RocksDBIO, V03State,
};

#[expect(clippy::multiple_inherent_impl, reason = "Readability")]
impl RocksDBIO {
    // Meta

    pub fn put_meta_last_block_in_db(&self, block_id: u64) -> DbResult<()> {
        let cf_meta = self.meta_column();
        self.db
            .put_cf(
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
                                .to_owned(),
                        ),
                    )
                    },
                )?,
                borsh::to_vec(&l1_lib_header).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize last l1 block header".to_owned()),
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
                        Some("Failed to serialize DB_META_LAST_BREAKPOINT_ID".to_owned()),
                    )
                })?,
                borsh::to_vec(&br_id).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize last block id".to_owned()),
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
                        Some("Failed to serialize DB_META_FIRST_BLOCK_SET_KEY".to_owned()),
                    )
                })?,
                [1_u8; 1],
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;
        Ok(())
    }

    // State

    pub fn put_breakpoint(&self, br_id: u64, breakpoint: &V03State) -> DbResult<()> {
        let cf_br = self.breakpoint_column();

        self.db
            .put_cf(
                &cf_br,
                borsh::to_vec(&br_id).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize breakpoint id".to_owned()),
                    )
                })?,
                borsh::to_vec(breakpoint).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize breakpoint data".to_owned()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))
    }

    pub fn put_next_breakpoint(&self) -> DbResult<()> {
        let last_block = self.get_meta_last_block_in_db()?;
        let next_breakpoint_id = self
            .get_meta_last_breakpoint_id()?
            .checked_add(1)
            .expect("Breakpoint Id will be lesser than u64::MAX");
        let block_to_break_id = next_breakpoint_id
            .checked_mul(u64::from(BREAKPOINT_INTERVAL))
            .expect("Reached maximum breakpoint id");

        if block_to_break_id <= last_block {
            let next_breakpoint = self.calculate_state_for_id(block_to_break_id)?;

            self.put_breakpoint(next_breakpoint_id, &next_breakpoint)?;
            self.put_meta_last_breakpoint_id(next_breakpoint_id)
        } else {
            Err(DbError::db_interaction_error(
                "Breakpoint not yet achieved".to_owned(),
            ))
        }
    }
}
