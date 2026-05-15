use super::{BREAKPOINT_INTERVAL, DbError, DbResult, RocksDBIO, V03State};
use crate::{
    DBIO as _,
    cells::shared_cells::{FirstBlockSetCell, LastBlockCell},
    indexer::indexer_cells::{
        BreakpointCellRef, LastBreakpointIdCell, LastObservedL1LibHeaderCell,
        ZoneSdkIndexerCursorCellRef,
    },
};

#[expect(clippy::multiple_inherent_impl, reason = "Readability")]
impl RocksDBIO {
    // Meta

    pub fn put_meta_last_block_in_db(&self, block_id: u64) -> DbResult<()> {
        self.put(&LastBlockCell(block_id), ())
    }

    pub fn put_meta_last_observed_l1_lib_header_in_db(
        &self,
        l1_lib_header: [u8; 32],
    ) -> DbResult<()> {
        self.put(&LastObservedL1LibHeaderCell(l1_lib_header), ())
    }

    pub fn put_meta_last_breakpoint_id(&self, br_id: u64) -> DbResult<()> {
        self.put(&LastBreakpointIdCell(br_id), ())
    }

    pub fn put_meta_is_first_block_set(&self) -> DbResult<()> {
        self.put(&FirstBlockSetCell(true), ())
    }

    pub fn put_zone_sdk_indexer_cursor_bytes(&self, bytes: &[u8]) -> DbResult<()> {
        self.put(&ZoneSdkIndexerCursorCellRef(bytes), ())
    }

    // State

    pub fn put_breakpoint(&self, br_id: u64, breakpoint: &V03State) -> DbResult<()> {
        self.put(&BreakpointCellRef(breakpoint), br_id)
    }

    pub fn put_next_breakpoint(&self) -> DbResult<()> {
        let last_block = self.get_meta_last_block_id_in_db()?.unwrap_or(0);
        let next_breakpoint_id = self
            .get_meta_last_breakpoint_id()?
            .unwrap_or(0)
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
