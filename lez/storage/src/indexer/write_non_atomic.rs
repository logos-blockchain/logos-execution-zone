use super::{DbResult, RocksDBIO, V03State};
#[cfg(test)]
use crate::error::DbError;
use crate::{
    DBIO as _,
    cells::shared_cells::{FirstBlockSetCell, LastBlockCell},
    indexer::indexer_cells::{
        BreakpointCellRef, CrossZoneHaltCellRef, EventFilterSegmentsCellRef,
        LastObservedL1LibHeaderCell, StallReasonCellRef, ZoneSdkIndexerCursorCellRef,
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

    pub fn put_meta_is_first_block_set(&self) -> DbResult<()> {
        self.put(&FirstBlockSetCell(true), ())
    }

    pub fn put_zone_sdk_indexer_cursor_bytes(&self, bytes: &[u8]) -> DbResult<()> {
        self.put(&ZoneSdkIndexerCursorCellRef(bytes), ())
    }

    pub fn put_event_filter_segments_bytes(&self, bytes: &[u8]) -> DbResult<()> {
        self.put(&EventFilterSegmentsCellRef(bytes), ())
    }

    pub fn put_stall_reason_bytes(&self, bytes: &[u8]) -> DbResult<()> {
        self.put(&StallReasonCellRef(bytes), ())
    }

    pub fn put_cross_zone_halt_bytes(&self, bytes: &[u8]) -> DbResult<()> {
        self.put(&CrossZoneHaltCellRef(bytes), ())
    }

    // State

    pub fn put_breakpoint(&self, br_id: u64, breakpoint: &V03State) -> DbResult<()> {
        self.put(&BreakpointCellRef(breakpoint), br_id)
    }

    /// Deletes a breakpoint snapshot. Test-only fault injection for simulating
    /// stores whose boundary snapshot was lost.
    #[cfg(test)]
    pub(crate) fn delete_breakpoint(&self, br_id: u64) -> DbResult<()> {
        let key = borsh::to_vec(&br_id).map_err(|err| {
            DbError::borsh_cast_message(err, Some("Failed to serialize breakpoint id".to_owned()))
        })?;
        self.db
            .delete_cf(&self.breakpoint_column(), key)
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))
    }
}
