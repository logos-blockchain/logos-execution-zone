use super::{Block, DbResult, RocksDBIO, V03State};
use crate::{
    DBIO as _,
    cells::shared_cells::{BlockCell, FirstBlockCell, FirstBlockSetCell, LastBlockCell},
    indexer::indexer_cells::{
        AccNumTxCell, BlockHashToBlockIdMapCell, BreakpointCellOwned, LastBreakpointIdCell,
        LastObservedL1LibHeaderCell, TxHashToBlockIdMapCell,
    },
};

#[expect(clippy::multiple_inherent_impl, reason = "Readability")]
impl RocksDBIO {
    // Meta

    pub fn get_meta_first_block_in_db(&self) -> DbResult<u64> {
        self.get::<FirstBlockCell>(()).map(|cell| cell.0)
    }

    pub fn get_meta_last_block_in_db(&self) -> DbResult<u64> {
        self.get::<LastBlockCell>(()).map(|cell| cell.0)
    }

    pub fn get_meta_last_observed_l1_lib_header_in_db(&self) -> DbResult<Option<[u8; 32]>> {
        self.get_opt::<LastObservedL1LibHeaderCell>(())
            .map(|opt| opt.map(|val| val.0))
    }

    pub fn get_meta_is_first_block_set(&self) -> DbResult<bool> {
        Ok(self.get_opt::<FirstBlockSetCell>(())?.is_some())
    }

    pub fn get_meta_last_breakpoint_id(&self) -> DbResult<u64> {
        self.get::<LastBreakpointIdCell>(()).map(|cell| cell.0)
    }

    // Block

    pub fn get_block(&self, block_id: u64) -> DbResult<Option<Block>> {
        self.get_opt::<BlockCell>(block_id)
            .map(|opt| opt.map(|val| val.0))
    }

    // State

    pub fn get_breakpoint(&self, br_id: u64) -> DbResult<V03State> {
        self.get::<BreakpointCellOwned>(br_id).map(|cell| cell.0)
    }

    // Mappings

    pub fn get_block_id_by_hash(&self, hash: [u8; 32]) -> DbResult<Option<u64>> {
        self.get_opt::<BlockHashToBlockIdMapCell>(hash)
            .map(|opt| opt.map(|cell| cell.0))
    }

    pub fn get_block_id_by_tx_hash(&self, tx_hash: [u8; 32]) -> DbResult<Option<u64>> {
        self.get_opt::<TxHashToBlockIdMapCell>(tx_hash)
            .map(|opt| opt.map(|cell| cell.0))
    }

    // Accounts meta

    pub(crate) fn get_acc_meta_num_tx(&self, acc_id: [u8; 32]) -> DbResult<Option<u64>> {
        self.get_opt::<AccNumTxCell>(acc_id)
            .map(|opt| opt.map(|cell| cell.0))
    }
}
