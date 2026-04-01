use rocksdb::{DBWithThreadMode, MultiThreaded, WriteBatch};

use crate::{
    error::DbError,
    storable_cell::{SimpleReadableCell, SimpleWritableCell},
};

pub mod error;
pub mod indexer;
pub mod sequencer;
pub mod storable_cell;

/// Maximal size of stored blocks in base.
///
/// Used to control db size.
///
/// Currently effectively unbounded.
pub const BUFF_SIZE_ROCKSDB: usize = usize::MAX;

/// Size of stored blocks cache in memory.
///
/// Keeping small to not run out of memory.
pub const CACHE_SIZE: usize = 1000;

/// Key base for storing metainformation which describe if first block has been set.
pub const DB_META_FIRST_BLOCK_SET_KEY: &str = "first_block_set";
/// Key base for storing metainformation about id of first block in db.
pub const DB_META_FIRST_BLOCK_IN_DB_KEY: &str = "first_block_in_db";
/// Key base for storing metainformation about id of last current block in db.
pub const DB_META_LAST_BLOCK_IN_DB_KEY: &str = "last_block_in_db";

/// Cell name for a block.
pub const BLOCK_CELL_NAME: &str = "block";

/// Interval between state breakpoints.
pub const BREAKPOINT_INTERVAL: u8 = 100;

/// Name of block column family.
pub const CF_BLOCK_NAME: &str = "cf_block";
/// Name of meta column family.
pub const CF_META_NAME: &str = "cf_meta";

pub type DbResult<T> = Result<T, DbError>;

/// Minimal requirements for DB IO.
pub trait DBIO {
    fn db(&self) -> &DBWithThreadMode<MultiThreaded>;

    fn get<T: SimpleReadableCell>(&self, params: T::KeyParams) -> DbResult<T> {
        T::get(self.db(), params)
    }

    fn get_opt<T: SimpleReadableCell>(&self, params: T::KeyParams) -> DbResult<Option<T>> {
        T::get_opt(self.db(), params)
    }

    fn put<T: SimpleWritableCell>(&self, cell: &T, params: T::KeyParams) -> DbResult<()> {
        cell.put(self.db(), params)
    }

    fn put_batch<T: SimpleWritableCell>(
        &self,
        cell: &T,
        params: T::KeyParams,
        write_batch: &mut WriteBatch,
    ) -> DbResult<()> {
        cell.put_batch(self.db(), params, write_batch)
    }
}
