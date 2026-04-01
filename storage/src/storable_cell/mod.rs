use std::sync::Arc;

use borsh::{BorshDeserialize, BorshSerialize};
use rocksdb::{BoundColumnFamily, DBWithThreadMode, MultiThreaded, WriteBatch};

use crate::{DbResult, error::DbError};

pub mod cells;

pub trait SimpleStorableCell {
    const CF_NAME: &'static str;
    const CELL_NAME: &'static str;
    type KeyParams;

    fn key_constructor(_params: Self::KeyParams) -> DbResult<Vec<u8>> {
        borsh::to_vec(&Self::CELL_NAME).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some(format!("Failed to serialize {:?}", Self::CELL_NAME)),
            )
        })
    }

    fn column_ref(db: &DBWithThreadMode<MultiThreaded>) -> Arc<BoundColumnFamily<'_>> {
        db.cf_handle(Self::CF_NAME)
            .unwrap_or_else(|| panic!("Column family {:?} must be present", Self::CF_NAME))
    }
}

pub trait SimpleReadableCell: SimpleStorableCell + BorshDeserialize {
    fn get(db: &DBWithThreadMode<MultiThreaded>, params: Self::KeyParams) -> DbResult<Self> {
        let res = Self::get_opt(db, params)?;

        res.ok_or_else(|| DbError::db_interaction_error(format!("{:?} not found", Self::CELL_NAME)))
    }

    fn get_opt(
        db: &DBWithThreadMode<MultiThreaded>,
        params: Self::KeyParams,
    ) -> DbResult<Option<Self>> {
        let cf_ref = Self::column_ref(db);
        let res = db
            .get_cf(&cf_ref, Self::key_constructor(params)?)
            .map_err(|rerr| {
                DbError::rocksdb_cast_message(
                    rerr,
                    Some(format!("Failed to read {:?}", Self::CELL_NAME)),
                )
            })?;

        res.map(|data| {
            borsh::from_slice::<Self>(&data).map_err(|err| {
                DbError::borsh_cast_message(
                    err,
                    Some(format!("Failed to deserialize {:?}", Self::CELL_NAME)),
                )
            })
        })
        .transpose()
    }
}

pub trait SimpleWritableCell: SimpleStorableCell + BorshSerialize {
    fn value_constructor(&self) -> DbResult<Vec<u8>>;

    fn put(&self, db: &DBWithThreadMode<MultiThreaded>, params: Self::KeyParams) -> DbResult<()> {
        let cf_ref = Self::column_ref(db);
        db.put_cf(
            &cf_ref,
            Self::key_constructor(params)?,
            self.value_constructor()?,
        )
        .map_err(|rerr| {
            DbError::rocksdb_cast_message(
                rerr,
                Some(format!("Failed to write {:?}", Self::CELL_NAME)),
            )
        })?;
        Ok(())
    }

    fn put_batch(
        &self,
        db: &DBWithThreadMode<MultiThreaded>,
        params: Self::KeyParams,
        write_batch: &mut WriteBatch,
    ) -> DbResult<()> {
        let cf_ref = Self::column_ref(db);
        write_batch.put_cf(
            &cf_ref,
            Self::key_constructor(params)?,
            self.value_constructor()?,
        );
        Ok(())
    }
}
