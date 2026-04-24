use borsh::{BorshDeserialize, BorshSerialize};
use common::block::Block;

use crate::{
    BLOCK_CELL_NAME, CF_BLOCK_NAME, CF_META_NAME, DB_META_FIRST_BLOCK_IN_DB_KEY,
    DB_META_FIRST_BLOCK_SET_KEY, DB_META_LAST_BLOCK_IN_DB_KEY, DbResult,
    cells::{SimpleReadableCell, SimpleStorableCell, SimpleWritableCell},
    error::DbError,
};

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct LastBlockCell(pub u64);

impl SimpleStorableCell for LastBlockCell {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_LAST_BLOCK_IN_DB_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleReadableCell for LastBlockCell {}

impl SimpleWritableCell for LastBlockCell {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(err, Some("Failed to serialize last block id".to_owned()))
        })
    }
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct FirstBlockSetCell(pub bool);

impl SimpleStorableCell for FirstBlockSetCell {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_FIRST_BLOCK_SET_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleReadableCell for FirstBlockSetCell {}

impl SimpleWritableCell for FirstBlockSetCell {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some("Failed to serialize first block set flag".to_owned()),
            )
        })
    }
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct FirstBlockCell(pub u64);

impl SimpleStorableCell for FirstBlockCell {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_FIRST_BLOCK_IN_DB_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleReadableCell for FirstBlockCell {}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct BlockCell(pub Block);

impl SimpleStorableCell for BlockCell {
    type KeyParams = u64;

    const CELL_NAME: &'static str = BLOCK_CELL_NAME;
    const CF_NAME: &'static str = CF_BLOCK_NAME;

    fn key_constructor(params: Self::KeyParams) -> DbResult<Vec<u8>> {
        // ToDo: Replace with increasing ordering serialization
        borsh::to_vec(&params).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some(format!(
                    "Failed to serialize {:?} key params",
                    Self::CELL_NAME
                )),
            )
        })
    }
}

impl SimpleReadableCell for BlockCell {}
