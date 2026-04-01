use borsh::{BorshDeserialize, BorshSerialize};
use common::block::BlockMeta;
use nssa::V03State;

use crate::{
    CF_META_NAME, DbResult,
    error::DbError,
    sequencer::{
        CF_NSSA_STATE_NAME, DB_META_LAST_FINALIZED_BLOCK_ID, DB_META_LATEST_BLOCK_META_KEY,
        DB_NSSA_STATE_KEY,
    },
    storable_cell::{SimpleReadableCell, SimpleStorableCell, SimpleWritableCell},
};

#[derive(BorshDeserialize)]
pub struct NSSAStateCellOwned(pub V03State);

impl SimpleStorableCell for NSSAStateCellOwned {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_NSSA_STATE_KEY;
    const CF_NAME: &'static str = CF_NSSA_STATE_NAME;
}

impl SimpleReadableCell for NSSAStateCellOwned {}

#[derive(BorshSerialize)]
pub struct NSSAStateCellRef<'state>(pub &'state V03State);

impl SimpleStorableCell for NSSAStateCellRef<'_> {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_NSSA_STATE_KEY;
    const CF_NAME: &'static str = CF_NSSA_STATE_NAME;
}

impl SimpleWritableCell for NSSAStateCellRef<'_> {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(err, Some("Failed to serialize last state".to_owned()))
        })
    }
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct LastFinalizedBlockIdCell(pub Option<u64>);

impl SimpleStorableCell for LastFinalizedBlockIdCell {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_LAST_FINALIZED_BLOCK_ID;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleReadableCell for LastFinalizedBlockIdCell {}

impl SimpleWritableCell for LastFinalizedBlockIdCell {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some("Failed to serialize last finalized block id".to_owned()),
            )
        })
    }
}

#[derive(BorshDeserialize)]
pub struct LatestBlockMetaCellOwned(pub BlockMeta);

impl SimpleStorableCell for LatestBlockMetaCellOwned {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_LATEST_BLOCK_META_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleReadableCell for LatestBlockMetaCellOwned {}

#[derive(BorshSerialize)]
pub struct LatestBlockMetaCellRef<'blockmeta>(pub &'blockmeta BlockMeta);

impl SimpleStorableCell for LatestBlockMetaCellRef<'_> {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_LATEST_BLOCK_META_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleWritableCell for LatestBlockMetaCellRef<'_> {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(err, Some("Failed to serialize last block meta".to_owned()))
        })
    }
}

#[cfg(test)]
mod uniform_tests {
    use crate::{
        sequencer::sequencer_cells::{
            LatestBlockMetaCellOwned, LatestBlockMetaCellRef, NSSAStateCellOwned, NSSAStateCellRef,
        },
        storable_cell::SimpleStorableCell as _,
    };

    #[test]
    fn state_ref_and_owned_is_aligned() {
        assert_eq!(NSSAStateCellRef::CELL_NAME, NSSAStateCellOwned::CELL_NAME);
        assert_eq!(NSSAStateCellRef::CF_NAME, NSSAStateCellOwned::CF_NAME);
        assert_eq!(
            NSSAStateCellRef::key_constructor(()).unwrap(),
            NSSAStateCellOwned::key_constructor(()).unwrap()
        );
    }

    #[test]
    fn block_meta_ref_and_owned_is_aligned() {
        assert_eq!(
            LatestBlockMetaCellRef::CELL_NAME,
            LatestBlockMetaCellOwned::CELL_NAME
        );
        assert_eq!(
            LatestBlockMetaCellRef::CF_NAME,
            LatestBlockMetaCellOwned::CF_NAME
        );
        assert_eq!(
            LatestBlockMetaCellRef::key_constructor(()).unwrap(),
            LatestBlockMetaCellOwned::key_constructor(()).unwrap()
        );
    }
}
