use borsh::{BorshDeserialize, BorshSerialize};
use nssa::V03State;

use crate::{
    CF_META_NAME, DbResult,
    cells::{SimpleReadableCell, SimpleStorableCell, SimpleWritableCell},
    error::DbError,
    indexer::{
        ACC_NUM_CELL_NAME, BLOCK_HASH_CELL_NAME, BREAKPOINT_CELL_NAME, CF_ACC_META,
        CF_BREAKPOINT_NAME, CF_HASH_TO_ID, CF_TX_TO_ID, DB_META_LAST_BREAKPOINT_ID,
        DB_META_LAST_OBSERVED_L1_LIB_HEADER_ID_IN_DB_KEY, DB_META_ZONE_SDK_INDEXER_CURSOR_KEY,
        TX_HASH_CELL_NAME,
    },
};

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct LastObservedL1LibHeaderCell(pub [u8; 32]);

impl SimpleStorableCell for LastObservedL1LibHeaderCell {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_LAST_OBSERVED_L1_LIB_HEADER_ID_IN_DB_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleReadableCell for LastObservedL1LibHeaderCell {}

impl SimpleWritableCell for LastObservedL1LibHeaderCell {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some("Failed to serialize last observed l1 header".to_owned()),
            )
        })
    }
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct LastBreakpointIdCell(pub u64);

impl SimpleStorableCell for LastBreakpointIdCell {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_LAST_BREAKPOINT_ID;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleReadableCell for LastBreakpointIdCell {}

impl SimpleWritableCell for LastBreakpointIdCell {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some("Failed to serialize last breakpoint id".to_owned()),
            )
        })
    }
}

#[derive(BorshDeserialize)]
pub struct BreakpointCellOwned(pub V03State);

impl SimpleStorableCell for BreakpointCellOwned {
    type KeyParams = u64;

    const CELL_NAME: &'static str = BREAKPOINT_CELL_NAME;
    const CF_NAME: &'static str = CF_BREAKPOINT_NAME;

    fn key_constructor(params: Self::KeyParams) -> DbResult<Vec<u8>> {
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

impl SimpleReadableCell for BreakpointCellOwned {}

#[derive(BorshSerialize)]
pub struct BreakpointCellRef<'state>(pub &'state V03State);

impl SimpleStorableCell for BreakpointCellRef<'_> {
    type KeyParams = u64;

    const CELL_NAME: &'static str = BREAKPOINT_CELL_NAME;
    const CF_NAME: &'static str = CF_BREAKPOINT_NAME;

    fn key_constructor(params: Self::KeyParams) -> DbResult<Vec<u8>> {
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

impl SimpleWritableCell for BreakpointCellRef<'_> {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(err, Some("Failed to serialize breakpoint".to_owned()))
        })
    }
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct BlockHashToBlockIdMapCell(pub u64);

impl SimpleStorableCell for BlockHashToBlockIdMapCell {
    type KeyParams = [u8; 32];

    const CELL_NAME: &'static str = BLOCK_HASH_CELL_NAME;
    const CF_NAME: &'static str = CF_HASH_TO_ID;

    fn key_constructor(params: Self::KeyParams) -> DbResult<Vec<u8>> {
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

impl SimpleReadableCell for BlockHashToBlockIdMapCell {}

impl SimpleWritableCell for BlockHashToBlockIdMapCell {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(err, Some("Failed to serialize block id".to_owned()))
        })
    }
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct TxHashToBlockIdMapCell(pub u64);

impl SimpleStorableCell for TxHashToBlockIdMapCell {
    type KeyParams = [u8; 32];

    const CELL_NAME: &'static str = TX_HASH_CELL_NAME;
    const CF_NAME: &'static str = CF_TX_TO_ID;

    fn key_constructor(params: Self::KeyParams) -> DbResult<Vec<u8>> {
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

impl SimpleReadableCell for TxHashToBlockIdMapCell {}

impl SimpleWritableCell for TxHashToBlockIdMapCell {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(err, Some("Failed to serialize block id".to_owned()))
        })
    }
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct AccNumTxCell(pub u64);

impl SimpleStorableCell for AccNumTxCell {
    type KeyParams = [u8; 32];

    const CELL_NAME: &'static str = ACC_NUM_CELL_NAME;
    const CF_NAME: &'static str = CF_ACC_META;

    fn key_constructor(params: Self::KeyParams) -> DbResult<Vec<u8>> {
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

impl SimpleReadableCell for AccNumTxCell {}

impl SimpleWritableCell for AccNumTxCell {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some("Failed to serialize number of transactions".to_owned()),
            )
        })
    }
}

/// Opaque bytes for the zone-sdk indexer cursor `Option<(MsgId, Slot)>`.
/// The caller serializes via serde_json (neither type derives borsh).
#[derive(BorshDeserialize)]
pub struct ZoneSdkIndexerCursorCellOwned(pub Vec<u8>);

impl SimpleStorableCell for ZoneSdkIndexerCursorCellOwned {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_ZONE_SDK_INDEXER_CURSOR_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleReadableCell for ZoneSdkIndexerCursorCellOwned {}

#[derive(BorshSerialize)]
pub struct ZoneSdkIndexerCursorCellRef<'bytes>(pub &'bytes [u8]);

impl SimpleStorableCell for ZoneSdkIndexerCursorCellRef<'_> {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_ZONE_SDK_INDEXER_CURSOR_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleWritableCell for ZoneSdkIndexerCursorCellRef<'_> {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some("Failed to serialize zone-sdk indexer cursor cell".to_owned()),
            )
        })
    }
}

#[cfg(test)]
mod uniform_tests {
    use crate::{
        cells::SimpleStorableCell as _,
        indexer::indexer_cells::{BreakpointCellOwned, BreakpointCellRef},
    };

    #[test]
    fn breakpoint_ref_and_owned_is_aligned() {
        assert_eq!(BreakpointCellRef::CELL_NAME, BreakpointCellOwned::CELL_NAME);
        assert_eq!(BreakpointCellRef::CF_NAME, BreakpointCellOwned::CF_NAME);
        assert_eq!(
            BreakpointCellRef::key_constructor(1000).unwrap(),
            BreakpointCellOwned::key_constructor(1000).unwrap()
        );
    }
}
