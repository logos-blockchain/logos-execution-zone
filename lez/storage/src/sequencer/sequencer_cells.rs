use borsh::{BorshDeserialize, BorshSerialize};
use common::{HashType, block::BlockMeta};
use lee::V03State;

use crate::{
    CF_META_NAME, DbResult,
    cells::{SimpleReadableCell, SimpleStorableCell, SimpleWritableCell},
    error::DbError,
    sequencer::{
        CF_LEE_STATE_NAME, DB_LEE_STATE_KEY, DB_META_LAST_FINALIZED_BLOCK_ID,
        DB_META_LATEST_BLOCK_META_KEY, DB_META_PENDING_DEPOSIT_EVENTS_KEY,
        DB_META_ZONE_SDK_CHECKPOINT_KEY,
    },
};

#[derive(BorshDeserialize)]
pub struct LEEStateCellOwned(pub V03State);

impl SimpleStorableCell for LEEStateCellOwned {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_LEE_STATE_KEY;
    const CF_NAME: &'static str = CF_LEE_STATE_NAME;
}

impl SimpleReadableCell for LEEStateCellOwned {}

#[derive(BorshSerialize)]
pub struct LEEStateCellRef<'state>(pub &'state V03State);

impl SimpleStorableCell for LEEStateCellRef<'_> {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_LEE_STATE_KEY;
    const CF_NAME: &'static str = CF_LEE_STATE_NAME;
}

impl SimpleWritableCell for LEEStateCellRef<'_> {
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

/// Opaque bytes for the zone-sdk sequencer checkpoint. The caller is
/// responsible for the actual encoding (we use `serde_json` since
/// `SequencerCheckpoint` only derives serde, not borsh).
#[derive(BorshDeserialize)]
pub struct ZoneSdkCheckpointCellOwned(pub Vec<u8>);

impl SimpleStorableCell for ZoneSdkCheckpointCellOwned {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_ZONE_SDK_CHECKPOINT_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleReadableCell for ZoneSdkCheckpointCellOwned {}

#[derive(BorshSerialize)]
pub struct ZoneSdkCheckpointCellRef<'bytes>(pub &'bytes [u8]);

impl SimpleStorableCell for ZoneSdkCheckpointCellRef<'_> {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_ZONE_SDK_CHECKPOINT_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleWritableCell for ZoneSdkCheckpointCellRef<'_> {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some("Failed to serialize zone-sdk checkpoint cell".to_owned()),
            )
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PendingDepositEventRecord {
    pub deposit_op_id: HashType,
    pub source_tx_hash: HashType,
    pub amount: u64,
    pub metadata: Vec<u8>,
    /// Set when block containing the deposit event is submitted, but not necessarily finalized.
    pub submitted_in_block_id: Option<u64>,
}

#[derive(BorshDeserialize)]
pub struct PendingDepositEventsCellOwned(pub Vec<PendingDepositEventRecord>);

impl SimpleStorableCell for PendingDepositEventsCellOwned {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_PENDING_DEPOSIT_EVENTS_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleReadableCell for PendingDepositEventsCellOwned {}

#[derive(BorshSerialize)]
pub struct PendingDepositEventsCellRef<'records>(pub &'records [PendingDepositEventRecord]);

impl SimpleStorableCell for PendingDepositEventsCellRef<'_> {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_PENDING_DEPOSIT_EVENTS_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleWritableCell for PendingDepositEventsCellRef<'_> {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some("Failed to serialize pending deposit events cell".to_owned()),
            )
        })
    }
}

#[cfg(test)]
mod uniform_tests {
    use crate::{
        cells::SimpleStorableCell as _,
        sequencer::sequencer_cells::{
            LEEStateCellOwned, LEEStateCellRef, LatestBlockMetaCellOwned, LatestBlockMetaCellRef,
            PendingDepositEventsCellOwned, PendingDepositEventsCellRef,
        },
    };

    #[test]
    fn state_ref_and_owned_is_aligned() {
        assert_eq!(LEEStateCellRef::CELL_NAME, LEEStateCellOwned::CELL_NAME);
        assert_eq!(LEEStateCellRef::CF_NAME, LEEStateCellOwned::CF_NAME);
        assert_eq!(
            LEEStateCellRef::key_constructor(()).unwrap(),
            LEEStateCellOwned::key_constructor(()).unwrap()
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

    #[test]
    fn pending_deposit_events_ref_and_owned_is_aligned() {
        assert_eq!(
            PendingDepositEventsCellRef::CELL_NAME,
            PendingDepositEventsCellOwned::CELL_NAME
        );
        assert_eq!(
            PendingDepositEventsCellRef::CF_NAME,
            PendingDepositEventsCellOwned::CF_NAME
        );
        assert_eq!(
            PendingDepositEventsCellRef::key_constructor(()).unwrap(),
            PendingDepositEventsCellOwned::key_constructor(()).unwrap()
        );
    }
}
