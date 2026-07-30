use borsh::{BorshDeserialize, BorshSerialize};
use common::{HashType, block::BlockMeta};
use lee::V03State;

use crate::{
    CF_META_NAME, DbResult,
    cells::{SimpleReadableCell, SimpleStorableCell, SimpleWritableCell},
    error::DbError,
    sequencer::{
        CF_LEE_STATE_NAME, DB_FINAL_BLOCK_META_KEY, DB_FINAL_LEE_STATE_KEY, DB_LEE_STATE_KEY,
        DB_META_LAST_FINALIZED_BLOCK_ID, DB_META_LATEST_BLOCK_META_KEY,
        DB_META_PENDING_DEPOSIT_EVENTS_KEY, DB_META_UNSEEN_WITHDRAW_COUNT_KEY,
        DB_META_ZONE_CURSOR_KEY, DB_META_ZONE_SDK_CHECKPOINT_KEY,
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

/// State at the last L1-finalized block, written atomically with
/// [`FinalBlockMetaCellRef`].
#[derive(BorshDeserialize)]
pub struct FinalLeeStateCellOwned(pub V03State);

impl SimpleStorableCell for FinalLeeStateCellOwned {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_FINAL_LEE_STATE_KEY;
    const CF_NAME: &'static str = CF_LEE_STATE_NAME;
}

impl SimpleReadableCell for FinalLeeStateCellOwned {}

#[derive(BorshSerialize)]
pub struct FinalLeeStateCellRef<'state>(pub &'state V03State);

impl SimpleStorableCell for FinalLeeStateCellRef<'_> {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_FINAL_LEE_STATE_KEY;
    const CF_NAME: &'static str = CF_LEE_STATE_NAME;
}

impl SimpleWritableCell for FinalLeeStateCellRef<'_> {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(err, Some("Failed to serialize final state".to_owned()))
        })
    }
}

/// `(id, hash)` of the last L1-finalized block, paired with [`FinalLeeStateCellRef`].
#[derive(BorshDeserialize)]
pub struct FinalBlockMetaCellOwned(pub BlockMeta);

impl SimpleStorableCell for FinalBlockMetaCellOwned {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_FINAL_BLOCK_META_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleReadableCell for FinalBlockMetaCellOwned {}

#[derive(BorshSerialize)]
pub struct FinalBlockMetaCellRef<'blockmeta>(pub &'blockmeta BlockMeta);

impl SimpleStorableCell for FinalBlockMetaCellRef<'_> {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_FINAL_BLOCK_META_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleWritableCell for FinalBlockMetaCellRef<'_> {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some("Failed to serialize final block meta".to_owned()),
            )
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

/// The last channel block read back and verified from Bedrock.
///
/// Holds its L1 inscription `slot` plus the block's `id`/`hash`, and serves as
/// both the anchor for the startup consistency check and the resume point for
/// reconstruction. `slot` is stored as a raw `u64` because the zone-sdk `Slot`
/// does not derive borsh; the caller converts to/from `Slot`.
#[derive(Debug, Clone, Copy, BorshSerialize, BorshDeserialize)]
pub struct ZoneAnchorRecord {
    pub slot: u64,
    pub block_id: u64,
    pub hash: HashType,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct ZoneAnchorCell(pub ZoneAnchorRecord);

impl SimpleStorableCell for ZoneAnchorCell {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_ZONE_CURSOR_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleReadableCell for ZoneAnchorCell {}

impl SimpleWritableCell for ZoneAnchorCell {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(err, Some("Failed to serialize zone cursor".to_owned()))
        })
    }
}

/// An L1 deposit event observed but not yet seen finalized.
///
/// Purely a liveness queue: whether to actually emit a mint is decided against
/// chain state (the deposit-receipt PDA), and the record is dropped once its
/// mint finalizes.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PendingDepositEventRecord {
    pub deposit_op_id: HashType,
    pub source_tx_hash: HashType,
    pub amount: u64,
    pub metadata: Vec<u8>,
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

/// Identity of one withdrawal, shared by the intent recorded when the
/// sequencer publishes it and the Bedrock Withdraw event that later reports
/// it: the id of the channel note the withdrawal releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WithdrawalReconciliationKey {
    pub released_note_id: [u8; 32],
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct UnseenWithdrawCountCell(pub u64);

impl SimpleStorableCell for UnseenWithdrawCountCell {
    type KeyParams = WithdrawalReconciliationKey;

    const CELL_NAME: &'static str = DB_META_UNSEEN_WITHDRAW_COUNT_KEY;
    const CF_NAME: &'static str = CF_META_NAME;

    fn key_constructor(key_params: Self::KeyParams) -> DbResult<Vec<u8>> {
        let WithdrawalReconciliationKey { released_note_id } = key_params;

        borsh::to_vec(&(Self::CELL_NAME, released_note_id)).map_err(|err| {
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

impl SimpleReadableCell for UnseenWithdrawCountCell {}

impl SimpleWritableCell for UnseenWithdrawCountCell {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some("Failed to serialize unseen withdraw count".to_owned()),
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
