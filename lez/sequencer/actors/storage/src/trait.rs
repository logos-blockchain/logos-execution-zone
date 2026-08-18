use common::{
    block::{Block, BlockMeta, PeerChainTip},
    transaction::LeeTransaction,
};
use kameo::{Actor, message::Message};
use lee::V03State;
use lee_core::BlockId;

use crate::{
    Result,
    error::Error,
    protocol::{
        AddPendingCrossZoneDispatches, AddPendingDepositEvent, ApplyStoreUpdate,
        CleanPendingBlocksUpTo, ConsumeUnseenWithdrawCount, DbDump, DeadLetterDispatchRecord,
        DeleteBlock, DeleteCrossZonePeerFloor, DeleteZoneCheckpoint, DispatchFailure,
        DropSettledCrossZoneDispatches, DumpDb, GetAllBlocks, GetBlock, GetCrossZonePeerFloorBytes,
        GetCrossZonePeerTip, GetDeadLetterDispatchCount, GetDeadLetterDispatches, GetFinalSnapshot,
        GetFirstBlockId, GetLastBlockId, GetLatestBlockMeta, GetLeeState,
        GetPendingCrossZoneDispatches, GetPendingDepositEvents, GetPublishedHighWater,
        GetSlashRecordBytes, GetTransactionByHash, GetZoneAnchor, GetZoneCheckpointBytes,
        MarkBlockAsFinalized,
        PendingCrossZoneDispatchRecord, PendingDepositEventRecord, RaisePublishedHighWater,
        RecordDispatchFailure, RecordNewBlock, ResetAllBlocksToPending, SetCrossZonePeerFloorBytes,
        PutSlashRecordBytes, SetCrossZonePeerTip, SetZoneAnchor, SetZoneCheckpointBytes,
        StoreUpdateOutcome,
        ZoneAnchorRecord,
    },
};

pub trait StorageActorTrait:
    Actor<Args = Self, Error = Error>
    + Message<RecordNewBlock, Reply = Result<()>>
    + Message<ApplyStoreUpdate, Reply = Result<StoreUpdateOutcome>>
    + Message<GetBlock, Reply = Result<Option<Block>>>
    + Message<GetAllBlocks, Reply = Result<Vec<Block>>>
    + Message<GetTransactionByHash, Reply = Result<Option<(LeeTransaction, BlockId)>>>
    + Message<DeleteBlock, Reply = Result<()>>
    + Message<MarkBlockAsFinalized, Reply = Result<()>>
    + Message<CleanPendingBlocksUpTo, Reply = Result<()>>
    + Message<ResetAllBlocksToPending, Reply = Result<()>>
    + Message<GetFirstBlockId, Reply = Result<Option<BlockId>>>
    + Message<GetLastBlockId, Reply = Result<Option<BlockId>>>
    + Message<GetLatestBlockMeta, Reply = Result<Option<BlockMeta>>>
    + Message<GetLeeState, Reply = Result<Option<V03State>>>
    + Message<GetFinalSnapshot, Reply = Result<Option<(V03State, BlockMeta)>>>
    + Message<GetZoneCheckpointBytes, Reply = Result<Option<Vec<u8>>>>
    + Message<SetZoneCheckpointBytes, Reply = Result<()>>
    + Message<GetSlashRecordBytes, Reply = Result<Option<Vec<u8>>>>
    + Message<PutSlashRecordBytes, Reply = Result<()>>
    + Message<DeleteZoneCheckpoint, Reply = Result<()>>
    + Message<GetZoneAnchor, Reply = Result<Option<ZoneAnchorRecord>>>
    + Message<SetZoneAnchor, Reply = Result<()>>
    + Message<GetPublishedHighWater, Reply = Result<Option<BlockId>>>
    + Message<RaisePublishedHighWater, Reply = Result<()>>
    + Message<GetPendingDepositEvents, Reply = Result<Vec<PendingDepositEventRecord>>>
    + Message<AddPendingDepositEvent, Reply = Result<bool>>
    + Message<ConsumeUnseenWithdrawCount, Reply = Result<bool>>
    + Message<GetPendingCrossZoneDispatches, Reply = Result<Vec<PendingCrossZoneDispatchRecord>>>
    + Message<AddPendingCrossZoneDispatches, Reply = Result<usize>>
    + Message<DropSettledCrossZoneDispatches, Reply = Result<usize>>
    + Message<RecordDispatchFailure, Reply = Result<DispatchFailure>>
    + Message<GetDeadLetterDispatches, Reply = Result<Vec<DeadLetterDispatchRecord>>>
    + Message<GetDeadLetterDispatchCount, Reply = Result<u64>>
    + Message<GetCrossZonePeerFloorBytes, Reply = Result<Option<Vec<u8>>>>
    + Message<SetCrossZonePeerFloorBytes, Reply = Result<()>>
    + Message<DeleteCrossZonePeerFloor, Reply = Result<()>>
    + Message<GetCrossZonePeerTip, Reply = Result<Option<PeerChainTip>>>
    + Message<SetCrossZonePeerTip, Reply = Result<()>>
    + Message<DumpDb, Reply = Result<DbDump>>
{
}
