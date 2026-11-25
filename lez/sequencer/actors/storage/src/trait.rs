use common::{
    block::{Block, BlockMeta, TransactionReceipt},
    transaction::LeeTransaction,
};
use kameo::{Actor, message::Message};
use lee::V03State;
use lee_core::BlockId;

use crate::{
    Result,
    error::Error,
    protocol::{
        AtomicUpdate, DbDump, DeleteBlock, DeleteZoneCheckpoint, DumpDb, GetAccountTransactions,
        GetAllBlocks, GetBlock, GetBlockByHash, GetChannelViewBytes, GetFinalConfigsBytes,
        GetFinalSnapshot, GetFirstBlockId, GetLastBlockId, GetLatestBlockMeta, GetLeeState,
        GetPendingDepositEvents, GetSlashRecordBytes, GetSystemApprovalsBytes,
        GetTransactionByHash, GetTransactionReceiptByHash, GetZoneAnchor, GetZoneCheckpoint,
        PendingDepositEventRecord, PutFinalConfigsBytes, PutSlashRecordBytes,
        PutSystemApprovalsBytes, SetZoneAnchor, StoreUpdateOutcome, UpdateZoneCheckpoint,
        ZoneAnchorRecord,
    },
};

pub trait StorageActorTrait:
    Actor<Args = Self, Error = Error>
    + Message<AtomicUpdate, Reply = Result<StoreUpdateOutcome>>
    + Message<GetBlock, Reply = Result<Option<Block>>>
    + Message<GetAllBlocks, Reply = Result<Vec<Block>>>
    + Message<GetTransactionByHash, Reply = Result<Option<(LeeTransaction, BlockId)>>>
    + Message<GetTransactionReceiptByHash, Reply = Result<Option<TransactionReceipt>>>
    + Message<DeleteBlock, Reply = Result<()>>
    + Message<GetFirstBlockId, Reply = Result<Option<BlockId>>>
    + Message<GetLastBlockId, Reply = Result<Option<BlockId>>>
    + Message<GetLatestBlockMeta, Reply = Result<Option<BlockMeta>>>
    + Message<GetLeeState, Reply = Result<Option<V03State>>>
    + Message<GetFinalSnapshot, Reply = Result<Option<(V03State, BlockMeta)>>>
    + Message<GetZoneCheckpoint, Reply = Result<Option<Vec<u8>>>>
    + Message<UpdateZoneCheckpoint, Reply = Result<()>>
    + Message<GetSlashRecordBytes, Reply = Result<Option<Vec<u8>>>>
    + Message<PutSlashRecordBytes, Reply = Result<()>>
    + Message<GetSystemApprovalsBytes, Reply = Result<Option<Vec<u8>>>>
    + Message<PutSystemApprovalsBytes, Reply = Result<()>>
    + Message<GetFinalConfigsBytes, Reply = Result<Option<Vec<u8>>>>
    + Message<PutFinalConfigsBytes, Reply = Result<()>>
    + Message<DeleteZoneCheckpoint, Reply = Result<()>>
    + Message<GetZoneAnchor, Reply = Result<Option<ZoneAnchorRecord>>>
    + Message<SetZoneAnchor, Reply = Result<()>>
    + Message<GetChannelViewBytes, Reply = Result<Option<Vec<u8>>>>
    + Message<GetPendingDepositEvents, Reply = Result<Vec<PendingDepositEventRecord>>>
    + Message<GetBlockByHash, Reply = Result<Option<u64>>>
    + Message<GetAccountTransactions, Reply = Result<Option<Vec<LeeTransaction>>>>
    + Message<DumpDb, Reply = Result<DbDump>>
{
}
