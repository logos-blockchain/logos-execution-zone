#![expect(
    clippy::struct_field_names,
    reason = "`handle*` prefix is used for convenience with `Message` trait"
)]

use common::{
    block::{Block, BlockMeta, PeerChainTip},
    transaction::LeeTransaction,
};
use kameo::{
    Actor, Reply,
    actor::ActorRef,
    message::{Context, Message},
};
use lee::V03State;
use lee_core::BlockId;

use crate::{
    Result, StorageActorTrait,
    error::Error,
    protocol::{
        AddPendingCrossZoneDispatches, AddPendingDepositEvent, ApplyStoreUpdate,
        CleanPendingBlocksUpTo, ConsumeUnseenWithdrawCount, DbDump, DeadLetterDispatchRecord,
        DeadLetterRequeue, DeleteBlock, DeleteCrossZonePeerFloor, DeleteZoneCheckpoint,
        DispatchFailure, DropSettledCrossZoneDispatches, DumpDb, GetAllBlocks, GetBlock,
        GetChannelCursor, GetCrossZonePeerFloorBytes, GetCrossZonePeerTip,
        GetDeadLetterDispatchCount, GetDeadLetterDispatches, GetFinalSnapshot, GetFirstBlockId,
        GetLastBlockId, GetLatestBlockMeta, GetLeeState, GetPendingCrossZoneDispatches,
        GetPendingDepositEvents, GetPublishedHighWater, GetSlashRecordBytes, GetTransactionByHash,
        GetZoneAnchor, GetZoneCheckpointBytes, MarkBlockAsFinalized,
        PendingCrossZoneDispatchRecord, PendingDepositEventRecord, PutSlashRecordBytes,
        RaisePublishedHighWater, RecordDispatchFailure, RecordNewBlock, RequeueDeadLetterDispatch,
        ResetAllBlocksToPending, SetCrossZonePeerFloorBytes, SetCrossZonePeerTip, SetZoneAnchor,
        SetZoneCheckpointBytes, StoreUpdateOutcome, ZoneAnchorRecord,
    },
};

mockall::mock! {
    pub StorageActor {
        pub fn handle_record_new_block(
            &mut self,
            msg: RecordNewBlock,
            ctx: &mut Context<Self, Result<()>>
        ) -> Result<()>;

        pub fn handle_get_block(
            &mut self,
            msg: GetBlock,
            ctx: &mut Context<Self, Result<Option<Block>>>
        ) -> Result<Option<Block>>;

        pub fn handle_get_all_blocks(
            &mut self,
            msg: GetAllBlocks,
            ctx: &mut Context<Self, Result<Vec<Block>>>
        ) -> Result<Vec<Block>>;

        pub fn handle_get_transaction_by_hash(
            &mut self,
            msg: GetTransactionByHash,
            ctx: &mut Context<Self, Result<Option<(LeeTransaction, BlockId)>>>
        ) -> Result<Option<(LeeTransaction, BlockId)>>;

        pub fn handle_delete_block(
            &mut self,
            msg: DeleteBlock,
            ctx: &mut Context<Self, Result<()>>
        ) -> Result<()>;

        pub fn handle_mark_block_as_finalized(
            &mut self,
            msg: MarkBlockAsFinalized,
            ctx: &mut Context<Self, Result<()>>
        ) -> Result<()>;

        pub fn handle_reset_all_blocks_to_pending(
            &mut self,
            msg: ResetAllBlocksToPending,
            ctx: &mut Context<Self, Result<()>>
        ) -> Result<()>;

        pub fn handle_get_first_block_id(
            &mut self,
            msg: GetFirstBlockId,
            ctx: &mut Context<Self, Result<Option<BlockId>>>
        ) -> Result<Option<BlockId>>;

        pub fn handle_get_last_block_id(
            &mut self,
            msg: GetLastBlockId,
            ctx: &mut Context<Self, Result<Option<BlockId>>>
        ) -> Result<Option<BlockId>>;

        pub fn handle_get_latest_block_meta(
            &mut self,
            msg: GetLatestBlockMeta,
            ctx: &mut Context<Self, Result<Option<BlockMeta>>>
        ) -> Result<Option<BlockMeta>>;

        pub fn handle_get_lee_state(
            &mut self,
            msg: GetLeeState,
            ctx: &mut Context<Self, Result<Option<V03State>>>
        ) -> Result<Option<V03State>>;

        pub fn handle_get_zone_checkpoint_bytes(
            &mut self,
            msg: GetZoneCheckpointBytes,
            ctx: &mut Context<Self, Result<Option<Vec<u8>>>>
        ) -> Result<Option<Vec<u8>>>;

        pub fn handle_set_zone_checkpoint_bytes(
            &mut self,
            msg: SetZoneCheckpointBytes,
            ctx: &mut Context<Self, Result<()>>
        ) -> Result<()>;

        pub fn handle_get_slash_record_bytes(
            &mut self,
            msg: GetSlashRecordBytes,
            ctx: &mut Context<Self, Result<Option<Vec<u8>>>>
        ) -> Result<Option<Vec<u8>>>;

        pub fn handle_put_slash_record_bytes(
            &mut self,
            msg: PutSlashRecordBytes,
            ctx: &mut Context<Self, Result<()>>
        ) -> Result<()>;

        pub fn handle_delete_zone_checkpoint(
            &mut self,
            msg: DeleteZoneCheckpoint,
            ctx: &mut Context<Self, Result<()>>
        ) -> Result<()>;

        pub fn handle_get_zone_anchor(
            &mut self,
            msg: GetZoneAnchor,
            ctx: &mut Context<Self, Result<Option<ZoneAnchorRecord>>>
        ) -> Result<Option<ZoneAnchorRecord>>;

        pub fn handle_set_zone_anchor(
            &mut self,
            msg: SetZoneAnchor,
            ctx: &mut Context<Self, Result<()>>
        ) -> Result<()>;

        pub fn handle_get_channel_cursor(
            &mut self,
            msg: GetChannelCursor,
            ctx: &mut Context<Self, Result<Option<[u8; 32]>>>
        ) -> Result<Option<[u8; 32]>>;

        pub fn handle_get_published_high_water(
            &mut self,
            msg: GetPublishedHighWater,
            ctx: &mut Context<Self, Result<Option<BlockId>>>
        ) -> Result<Option<BlockId>>;

        pub fn handle_raise_published_high_water(
            &mut self,
            msg: RaisePublishedHighWater,
            ctx: &mut Context<Self, Result<()>>
        ) -> Result<()>;

        pub fn handle_get_pending_deposit_events(
            &mut self,
            msg: GetPendingDepositEvents,
            ctx: &mut Context<Self, Result<Vec<PendingDepositEventRecord>>>
        ) -> Result<Vec<PendingDepositEventRecord>>;

        pub fn handle_apply_store_update(
            &mut self,
            msg: ApplyStoreUpdate,
            ctx: &mut Context<Self, Result<StoreUpdateOutcome>>
        ) -> Result<StoreUpdateOutcome>;

        pub fn handle_clean_pending_blocks_up_to(
            &mut self,
            msg: CleanPendingBlocksUpTo,
            ctx: &mut Context<Self, Result<()>>
        ) -> Result<()>;

        pub fn handle_get_final_snapshot(
            &mut self,
            msg: GetFinalSnapshot,
            ctx: &mut Context<Self, Result<Option<(V03State, BlockMeta)>>>
        ) -> Result<Option<(V03State, BlockMeta)>>;

        pub fn handle_add_pending_deposit_event(
            &mut self,
            msg: AddPendingDepositEvent,
            ctx: &mut Context<Self, Result<bool>>
        ) -> Result<bool>;

        pub fn handle_consume_unseen_withdraw_count(
            &mut self,
            msg: ConsumeUnseenWithdrawCount,
            ctx: &mut Context<Self, Result<bool>>
        ) -> Result<bool>;

        pub fn handle_get_pending_cross_zone_dispatches(
            &mut self,
            msg: GetPendingCrossZoneDispatches,
            ctx: &mut Context<Self, Result<Vec<PendingCrossZoneDispatchRecord>>>
        ) -> Result<Vec<PendingCrossZoneDispatchRecord>>;

        pub fn handle_add_pending_cross_zone_dispatches(
            &mut self,
            msg: AddPendingCrossZoneDispatches,
            ctx: &mut Context<Self, Result<usize>>
        ) -> Result<usize>;

        pub fn handle_drop_settled_cross_zone_dispatches(
            &mut self,
            msg: DropSettledCrossZoneDispatches,
            ctx: &mut Context<Self, Result<usize>>
        ) -> Result<usize>;

        pub fn handle_record_dispatch_failure(
            &mut self,
            msg: RecordDispatchFailure,
            ctx: &mut Context<Self, Result<DispatchFailure>>
        ) -> Result<DispatchFailure>;

        pub fn handle_requeue_dead_letter_dispatch(
            &mut self,
            msg: RequeueDeadLetterDispatch,
            ctx: &mut Context<Self, Result<DeadLetterRequeue>>
        ) -> Result<DeadLetterRequeue>;

        pub fn handle_get_dead_letter_dispatches(
            &mut self,
            msg: GetDeadLetterDispatches,
            ctx: &mut Context<Self, Result<Vec<DeadLetterDispatchRecord>>>
        ) -> Result<Vec<DeadLetterDispatchRecord>>;

        pub fn handle_get_dead_letter_dispatch_count(
            &mut self,
            msg: GetDeadLetterDispatchCount,
            ctx: &mut Context<Self, Result<u64>>
        ) -> Result<u64>;

        pub fn handle_get_cross_zone_peer_floor_bytes(
            &mut self,
            msg: GetCrossZonePeerFloorBytes,
            ctx: &mut Context<Self, Result<Option<Vec<u8>>>>
        ) -> Result<Option<Vec<u8>>>;

        pub fn handle_set_cross_zone_peer_floor_bytes(
            &mut self,
            msg: SetCrossZonePeerFloorBytes,
            ctx: &mut Context<Self, Result<()>>
        ) -> Result<()>;

        pub fn handle_delete_cross_zone_peer_floor(
            &mut self,
            msg: DeleteCrossZonePeerFloor,
            ctx: &mut Context<Self, Result<()>>
        ) -> Result<()>;

        pub fn handle_get_cross_zone_peer_tip(
            &mut self,
            msg: GetCrossZonePeerTip,
            ctx: &mut Context<Self, Result<Option<PeerChainTip>>>
        ) -> Result<Option<common::block::PeerChainTip>>;

        pub fn handle_set_cross_zone_peer_tip(
            &mut self,
            msg: SetCrossZonePeerTip,
            ctx: &mut Context<Self, Result<()>>
        ) -> Result<()>;

        pub fn handle_dump_db(
            &mut self,
            msg: DumpDb,
            ctx: &mut Context<Self, Result<DbDump>>
        ) -> Result<DbDump>;
    }
}

impl StorageActorTrait for MockStorageActor {}

impl Actor for MockStorageActor {
    type Args = Self;
    type Error = Error;

    async fn on_start(args: Self::Args, _actor_ref: ActorRef<Self>) -> Result<Self> {
        Ok(args)
    }
}

/// Special message to trigger [`MockStorageActor::checkpoint()`].
pub struct Checkpoint;

impl Message<Checkpoint> for MockStorageActor {
    type Reply = ();

    async fn handle(
        &mut self,
        Checkpoint: Checkpoint,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.checkpoint();
    }
}

/// Special message to [`std::mem::replace()`] the inner state of [`MockStorageActor`] with a new
/// one, returning old state.
/// This is useful for testing, to swap in a new mock with different expectations.
pub struct Replace {
    pub mock: MockStorageActor,
}

#[derive(Reply)]
pub struct ReplaceReply {
    pub old_mock: MockStorageActor,
}

impl Message<Replace> for MockStorageActor {
    type Reply = ReplaceReply;

    async fn handle(
        &mut self,
        Replace { mock }: Replace,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let old_mock = std::mem::replace(self, mock);
        ReplaceReply { old_mock }
    }
}

impl Message<RecordNewBlock> for MockStorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        msg: RecordNewBlock,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_record_new_block(msg, ctx)
    }
}

impl Message<GetBlock> for MockStorageActor {
    type Reply = Result<Option<Block>>;

    async fn handle(&mut self, msg: GetBlock, ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        self.handle_get_block(msg, ctx)
    }
}

impl Message<GetAllBlocks> for MockStorageActor {
    type Reply = Result<Vec<Block>>;

    async fn handle(
        &mut self,
        msg: GetAllBlocks,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_all_blocks(msg, ctx)
    }
}

impl Message<GetTransactionByHash> for MockStorageActor {
    type Reply = Result<Option<(LeeTransaction, BlockId)>>;

    async fn handle(
        &mut self,
        msg: GetTransactionByHash,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_transaction_by_hash(msg, ctx)
    }
}

impl Message<DeleteBlock> for MockStorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        msg: DeleteBlock,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_delete_block(msg, ctx)
    }
}

impl Message<MarkBlockAsFinalized> for MockStorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        msg: MarkBlockAsFinalized,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_mark_block_as_finalized(msg, ctx)
    }
}

impl Message<ResetAllBlocksToPending> for MockStorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        msg: ResetAllBlocksToPending,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_reset_all_blocks_to_pending(msg, ctx)
    }
}

impl Message<GetFirstBlockId> for MockStorageActor {
    type Reply = Result<Option<BlockId>>;

    async fn handle(
        &mut self,
        msg: GetFirstBlockId,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_first_block_id(msg, ctx)
    }
}

impl Message<GetLastBlockId> for MockStorageActor {
    type Reply = Result<Option<BlockId>>;

    async fn handle(
        &mut self,
        msg: GetLastBlockId,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_last_block_id(msg, ctx)
    }
}

impl Message<GetLatestBlockMeta> for MockStorageActor {
    type Reply = Result<Option<BlockMeta>>;

    async fn handle(
        &mut self,
        msg: GetLatestBlockMeta,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_latest_block_meta(msg, ctx)
    }
}

impl Message<GetLeeState> for MockStorageActor {
    type Reply = Result<Option<V03State>>;

    async fn handle(
        &mut self,
        msg: GetLeeState,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_lee_state(msg, ctx)
    }
}

impl Message<GetZoneCheckpointBytes> for MockStorageActor {
    type Reply = Result<Option<Vec<u8>>>;

    async fn handle(
        &mut self,
        msg: GetZoneCheckpointBytes,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_zone_checkpoint_bytes(msg, ctx)
    }
}

impl Message<SetZoneCheckpointBytes> for MockStorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        msg: SetZoneCheckpointBytes,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_set_zone_checkpoint_bytes(msg, ctx)
    }
}

impl Message<GetSlashRecordBytes> for MockStorageActor {
    type Reply = Result<Option<Vec<u8>>>;

    async fn handle(
        &mut self,
        msg: GetSlashRecordBytes,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_slash_record_bytes(msg, ctx)
    }
}

impl Message<PutSlashRecordBytes> for MockStorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        msg: PutSlashRecordBytes,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_put_slash_record_bytes(msg, ctx)
    }
}

impl Message<DeleteZoneCheckpoint> for MockStorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        msg: DeleteZoneCheckpoint,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_delete_zone_checkpoint(msg, ctx)
    }
}

impl Message<GetZoneAnchor> for MockStorageActor {
    type Reply = Result<Option<ZoneAnchorRecord>>;

    async fn handle(
        &mut self,
        msg: GetZoneAnchor,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_zone_anchor(msg, ctx)
    }
}

impl Message<SetZoneAnchor> for MockStorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        msg: SetZoneAnchor,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_set_zone_anchor(msg, ctx)
    }
}

impl Message<GetChannelCursor> for MockStorageActor {
    type Reply = Result<Option<[u8; 32]>>;

    async fn handle(
        &mut self,
        msg: GetChannelCursor,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_channel_cursor(msg, ctx)
    }
}

impl Message<GetPublishedHighWater> for MockStorageActor {
    type Reply = Result<Option<BlockId>>;

    async fn handle(
        &mut self,
        msg: GetPublishedHighWater,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_published_high_water(msg, ctx)
    }
}

impl Message<RaisePublishedHighWater> for MockStorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        msg: RaisePublishedHighWater,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_raise_published_high_water(msg, ctx)
    }
}

impl Message<GetPendingDepositEvents> for MockStorageActor {
    type Reply = Result<Vec<PendingDepositEventRecord>>;

    async fn handle(
        &mut self,
        msg: GetPendingDepositEvents,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_pending_deposit_events(msg, ctx)
    }
}

impl Message<DumpDb> for MockStorageActor {
    type Reply = Result<DbDump>;

    async fn handle(&mut self, msg: DumpDb, ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        self.handle_dump_db(msg, ctx)
    }
}

impl Message<ApplyStoreUpdate> for MockStorageActor {
    type Reply = Result<StoreUpdateOutcome>;

    async fn handle(
        &mut self,
        msg: ApplyStoreUpdate,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_apply_store_update(msg, ctx)
    }
}

impl Message<CleanPendingBlocksUpTo> for MockStorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        msg: CleanPendingBlocksUpTo,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_clean_pending_blocks_up_to(msg, ctx)
    }
}

impl Message<GetFinalSnapshot> for MockStorageActor {
    type Reply = Result<Option<(V03State, BlockMeta)>>;

    async fn handle(
        &mut self,
        msg: GetFinalSnapshot,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_final_snapshot(msg, ctx)
    }
}

impl Message<AddPendingDepositEvent> for MockStorageActor {
    type Reply = Result<bool>;

    async fn handle(
        &mut self,
        msg: AddPendingDepositEvent,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_add_pending_deposit_event(msg, ctx)
    }
}

impl Message<ConsumeUnseenWithdrawCount> for MockStorageActor {
    type Reply = Result<bool>;

    async fn handle(
        &mut self,
        msg: ConsumeUnseenWithdrawCount,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_consume_unseen_withdraw_count(msg, ctx)
    }
}

impl Message<GetPendingCrossZoneDispatches> for MockStorageActor {
    type Reply = Result<Vec<PendingCrossZoneDispatchRecord>>;

    async fn handle(
        &mut self,
        msg: GetPendingCrossZoneDispatches,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_pending_cross_zone_dispatches(msg, ctx)
    }
}

impl Message<AddPendingCrossZoneDispatches> for MockStorageActor {
    type Reply = Result<usize>;

    async fn handle(
        &mut self,
        msg: AddPendingCrossZoneDispatches,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_add_pending_cross_zone_dispatches(msg, ctx)
    }
}

impl Message<DropSettledCrossZoneDispatches> for MockStorageActor {
    type Reply = Result<usize>;

    async fn handle(
        &mut self,
        msg: DropSettledCrossZoneDispatches,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_drop_settled_cross_zone_dispatches(msg, ctx)
    }
}

impl Message<RecordDispatchFailure> for MockStorageActor {
    type Reply = Result<DispatchFailure>;

    async fn handle(
        &mut self,
        msg: RecordDispatchFailure,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_record_dispatch_failure(msg, ctx)
    }
}

impl Message<RequeueDeadLetterDispatch> for MockStorageActor {
    type Reply = Result<DeadLetterRequeue>;

    async fn handle(
        &mut self,
        msg: RequeueDeadLetterDispatch,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_requeue_dead_letter_dispatch(msg, ctx)
    }
}

impl Message<GetDeadLetterDispatches> for MockStorageActor {
    type Reply = Result<Vec<DeadLetterDispatchRecord>>;

    async fn handle(
        &mut self,
        msg: GetDeadLetterDispatches,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_dead_letter_dispatches(msg, ctx)
    }
}

impl Message<GetDeadLetterDispatchCount> for MockStorageActor {
    type Reply = Result<u64>;

    async fn handle(
        &mut self,
        msg: GetDeadLetterDispatchCount,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_dead_letter_dispatch_count(msg, ctx)
    }
}

impl Message<GetCrossZonePeerFloorBytes> for MockStorageActor {
    type Reply = Result<Option<Vec<u8>>>;

    async fn handle(
        &mut self,
        msg: GetCrossZonePeerFloorBytes,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_cross_zone_peer_floor_bytes(msg, ctx)
    }
}

impl Message<SetCrossZonePeerFloorBytes> for MockStorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        msg: SetCrossZonePeerFloorBytes,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_set_cross_zone_peer_floor_bytes(msg, ctx)
    }
}

impl Message<DeleteCrossZonePeerFloor> for MockStorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        msg: DeleteCrossZonePeerFloor,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_delete_cross_zone_peer_floor(msg, ctx)
    }
}

impl Message<GetCrossZonePeerTip> for MockStorageActor {
    type Reply = Result<Option<PeerChainTip>>;

    async fn handle(
        &mut self,
        msg: GetCrossZonePeerTip,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_cross_zone_peer_tip(msg, ctx)
    }
}

impl Message<SetCrossZonePeerTip> for MockStorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        msg: SetCrossZonePeerTip,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_set_cross_zone_peer_tip(msg, ctx)
    }
}
