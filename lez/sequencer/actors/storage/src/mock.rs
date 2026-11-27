#![expect(
    clippy::struct_field_names,
    reason = "`handle*` prefix is used for convenience with `Message` trait"
)]

use common::{
    block::{Block, BlockMeta, TransactionReceipt},
    transaction::LeeTransaction,
};
use kameo::{
    Actor,
    actor::ActorRef,
    message::{Context, Message},
};
use lee::V03State;
use lee_core::BlockId;
pub use sequencer_actors_common::mock::{Checkpoint, Replace, ReplaceReply};

pub use self::canned_store::{CannedStore, SharedStore};
use crate::{
    Result, StorageActorTrait,
    error::Error,
    protocol::{
        AtomicUpdate, DbDump, DeleteBlock, DeleteZoneCheckpoint, DumpDb, EventFilter,
        GetAccountTransactions, GetAllBlocks, GetBlock, GetBlockByHash, GetChannelViewBytes,
        GetEventFilter, GetFinalConfigsBytes, GetFinalSnapshot, GetFirstBlockId, GetLastBlockId,
        GetLatestBlockMeta, GetLeeState, GetPendingDepositEvents, GetSlashRecordBytes,
        GetSystemApprovalsBytes, GetTransactionByHash, GetTransactionReceiptByHash, GetZoneAnchor,
        GetZoneCheckpoint, PendingDepositEventRecord, PutFinalConfigsBytes, PutSlashRecordBytes,
        PutSystemApprovalsBytes, SetZoneAnchor, StoreUpdateOutcome, UpdateZoneCheckpoint,
        ZoneAnchorRecord,
    },
};

mod canned_store;

mockall::mock! {
    pub StorageActor {
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

        pub fn handle_get_transaction_receipt_by_hash(
            &mut self,
            msg: GetTransactionReceiptByHash,
            ctx: &mut Context<Self, Result<Option<TransactionReceipt>>>
        ) -> Result<Option<TransactionReceipt>>;

        pub fn handle_delete_block(
            &mut self,
            msg: DeleteBlock,
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

        pub fn handle_get_zone_checkpoint(
            &mut self,
            msg: GetZoneCheckpoint,
            ctx: &mut Context<Self, Result<Option<Vec<u8>>>>
        ) -> Result<Option<Vec<u8>>>;

        pub fn handle_update_zone_checkpoint(
            &mut self,
            msg: UpdateZoneCheckpoint,
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

        pub fn handle_get_system_approvals_bytes(
            &mut self,
            msg: GetSystemApprovalsBytes,
            ctx: &mut Context<Self, Result<Option<Vec<u8>>>>
        ) -> Result<Option<Vec<u8>>>;

        pub fn handle_put_system_approvals_bytes(
            &mut self,
            msg: PutSystemApprovalsBytes,
            ctx: &mut Context<Self, Result<()>>
        ) -> Result<()>;

        pub fn handle_get_final_configs_bytes(
            &mut self,
            msg: GetFinalConfigsBytes,
            ctx: &mut Context<Self, Result<Option<Vec<u8>>>>
        ) -> Result<Option<Vec<u8>>>;

        pub fn handle_put_final_configs_bytes(
            &mut self,
            msg: PutFinalConfigsBytes,
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

        pub fn handle_get_channel_view_bytes(
            &mut self,
            msg: GetChannelViewBytes,
            ctx: &mut Context<Self, Result<Option<Vec<u8>>>>
        ) -> Result<Option<Vec<u8>>>;

        pub fn handle_get_pending_deposit_events(
            &mut self,
            msg: GetPendingDepositEvents,
            ctx: &mut Context<Self, Result<Vec<PendingDepositEventRecord>>>
        ) -> Result<Vec<PendingDepositEventRecord>>;

        pub fn handle_apply_store_update(
            &mut self,
            msg: AtomicUpdate,
            ctx: &mut Context<Self, Result<StoreUpdateOutcome>>
        ) -> Result<StoreUpdateOutcome>;

        pub fn handle_get_final_snapshot(
            &mut self,
            msg: GetFinalSnapshot,
            ctx: &mut Context<Self, Result<Option<(V03State, BlockMeta)>>>
        ) -> Result<Option<(V03State, BlockMeta)>>;

        pub fn handle_dump_db(
            &mut self,
            msg: DumpDb,
            ctx: &mut Context<Self, Result<DbDump>>
        ) -> Result<DbDump>;

        pub fn handle_get_block_by_hash(
            &mut self,
            msg: GetBlockByHash,
            ctx: &mut Context<Self, Result<Option<u64>>>
        ) -> Result<Option<u64>>;

        pub fn handle_get_account_transactions(
            &mut self,
            msg: GetAccountTransactions,
            ctx: &mut Context<Self, Result<Option<Vec<LeeTransaction>>>>
        ) -> Result<Option<Vec<LeeTransaction>>>;

        pub fn handle_get_event_filter(
            &mut self,
            msg: GetEventFilter,
            ctx: &mut Context<Self, Result<EventFilter>>
        ) -> Result<EventFilter>;

        pub fn handle_checkpoint(
            &mut self,
            msg: Checkpoint,
            ctx: &mut Context<Self, Result<()>>,
        ) -> Result<()>;
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

impl Message<Replace<Self>> for MockStorageActor {
    type Reply = ReplaceReply<Self>;

    async fn handle(
        &mut self,
        Replace { mock }: Replace<Self>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let old_mock = std::mem::replace(self, mock);
        ReplaceReply { old_mock }
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

impl Message<GetTransactionReceiptByHash> for MockStorageActor {
    type Reply = Result<Option<TransactionReceipt>>;

    async fn handle(
        &mut self,
        msg: GetTransactionReceiptByHash,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_transaction_receipt_by_hash(msg, ctx)
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

impl Message<GetZoneCheckpoint> for MockStorageActor {
    type Reply = Result<Option<Vec<u8>>>;

    async fn handle(
        &mut self,
        msg: GetZoneCheckpoint,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_zone_checkpoint(msg, ctx)
    }
}

impl Message<UpdateZoneCheckpoint> for MockStorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        msg: UpdateZoneCheckpoint,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_update_zone_checkpoint(msg, ctx)
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

impl Message<GetSystemApprovalsBytes> for MockStorageActor {
    type Reply = Result<Option<Vec<u8>>>;

    async fn handle(
        &mut self,
        msg: GetSystemApprovalsBytes,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_system_approvals_bytes(msg, ctx)
    }
}

impl Message<PutSystemApprovalsBytes> for MockStorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        msg: PutSystemApprovalsBytes,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_put_system_approvals_bytes(msg, ctx)
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

impl Message<GetFinalConfigsBytes> for MockStorageActor {
    type Reply = Result<Option<Vec<u8>>>;

    async fn handle(
        &mut self,
        msg: GetFinalConfigsBytes,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_final_configs_bytes(msg, ctx)
    }
}

impl Message<PutFinalConfigsBytes> for MockStorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        msg: PutFinalConfigsBytes,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_put_final_configs_bytes(msg, ctx)
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

impl Message<GetChannelViewBytes> for MockStorageActor {
    type Reply = Result<Option<Vec<u8>>>;

    async fn handle(
        &mut self,
        msg: GetChannelViewBytes,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_channel_view_bytes(msg, ctx)
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

impl Message<AtomicUpdate> for MockStorageActor {
    type Reply = Result<StoreUpdateOutcome>;

    async fn handle(
        &mut self,
        msg: AtomicUpdate,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_apply_store_update(msg, ctx)
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

impl Message<GetBlockByHash> for MockStorageActor {
    type Reply = Result<Option<u64>>;

    async fn handle(
        &mut self,
        msg: GetBlockByHash,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_block_by_hash(msg, ctx)
    }
}

impl Message<GetAccountTransactions> for MockStorageActor {
    type Reply = Result<Option<Vec<LeeTransaction>>>;

    async fn handle(
        &mut self,
        msg: GetAccountTransactions,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_account_transactions(msg, ctx)
    }
}

impl Message<GetEventFilter> for MockStorageActor {
    type Reply = Result<EventFilter>;

    async fn handle(
        &mut self,
        msg: GetEventFilter,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.handle_get_event_filter(msg, ctx)
    }
}

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
