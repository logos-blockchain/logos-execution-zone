use std::path::Path;

use common::{
    block::{Block, BlockMeta, PeerChainTip},
    transaction::LeeTransaction,
};
use itertools::Itertools as _;
use kameo::{
    Actor,
    actor::{ActorRef, WeakActorRef},
    error::ActorStopReason,
    message::{Context, Message},
};
use lee::V03State;
use lee_core::BlockId;
use log::debug;
use storage::sequencer::RocksDBIO;

use crate::{
    Result, StorageActorTrait,
    actor::tx_index::TransactionIndex,
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

mod tx_index;

pub struct StorageActor {
    /// `None` after [`Actor::on_stop`] closed the database.
    dbio: Option<RocksDBIO>,
    tx_index: TransactionIndex,
}

impl StorageActor {
    /// Creates a new `StorageActor` with a database at `location`.
    /// If the database does not exist, it will be created.
    pub fn new(location: &Path) -> Result<Self> {
        let dbio = RocksDBIO::open_or_create(location)?;
        Self::new_inner(dbio)
    }

    /// Creates a fresh database at `location` from `dump`.
    pub fn restore_from_dump(location: &Path, dump: &DbDump) -> Result<Self> {
        let dbio = RocksDBIO::restore_from_dump(location, dump.as_db_dump())?;
        Self::new_inner(dbio)
    }

    fn new_inner(dbio: RocksDBIO) -> Result<Self> {
        Ok(Self {
            tx_index: Self::build_tx_index(&dbio)?,
            dbio: Some(dbio),
        })
    }

    /// The open database.
    ///
    /// # Panics
    ///
    /// If called after the actor has stopped, which can't happen for message handlers as kameo
    /// stops delivering messages before [`Actor::on_stop`].
    const fn dbio(&self) -> &RocksDBIO {
        self.dbio
            .as_ref()
            .expect("Database is closed, the actor has already stopped")
    }

    fn build_tx_index(dbio: &RocksDBIO) -> Result<TransactionIndex> {
        debug!("Building the transaction index");

        let index =
            dbio.get_all_blocks()
                .fold_ok(TransactionIndex::default(), |mut index, block| {
                    index.update_from_block(&block);
                    index
                })?;

        debug!(
            "Transaction index built, holding {} transactions",
            index.transaction_count()
        );

        Ok(index)
    }
}

impl StorageActorTrait for StorageActor {}

impl Actor for StorageActor {
    type Args = Self;
    type Error = Error;

    async fn on_start(args: Self::Args, _actor_ref: ActorRef<Self>) -> Result<Self> {
        Ok(args)
    }

    /// Closes the database, releasing the rocksdb lock on its directory.
    async fn on_stop(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        _reason: ActorStopReason,
    ) -> Result<()> {
        drop(self.dbio.take());
        Ok(())
    }
}

impl Message<RecordNewBlock> for StorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        RecordNewBlock {
            block,
            withdrawals,
            state,
            checkpoint_bytes,
        }: RecordNewBlock,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let withdrawals = withdrawals.into_iter().map(Into::into).collect::<Vec<_>>();
        self.dbio()
            .atomic_update(&block, &withdrawals, &state, checkpoint_bytes.as_deref())?;

        self.tx_index.update_from_block(&block);
        Ok(())
    }
}

impl Message<GetBlock> for StorageActor {
    type Reply = Result<Option<Block>>;

    async fn handle(
        &mut self,
        GetBlock { block_id }: GetBlock,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio().get_block(block_id).map_err(Into::into)
    }
}

impl Message<GetAllBlocks> for StorageActor {
    type Reply = Result<Vec<Block>>;

    async fn handle(
        &mut self,
        GetAllBlocks: GetAllBlocks,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio()
            .get_all_blocks()
            .collect::<storage::DbResult<Vec<_>>>()
            .map_err(Into::into)
    }
}

impl Message<GetTransactionByHash> for StorageActor {
    type Reply = Result<Option<(LeeTransaction, BlockId)>>;

    async fn handle(
        &mut self,
        GetTransactionByHash { hash }: GetTransactionByHash,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let Some(block_id) = self.tx_index.block_for_tx(&hash) else {
            return Ok(None);
        };
        let Some(block) = self.dbio().get_block(block_id)? else {
            return Ok(None);
        };

        Ok(block
            .body
            .transactions
            .into_iter()
            .find(|transaction| transaction.hash() == hash)
            .map(|transaction| (transaction, block_id)))
    }
}

impl Message<DeleteBlock> for StorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        DeleteBlock { block_id }: DeleteBlock,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio().delete_block(block_id)?;
        self.tx_index.delete_block(block_id);
        Ok(())
    }
}

impl Message<MarkBlockAsFinalized> for StorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        MarkBlockAsFinalized { block_id }: MarkBlockAsFinalized,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio()
            .mark_block_as_finalized(block_id)
            .map_err(Into::into)
    }
}

impl Message<ResetAllBlocksToPending> for StorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        ResetAllBlocksToPending: ResetAllBlocksToPending,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio()
            .reset_all_blocks_to_pending()
            .map_err(Into::into)
    }
}

impl Message<GetFirstBlockId> for StorageActor {
    type Reply = Result<Option<BlockId>>;

    async fn handle(
        &mut self,
        GetFirstBlockId: GetFirstBlockId,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio().get_meta_first_block_in_db().map_err(Into::into)
    }
}

impl Message<GetLastBlockId> for StorageActor {
    type Reply = Result<Option<BlockId>>;

    async fn handle(
        &mut self,
        GetLastBlockId: GetLastBlockId,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio().get_meta_last_block_in_db().map_err(Into::into)
    }
}

impl Message<GetLatestBlockMeta> for StorageActor {
    type Reply = Result<Option<BlockMeta>>;

    async fn handle(
        &mut self,
        GetLatestBlockMeta: GetLatestBlockMeta,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio().latest_block_meta().map_err(Into::into)
    }
}

impl Message<GetLeeState> for StorageActor {
    type Reply = Result<Option<V03State>>;

    async fn handle(
        &mut self,
        GetLeeState: GetLeeState,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio().get_lee_state().map_err(Into::into)
    }
}

impl Message<GetZoneCheckpointBytes> for StorageActor {
    type Reply = Result<Option<Vec<u8>>>;

    async fn handle(
        &mut self,
        GetZoneCheckpointBytes: GetZoneCheckpointBytes,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio()
            .get_zone_sdk_checkpoint_bytes()
            .map_err(Into::into)
    }
}

impl Message<SetZoneCheckpointBytes> for StorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        SetZoneCheckpointBytes { bytes }: SetZoneCheckpointBytes,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio()
            .put_zone_sdk_checkpoint_bytes(&bytes)
            .map_err(Into::into)
    }
}

impl Message<GetSlashRecordBytes> for StorageActor {
    type Reply = Result<Option<Vec<u8>>>;

    async fn handle(
        &mut self,
        GetSlashRecordBytes: GetSlashRecordBytes,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio().get_slash_record_bytes().map_err(Into::into)
    }
}

impl Message<PutSlashRecordBytes> for StorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        PutSlashRecordBytes { bytes }: PutSlashRecordBytes,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio().put_slash_record_bytes(&bytes).map_err(Into::into)
    }
}

impl Message<DeleteZoneCheckpoint> for StorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        DeleteZoneCheckpoint: DeleteZoneCheckpoint,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio()
            .delete_zone_sdk_checkpoint_bytes()
            .map_err(Into::into)
    }
}

impl Message<GetZoneAnchor> for StorageActor {
    type Reply = Result<Option<ZoneAnchorRecord>>;

    async fn handle(
        &mut self,
        GetZoneAnchor: GetZoneAnchor,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio()
            .get_zone_anchor()
            .map(|anchor| anchor.map(Into::into))
            .map_err(Into::into)
    }
}

impl Message<SetZoneAnchor> for StorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        SetZoneAnchor { anchor }: SetZoneAnchor,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio()
            .put_zone_anchor(&anchor.into())
            .map_err(Into::into)
    }
}

impl Message<GetPublishedHighWater> for StorageActor {
    type Reply = Result<Option<BlockId>>;

    async fn handle(
        &mut self,
        GetPublishedHighWater: GetPublishedHighWater,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio().published_high_water().map_err(Into::into)
    }
}

impl Message<RaisePublishedHighWater> for StorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        RaisePublishedHighWater { block_id }: RaisePublishedHighWater,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio()
            .raise_published_high_water(block_id)
            .map_err(Into::into)
    }
}

impl Message<GetPendingDepositEvents> for StorageActor {
    type Reply = Result<Vec<PendingDepositEventRecord>>;

    async fn handle(
        &mut self,
        GetPendingDepositEvents: GetPendingDepositEvents,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio()
            .get_pending_deposit_events()
            .map(|events| events.into_iter().map(Into::into).collect())
            .map_err(Into::into)
    }
}

impl Message<DumpDb> for StorageActor {
    type Reply = Result<DbDump>;

    async fn handle(
        &mut self,
        DumpDb: DumpDb,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio().dump_all().map(Into::into).map_err(Into::into)
    }
}

impl Message<ApplyStoreUpdate> for StorageActor {
    type Reply = Result<StoreUpdateOutcome>;

    async fn handle(
        &mut self,
        msg: ApplyStoreUpdate,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let ApplyStoreUpdate {
            checkpoint,
            blocks,
            head_tip,
            head_state,
            final_snapshot,
            finalized_up_to,
            new_deposit_events,
            remove_deposit_records,
            remove_dispatch_records,
            consumed_withdrawals,
            new_withdraw_intents,
            zone_anchor,
            lower_published_high_water,
        } = msg;

        let blocks = blocks
            .iter()
            .map(|(block, finalized)| (block, *finalized))
            .collect::<Vec<_>>();
        let zone_anchor = zone_anchor.map(Into::into);
        let new_deposit_events = new_deposit_events
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>();
        let consumed_withdrawals = consumed_withdrawals
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>();
        let new_withdraw_intents = new_withdraw_intents
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>();

        let update = storage::sequencer::StoreUpdate {
            checkpoint: checkpoint.as_deref(),
            blocks: &blocks,
            head_tip: head_tip.as_ref(),
            head_state: &head_state,
            final_snapshot: final_snapshot
                .as_ref()
                .map(|(state, meta)| (state.as_ref(), meta)),
            finalized_up_to,
            new_deposit_events: &new_deposit_events,
            remove_deposit_records: &remove_deposit_records,
            remove_dispatch_records: &remove_dispatch_records,
            consumed_withdrawals: &consumed_withdrawals,
            new_withdraw_intents: &new_withdraw_intents,
            zone_anchor: zone_anchor.as_ref(),
            lower_published_high_water,
        };
        let outcome = self.dbio().store_update(&update)?;

        for (block, _) in blocks {
            self.tx_index.update_from_block(block);
        }
        Ok(outcome.into())
    }
}

impl Message<CleanPendingBlocksUpTo> for StorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        CleanPendingBlocksUpTo { last_finalized }: CleanPendingBlocksUpTo,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio()
            .clean_pending_blocks_up_to(last_finalized)
            .map_err(Into::into)
    }
}

impl Message<GetFinalSnapshot> for StorageActor {
    type Reply = Result<Option<(V03State, BlockMeta)>>;

    async fn handle(
        &mut self,
        GetFinalSnapshot: GetFinalSnapshot,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio().get_final_snapshot().map_err(Into::into)
    }
}

impl Message<AddPendingDepositEvent> for StorageActor {
    type Reply = Result<bool>;

    async fn handle(
        &mut self,
        AddPendingDepositEvent { event }: AddPendingDepositEvent,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio()
            .add_pending_deposit_event(event.into())
            .map_err(Into::into)
    }
}

impl Message<ConsumeUnseenWithdrawCount> for StorageActor {
    type Reply = Result<bool>;

    async fn handle(
        &mut self,
        ConsumeUnseenWithdrawCount { withdrawal }: ConsumeUnseenWithdrawCount,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio()
            .consume_unseen_withdraw_count(withdrawal.into())
            .map_err(Into::into)
    }
}

impl Message<GetPendingCrossZoneDispatches> for StorageActor {
    type Reply = Result<Vec<PendingCrossZoneDispatchRecord>>;

    async fn handle(
        &mut self,
        GetPendingCrossZoneDispatches: GetPendingCrossZoneDispatches,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio()
            .get_pending_cross_zone_dispatches()
            .map(|records| records.into_iter().map(Into::into).collect())
            .map_err(Into::into)
    }
}

impl Message<AddPendingCrossZoneDispatches> for StorageActor {
    type Reply = Result<usize>;

    async fn handle(
        &mut self,
        AddPendingCrossZoneDispatches { dispatches }: AddPendingCrossZoneDispatches,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let dispatches = dispatches.into_iter().map(Into::into).collect();
        self.dbio()
            .add_pending_cross_zone_dispatches(dispatches)
            .map_err(Into::into)
    }
}

impl Message<DropSettledCrossZoneDispatches> for StorageActor {
    type Reply = Result<usize>;

    async fn handle(
        &mut self,
        DropSettledCrossZoneDispatches { message_keys }: DropSettledCrossZoneDispatches,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio()
            .drop_settled_cross_zone_dispatches(&message_keys)
            .map_err(Into::into)
    }
}

impl Message<RecordDispatchFailure> for StorageActor {
    type Reply = Result<DispatchFailure>;

    async fn handle(
        &mut self,
        RecordDispatchFailure {
            message_key,
            retire_at,
            origin,
        }: RecordDispatchFailure,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio()
            .record_dispatch_failure(message_key, retire_at, origin.into())
            .map(Into::into)
            .map_err(Into::into)
    }
}

impl Message<GetDeadLetterDispatches> for StorageActor {
    type Reply = Result<Vec<DeadLetterDispatchRecord>>;

    async fn handle(
        &mut self,
        GetDeadLetterDispatches: GetDeadLetterDispatches,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio()
            .get_dead_letter_cross_zone_dispatches()
            .map(|records| records.into_iter().map(Into::into).collect())
            .map_err(Into::into)
    }
}

impl Message<GetDeadLetterDispatchCount> for StorageActor {
    type Reply = Result<u64>;

    async fn handle(
        &mut self,
        GetDeadLetterDispatchCount: GetDeadLetterDispatchCount,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio()
            .get_dead_letter_cross_zone_dispatch_count()
            .map_err(Into::into)
    }
}

impl Message<GetCrossZonePeerFloorBytes> for StorageActor {
    type Reply = Result<Option<Vec<u8>>>;

    async fn handle(
        &mut self,
        GetCrossZonePeerFloorBytes { peer_zone }: GetCrossZonePeerFloorBytes,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio()
            .get_cross_zone_peer_floor_bytes(peer_zone)
            .map_err(Into::into)
    }
}

impl Message<SetCrossZonePeerFloorBytes> for StorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        SetCrossZonePeerFloorBytes { peer_zone, bytes }: SetCrossZonePeerFloorBytes,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio()
            .put_cross_zone_peer_floor_bytes(peer_zone, &bytes)
            .map_err(Into::into)
    }
}

impl Message<DeleteCrossZonePeerFloor> for StorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        DeleteCrossZonePeerFloor { peer_zone }: DeleteCrossZonePeerFloor,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio()
            .delete_cross_zone_peer_floor(peer_zone)
            .map_err(Into::into)
    }
}

impl Message<GetCrossZonePeerTip> for StorageActor {
    type Reply = Result<Option<PeerChainTip>>;

    async fn handle(
        &mut self,
        GetCrossZonePeerTip { peer_zone }: GetCrossZonePeerTip,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio()
            .get_cross_zone_peer_tip(peer_zone)
            .map_err(Into::into)
    }
}

impl Message<SetCrossZonePeerTip> for StorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        SetCrossZonePeerTip { peer_zone, tip }: SetCrossZonePeerTip,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.dbio()
            .put_cross_zone_peer_tip(peer_zone, tip)
            .map_err(Into::into)
    }
}
