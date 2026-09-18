use std::{
    collections::{BTreeMap, HashSet},
    path::Path,
    sync::Arc,
};

use common::{
    HashType,
    block::{BedrockStatus, Block, BlockMeta, PeerChainTip},
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

use crate::{
    Result, StorageActorTrait,
    actor::tx_index::TransactionIndex,
    error::Error,
    protocol::{
        AddPendingCrossZoneDispatches, AtomicUpdate, DbDump, DeadLetterDispatch, DeadLetterRequeue,
        DeleteBlock, DeleteCrossZonePeerFloor, DeleteZoneCheckpoint, DispatchFailure,
        DropSettledCrossZoneDispatches, DumpDb, GetAllBlocks, GetBlock, GetChannelCursor,
        GetCrossZonePeerFloorBytes, GetCrossZonePeerTip, GetDeadLetterDispatchCount,
        GetDeadLetterDispatches, GetFinalSnapshot, GetFirstBlockId, GetLastBlockId,
        GetLatestBlockMeta, GetLeeState, GetPendingCrossZoneDispatches, GetPendingDepositEvents,
        GetPublishedHighWater, GetSlashRecordBytes, GetTransactionByHash, GetZoneAnchor,
        GetZoneCheckpointBytes, MsgId, PendingCrossZoneDispatchRecord, PendingDepositEventRecord,
        PutSlashRecordBytes, RaisePublishedHighWater, RecordDispatchFailure,
        RequeueDeadLetterDispatch, ResetAllBlocksToPending, SetCrossZonePeerFloorBytes,
        SetCrossZonePeerTip, SetZoneAnchor, SetZoneCheckpointBytes, StoreUpdateOutcome,
        WithdrawalReconciliationKey, ZoneAnchorRecord,
    },
};

mod conversions;
pub mod db;
mod encoding;
mod entities;
#[cfg(test)]
mod tests;
mod tx_index;

// TODO: Remove this hardcoding unrelated to the storage actor and make it configurable by
// the ExecutorActor (or CrossZoneRelayerActor in future).
const MAX_PENDING_CROSS_ZONE_DISPATCHES: usize = 4096;

pub struct StorageActor {
    /// `None` after [`Actor::on_stop`] closed the database.
    db: Option<db::Database<entities::ColumnFamily>>,
    tx_index: TransactionIndex,
}

struct UpdatedBlocks {
    written: BTreeMap<BlockId, entities::Block>,
    removed: Vec<BlockId>,
    /// Whether the stored chain moved.
    chain_moved: bool,
}

impl StorageActor {
    /// Creates a new `StorageActor` with a database at `location`.
    /// If the database does not exist, it will be created.
    pub fn new(location: &Path) -> Result<Self> {
        Self::new_inner(db::Database::new(location)?)
    }

    /// Creates a fresh database at `location` from `dump`.
    pub fn restore_from_dump(location: &Path, dump: &DbDump) -> Result<Self> {
        let dump = db::Dump::from_bytes(&dump.bytes)?;
        Self::new_inner(db::Database::restore(location, &dump)?)
    }

    fn new_inner(db: db::Database<entities::ColumnFamily>) -> Result<Self> {
        Ok(Self {
            tx_index: Self::build_tx_index(&db)?,
            db: Some(db),
        })
    }

    /// The open database.
    ///
    /// # Panics
    ///
    /// If called after the actor has stopped, which can't happen for message handlers as kameo
    /// stops delivering messages before [`Actor::on_stop`].
    const fn db(&self) -> &db::Database<entities::ColumnFamily> {
        self.db
            .as_ref()
            .expect("Database is closed, the actor has already stopped")
    }

    fn build_tx_index(db: &db::Database<entities::ColumnFamily>) -> Result<TransactionIndex> {
        debug!("Building the transaction index");

        let index = db
            .iter::<entities::Block>()
            .map_ok(|block| block.block)
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

    fn last_block(&self) -> Result<Option<Block>> {
        self.db()
            .iter::<entities::Block>()
            .map_ok(|block| block.block)
            .next_back()
            .transpose()
            .map_err(Into::into)
    }

    fn update_blocks(
        &self,
        batch: &mut db::WriteBatch,
        new_blocks: Vec<Block>,
        finalized_up_to: Option<BlockId>,
        head_tip: Option<BlockMeta>,
    ) -> Result<UpdatedBlocks> {
        let last_stored_block_id = self.last_block()?.map_or(0, |block| block.header.block_id);

        let (written, written_differs) =
            self.stage_new_blocks(batch, new_blocks, finalized_up_to)?;

        let tip_moved = head_tip
            .as_ref()
            .is_some_and(|tip| tip.id != last_stored_block_id);

        let highest_staged = written.last_key_value().map_or(0, |(id, _)| *id);
        let highest_block_id = last_stored_block_id.max(highest_staged);
        let removed = self.delete_stale_blocks(batch, highest_block_id, head_tip);

        Ok(UpdatedBlocks {
            chain_moved: written_differs || tip_moved || !removed.is_empty(),
            written,
            removed,
        })
    }

    /// Stages every block this update writes, reporting whether any of them
    /// differs from the payload the store already holds.
    fn stage_new_blocks(
        &self,
        batch: &mut db::WriteBatch,
        new_blocks: Vec<Block>,
        finalized_up_to: Option<BlockId>,
    ) -> Result<(BTreeMap<BlockId, entities::Block>, bool)> {
        let mut to_write: BTreeMap<BlockId, entities::Block> = new_blocks
            .into_iter()
            .map(|block| (block.header.block_id, entities::Block { block }))
            .collect();

        if let Some(last_finalized) = finalized_up_to {
            for (_, block) in to_write.range_mut(..=last_finalized) {
                block.block.bedrock_status = BedrockStatus::Finalized;
            }

            self.db()
                .iter::<entities::Block>()
                .map_ok(|block| block.block)
                .filter_ok(|block| {
                    block.header.block_id <= last_finalized
                        && matches!(block.bedrock_status, BedrockStatus::Pending)
                })
                .try_for_each(|block| {
                    let mut block = block?;
                    block.bedrock_status = BedrockStatus::Finalized;
                    to_write
                        .entry(block.header.block_id)
                        .or_insert(entities::Block { block });
                    Result::Ok(())
                })?;
        }

        // Finality is irreversible, so a block the store already holds as
        // finalized keeps that status when a later update writes it again. Only
        // the same block: a competing one at that id is a different block, and
        // inherits nothing from the one it replaces.
        let mut differs_from_stored = false;
        for (block_id, block) in &mut to_write {
            match self
                .db()
                .get::<entities::Block>(&encoding::BigEndian::new(block_id))?
            {
                Some(stored) if stored.block.header.hash == block.block.header.hash => {
                    if matches!(stored.block.bedrock_status, BedrockStatus::Finalized) {
                        block.block.bedrock_status = BedrockStatus::Finalized;
                    }
                }
                _ => differs_from_stored = true,
            }
        }

        for (block_id, block) in &to_write {
            self.db()
                .put_batch(batch, &encoding::BigEndian::new(block_id), block)?;
        }

        Ok((to_write, differs_from_stored))
    }

    fn delete_stale_blocks(
        &self,
        batch: &mut db::WriteBatch,
        highest_block_id: BlockId,
        head_tip: Option<BlockMeta>,
    ) -> Vec<BlockId> {
        let mut removed_block_ids = Vec::new();
        if let Some(head_tip) = head_tip {
            for stale_id in head_tip.id.saturating_add(1)..=highest_block_id {
                self.db()
                    .delete_batch::<entities::Block>(batch, &encoding::BigEndian::new(&stale_id));
                removed_block_ids.push(stale_id);
            }
        }

        removed_block_ids
    }

    /// Stages the published high water mark down to `block_id`, leaving a mark
    /// already at or below it alone.
    fn lower_published_high_water(
        &self,
        batch: &mut db::WriteBatch,
        block_id: BlockId,
    ) -> Result<()> {
        let stored = self
            .db()
            .get::<entities::PublishedHighWater>(&encoding::SingletonKey)?;

        if stored.is_none_or(|stored| stored.block_id <= block_id) {
            return Ok(());
        }

        self.db()
            .put_batch(
                batch,
                &encoding::SingletonKey,
                &entities::PublishedHighWater { block_id },
            )
            .map_err(Into::into)
    }

    /// Records the deposits `new_deposit_events` observes and drops the records
    /// of `finalized_deposit_records`, returning how many were newly recorded.
    fn update_pending_deposits(
        &self,
        batch: &mut db::WriteBatch,
        new_deposit_events: Vec<PendingDepositEventRecord>,
        finalized_deposit_records: &HashSet<HashType>,
    ) -> Result<usize> {
        #[expect(
            clippy::iter_over_hash_type,
            reason = "HashSet is more efficient and delete order doesn't matter"
        )]
        for finalized_deposit in finalized_deposit_records {
            self.db()
                .delete_batch::<entities::PendingDeposit>(batch, finalized_deposit);
        }

        let mut accepted_deposits_count = 0_usize;
        for deposit in new_deposit_events
            .into_iter()
            .unique_by(|event| event.deposit_op_id)
            .filter(|event| !finalized_deposit_records.contains(&event.deposit_op_id))
        {
            if self
                .db()
                .get::<entities::PendingDeposit>(&deposit.deposit_op_id)?
                .is_some()
            {
                continue;
            }

            let deposit_op_id = deposit.deposit_op_id;
            self.db().put_batch(
                batch,
                &deposit_op_id,
                &entities::PendingDeposit::from(deposit),
            )?;
            accepted_deposits_count = accepted_deposits_count.saturating_add(1);
        }

        Ok(accepted_deposits_count)
    }

    /// Raises the intents `new_withdrawals` publishes and settles the ones
    /// `consumed_withdrawals` reports, returning the reported withdrawals this
    /// node holds no intent for.
    fn update_pending_withdrawals(
        &self,
        batch: &mut db::WriteBatch,
        new_withdrawals: HashSet<WithdrawalReconciliationKey>,
        consumed_withdrawals: &HashSet<WithdrawalReconciliationKey>,
    ) -> Result<Vec<WithdrawalReconciliationKey>> {
        let mut unmatched_withdrawals = Vec::new();

        #[expect(
            clippy::iter_over_hash_type,
            reason = "HashSet is more efficient and delete order doesn't matter"
        )]
        for consumed in consumed_withdrawals {
            let key = entities::WithdrawalReconciliationKey::from(*consumed);
            let matched = new_withdrawals.contains(consumed)
                || self
                    .db()
                    .get::<entities::PendingWithdrawal>(&key)?
                    .is_some();

            if matched {
                self.db()
                    .delete_batch::<entities::PendingWithdrawal>(batch, &key);
            } else {
                unmatched_withdrawals.push(*consumed);
            }
        }

        for new_withdrawal in new_withdrawals
            .into_iter()
            .filter(|withdrawal| !consumed_withdrawals.contains(withdrawal))
        {
            self.db().put_batch(
                batch,
                &entities::WithdrawalReconciliationKey::from(new_withdrawal),
                &entities::PendingWithdrawal,
            )?;
        }

        Ok(unmatched_withdrawals)
    }

    /// Drops the records of the deliveries `settled_dispatches` reports as
    /// settled for good.
    fn stage_settled_dispatches(
        &self,
        batch: &mut db::WriteBatch,
        settled_dispatches: impl IntoIterator<Item = entities::CrossZoneMessageKey>,
    ) -> Result<()> {
        let mut dead_letters = self
            .db()
            .get::<entities::DeadLetterDispatches>(&encoding::SingletonKey)?;
        let mut reconciled = false;

        for key in settled_dispatches.into_iter().unique() {
            // A point read before the delete so a key naming no record stages
            // nothing, keeping an update that settles nothing out of the batch.
            if self
                .db()
                .get::<entities::PendingCrossZoneDispatch>(&key)?
                .is_some()
            {
                self.db()
                    .delete_batch::<entities::PendingCrossZoneDispatch>(batch, &key);
            }

            if let Some(dead_letters) = dead_letters.as_mut()
                && dead_letters.remove(&key).is_some()
            {
                reconciled = true;
            }
        }

        if let Some(dead_letters) = dead_letters
            && reconciled
        {
            self.db()
                .put_batch(batch, &encoding::SingletonKey, &dead_letters)?;
        }

        Ok(())
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
        let Self { db, tx_index: _ } = self;

        drop(db.take());

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
        Ok(self
            .db()
            .get::<entities::Block>(&encoding::BigEndian::new(&block_id))?
            .map(|block| block.block))
    }
}

impl Message<GetAllBlocks> for StorageActor {
    type Reply = Result<Vec<Block>>;

    async fn handle(
        &mut self,
        GetAllBlocks: GetAllBlocks,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.db()
            .iter::<entities::Block>()
            .map_ok(|block| block.block)
            .collect::<db::Result<_>>()
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
        let Some(block) = self
            .db()
            .get::<entities::Block>(&encoding::BigEndian::new(&block_id))?
        else {
            return Ok(None);
        };

        Ok(block
            .block
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
        self.db()
            .delete::<entities::Block>(&encoding::BigEndian::new(&block_id))?;
        self.tx_index.delete_block(block_id);
        Ok(())
    }
}

impl Message<ResetAllBlocksToPending> for StorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        ResetAllBlocksToPending: ResetAllBlocksToPending,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let mut batch = db::WriteBatch::default();

        let blocks_to_reset = self
            .db()
            .iter::<entities::Block>()
            .map_ok(|block| block.block)
            .filter_ok(|block| !matches!(block.bedrock_status, BedrockStatus::Pending));

        for block in blocks_to_reset {
            let mut block = block?;
            block.bedrock_status = BedrockStatus::Pending;
            self.db().put_batch(
                &mut batch,
                &encoding::BigEndian::new(&block.header.block_id),
                &entities::Block { block },
            )?;
        }

        self.db().write(batch)?;

        Ok(())
    }
}

impl Message<GetFirstBlockId> for StorageActor {
    type Reply = Result<Option<BlockId>>;

    async fn handle(
        &mut self,
        GetFirstBlockId: GetFirstBlockId,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self
            .db()
            .iter::<entities::Block>()
            .next()
            .transpose()?
            .map(|block| block.block.header.block_id))
    }
}

impl Message<GetLastBlockId> for StorageActor {
    type Reply = Result<Option<BlockId>>;

    async fn handle(
        &mut self,
        GetLastBlockId: GetLastBlockId,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self.last_block()?.map(|block| block.header.block_id))
    }
}

impl Message<GetLatestBlockMeta> for StorageActor {
    type Reply = Result<Option<BlockMeta>>;

    async fn handle(
        &mut self,
        GetLatestBlockMeta: GetLatestBlockMeta,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self.last_block()?.map(|block| BlockMeta::from(&block)))
    }
}

impl Message<GetLeeState> for StorageActor {
    type Reply = Result<Option<V03State>>;

    async fn handle(
        &mut self,
        GetLeeState: GetLeeState,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self
            .db()
            .get::<entities::LeeState>(&encoding::SingletonKey)?
            .map(|state| {
                Arc::into_inner(state.state.0).expect("This is the only strong reference")
            }))
    }
}

impl Message<GetZoneCheckpointBytes> for StorageActor {
    type Reply = Result<Option<Vec<u8>>>;

    async fn handle(
        &mut self,
        GetZoneCheckpointBytes: GetZoneCheckpointBytes,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self
            .db()
            .get::<entities::ZoneCheckpoint>(&encoding::SingletonKey)?
            .map(|checkpoint| checkpoint.bytes))
    }
}

impl Message<SetZoneCheckpointBytes> for StorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        SetZoneCheckpointBytes { bytes }: SetZoneCheckpointBytes,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.db()
            .put(&encoding::SingletonKey, &entities::ZoneCheckpoint { bytes })
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
        Ok(self
            .db()
            .get::<entities::SlashRecord>(&encoding::SingletonKey)?
            .map(|record| record.bytes))
    }
}

impl Message<PutSlashRecordBytes> for StorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        PutSlashRecordBytes { bytes }: PutSlashRecordBytes,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.db()
            .put(&encoding::SingletonKey, &entities::SlashRecord { bytes })
            .map_err(Into::into)
    }
}

impl Message<DeleteZoneCheckpoint> for StorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        DeleteZoneCheckpoint: DeleteZoneCheckpoint,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.db()
            .delete::<entities::ZoneCheckpoint>(&encoding::SingletonKey)
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
        Ok(self
            .db()
            .get::<entities::ZoneAnchor>(&encoding::SingletonKey)?
            .map(Into::into))
    }
}

impl Message<SetZoneAnchor> for StorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        SetZoneAnchor { anchor }: SetZoneAnchor,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.db()
            .put(&encoding::SingletonKey, &entities::ZoneAnchor::from(anchor))
            .map_err(Into::into)
    }
}

impl Message<GetChannelCursor> for StorageActor {
    type Reply = Result<Option<MsgId>>;

    async fn handle(
        &mut self,
        GetChannelCursor: GetChannelCursor,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self
            .db()
            .get::<entities::ChannelCursor>(&encoding::SingletonKey)?
            .map(|cursor| cursor.msg_id))
    }
}

impl Message<GetPublishedHighWater> for StorageActor {
    type Reply = Result<Option<BlockId>>;

    async fn handle(
        &mut self,
        GetPublishedHighWater: GetPublishedHighWater,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self
            .db()
            .get::<entities::PublishedHighWater>(&encoding::SingletonKey)?
            .map(|high_water| high_water.block_id))
    }
}

impl Message<RaisePublishedHighWater> for StorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        RaisePublishedHighWater { block_id }: RaisePublishedHighWater,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let stored = self
            .db()
            .get::<entities::PublishedHighWater>(&encoding::SingletonKey)?;

        if stored.is_some_and(|stored| stored.block_id >= block_id) {
            return Ok(());
        }

        self.db().put(
            &encoding::SingletonKey,
            &entities::PublishedHighWater { block_id },
        )?;

        Ok(())
    }
}

impl Message<GetPendingDepositEvents> for StorageActor {
    type Reply = Result<Vec<PendingDepositEventRecord>>;

    async fn handle(
        &mut self,
        GetPendingDepositEvents: GetPendingDepositEvents,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.db()
            .iter::<entities::PendingDeposit>()
            .map_ok(Into::into)
            .collect::<db::Result<_>>()
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
        Ok(DbDump {
            bytes: self.db().dump()?.to_bytes()?,
        })
    }
}

impl Message<AtomicUpdate> for StorageActor {
    type Reply = Result<StoreUpdateOutcome>;

    async fn handle(
        &mut self,
        msg: AtomicUpdate,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let AtomicUpdate {
            checkpoint,
            blocks,
            channel_cursor,
            head_tip,
            head_state,
            final_snapshot,
            finalized_up_to,
            new_deposit_events,
            finalized_deposit_records,
            consumed_withdrawals,
            new_withdraw_intents,
            finalized_dispatch_records,
            zone_anchor,
            lower_published_high_water,
        } = msg;

        let mut batch = db::WriteBatch::default();

        // Channel cursor
        if let Some(msg_id) = channel_cursor {
            self.db().put_batch(
                &mut batch,
                &encoding::SingletonKey,
                &entities::ChannelCursor { msg_id },
            )?;
        }

        // Published high water
        if let Some(block_id) = lower_published_high_water {
            self.lower_published_high_water(&mut batch, block_id)?;
        }

        // Checkpoint
        if let Some(checkpoint) = checkpoint {
            self.db().put_batch(
                &mut batch,
                &encoding::SingletonKey,
                &entities::ZoneCheckpoint { bytes: checkpoint },
            )?;
        }

        // Zone anchor
        if let Some(zone_anchor) = zone_anchor {
            self.db().put_batch(
                &mut batch,
                &encoding::SingletonKey,
                &entities::ZoneAnchor::from(zone_anchor),
            )?;
        }

        // Blocks
        let updated_blocks = self.update_blocks(&mut batch, blocks, finalized_up_to, head_tip)?;

        // Deposits
        let accepted_deposits_count = self.update_pending_deposits(
            &mut batch,
            new_deposit_events,
            &finalized_deposit_records,
        )?;

        // Withdrawals
        let unmatched_withdrawals = self.update_pending_withdrawals(
            &mut batch,
            new_withdraw_intents,
            &consumed_withdrawals,
        )?;

        // Cross-zone dispatches
        self.stage_settled_dispatches(&mut batch, finalized_dispatch_records)?;

        // State
        if updated_blocks.chain_moved || final_snapshot.is_some() {
            self.db().put_batch(
                &mut batch,
                &encoding::SingletonKey,
                &entities::LeeState {
                    state: encoding::BorshArc(head_state),
                },
            )?;
        }

        // Snapshot
        if let Some((final_state, final_meta)) = final_snapshot {
            self.db().put_batch(
                &mut batch,
                &encoding::SingletonKey,
                &entities::FinalSnapshot {
                    state: encoding::BorshArc(final_state),
                    meta: final_meta,
                },
            )?;
        }

        self.db().write(batch)?;

        // Index is updated after the database write, so that if it fails, the store is still
        // consistent.
        for block in updated_blocks.written.values() {
            self.tx_index.update_from_block(&block.block);
        }
        for block_id in updated_blocks.removed {
            self.tx_index.delete_block(block_id);
        }

        Ok(StoreUpdateOutcome {
            accepted_deposits: accepted_deposits_count,
            unmatched_withdrawals,
        })
    }
}

impl Message<GetFinalSnapshot> for StorageActor {
    type Reply = Result<Option<(V03State, BlockMeta)>>;

    async fn handle(
        &mut self,
        GetFinalSnapshot: GetFinalSnapshot,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self
            .db()
            .get::<entities::FinalSnapshot>(&encoding::SingletonKey)?
            .map(|snapshot| {
                let state =
                    Arc::into_inner(snapshot.state.0).expect("This is the only strong reference");
                (state, snapshot.meta)
            }))
    }
}

impl Message<GetPendingCrossZoneDispatches> for StorageActor {
    type Reply = Result<Vec<PendingCrossZoneDispatchRecord>>;

    async fn handle(
        &mut self,
        GetPendingCrossZoneDispatches: GetPendingCrossZoneDispatches,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.db()
            .iter::<entities::PendingCrossZoneDispatch>()
            .map_ok(|dispatch| PendingCrossZoneDispatchRecord {
                message_key: dispatch.message_key,
                transaction: dispatch.transaction,
                failed_attempts: dispatch.failed_attempts,
            })
            .collect::<db::Result<_>>()
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
        if dispatches.is_empty() {
            return Ok(0);
        }

        let mut deduped_dispatches = Vec::new();
        for dispatch in dispatches
            .into_iter()
            .unique_by(|dispatch| dispatch.message_key)
        {
            if self
                .db()
                .get::<entities::PendingCrossZoneDispatch>(&dispatch.message_key)?
                .is_none()
            {
                deduped_dispatches.push(dispatch);
            }
        }

        let accepted = deduped_dispatches.len();
        if accepted == 0 {
            return Ok(0);
        }

        let pending = self.db().count::<entities::PendingCrossZoneDispatch>();
        if pending.saturating_add(accepted) > MAX_PENDING_CROSS_ZONE_DISPATCHES {
            return Err(Error::TooManyPendingCrossZoneDispatches {
                max: MAX_PENDING_CROSS_ZONE_DISPATCHES,
            });
        }

        let mut batch = db::WriteBatch::default();
        for dispatch in deduped_dispatches {
            self.db().put_batch(
                &mut batch,
                &dispatch.message_key,
                &entities::PendingCrossZoneDispatch {
                    message_key: dispatch.message_key,
                    transaction: dispatch.transaction,
                    failed_attempts: dispatch.failed_attempts,
                },
            )?;
        }
        self.db().write(batch)?;

        Ok(accepted)
    }
}

impl Message<DropSettledCrossZoneDispatches> for StorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        DropSettledCrossZoneDispatches { message_keys }: DropSettledCrossZoneDispatches,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let mut batch = db::WriteBatch::default();
        self.stage_settled_dispatches(&mut batch, message_keys)?;
        self.db().write(batch)?;

        Ok(())
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
        let Some(mut pending) = self
            .db()
            .get::<entities::PendingCrossZoneDispatch>(&message_key)?
        else {
            return Ok(DispatchFailure::Absent);
        };

        pending.failed_attempts = pending.failed_attempts.saturating_add(1);
        let failed_attempts = pending.failed_attempts;
        if failed_attempts < retire_at {
            self.db().put(&message_key, &pending)?;
            return Ok(DispatchFailure::Retried { failed_attempts });
        }

        let dead_letter = entities::DeadLetterDispatch::retiring(
            message_key,
            origin.into(),
            failed_attempts,
            pending.transaction,
        );
        let mut dead_letters = self
            .db()
            .get::<entities::DeadLetterDispatches>(&encoding::SingletonKey)?
            .unwrap_or_default();
        dead_letters.push(dead_letter.clone());

        let mut batch = db::WriteBatch::default();
        self.db()
            .delete_batch::<entities::PendingCrossZoneDispatch>(&mut batch, &message_key);
        self.db()
            .put_batch(&mut batch, &encoding::SingletonKey, &dead_letters)?;
        self.db().write(batch)?;

        Ok(DispatchFailure::Retired(Box::new(dead_letter.into())))
    }
}

impl Message<RequeueDeadLetterDispatch> for StorageActor {
    type Reply = Result<DeadLetterRequeue>;

    async fn handle(
        &mut self,
        RequeueDeadLetterDispatch { message_key }: RequeueDeadLetterDispatch,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let mut dead_letters = self
            .db()
            .get::<entities::DeadLetterDispatches>(&encoding::SingletonKey)?
            .unwrap_or_default();

        let Some(dead_letter) = dead_letters.remove(&message_key) else {
            return Ok(DeadLetterRequeue::NotFound);
        };
        let Some(transaction) = dead_letter.transaction else {
            return Ok(DeadLetterRequeue::NotRetained);
        };

        let already_pending = self
            .db()
            .get::<entities::PendingCrossZoneDispatch>(&message_key)?
            .is_some();

        let mut batch = db::WriteBatch::default();
        self.db()
            .put_batch(&mut batch, &encoding::SingletonKey, &dead_letters)?;

        if already_pending {
            self.db().write(batch)?;
            return Ok(DeadLetterRequeue::AlreadyPending);
        }

        if self
            .db()
            .count::<entities::PendingCrossZoneDispatch>()
            .saturating_add(1)
            > MAX_PENDING_CROSS_ZONE_DISPATCHES
        {
            return Err(Error::TooManyPendingCrossZoneDispatches {
                max: MAX_PENDING_CROSS_ZONE_DISPATCHES,
            });
        }

        self.db().put_batch(
            &mut batch,
            &message_key,
            &entities::PendingCrossZoneDispatch {
                message_key,
                transaction,
                failed_attempts: 0,
            },
        )?;
        self.db().write(batch)?;

        Ok(DeadLetterRequeue::Requeued)
    }
}

impl Message<GetDeadLetterDispatches> for StorageActor {
    type Reply = Result<Vec<DeadLetterDispatch>>;

    async fn handle(
        &mut self,
        GetDeadLetterDispatches: GetDeadLetterDispatches,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self
            .db()
            .get::<entities::DeadLetterDispatches>(&encoding::SingletonKey)?
            .into_iter()
            .flat_map(|dispatches| dispatches.records.into_iter())
            .map(Into::into)
            .collect())
    }
}

impl Message<GetDeadLetterDispatchCount> for StorageActor {
    type Reply = Result<u64>;

    async fn handle(
        &mut self,
        GetDeadLetterDispatchCount: GetDeadLetterDispatchCount,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self
            .db()
            .get::<entities::DeadLetterDispatches>(&encoding::SingletonKey)?
            .map_or(0, |dispatches| dispatches.total))
    }
}

impl Message<GetCrossZonePeerFloorBytes> for StorageActor {
    type Reply = Result<Option<Vec<u8>>>;

    async fn handle(
        &mut self,
        GetCrossZonePeerFloorBytes { peer_zone }: GetCrossZonePeerFloorBytes,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self
            .db()
            .get::<entities::CrossZonePeerFloor>(&peer_zone)?
            .map(|floor| floor.bytes))
    }
}

impl Message<SetCrossZonePeerFloorBytes> for StorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        SetCrossZonePeerFloorBytes { peer_zone, bytes }: SetCrossZonePeerFloorBytes,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.db()
            .put(&peer_zone, &entities::CrossZonePeerFloor { bytes })
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
        self.db()
            .delete::<entities::CrossZonePeerFloor>(&peer_zone)
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
        Ok(self
            .db()
            .get::<entities::CrossZonePeerTip>(&peer_zone)?
            .map(|peer| peer.tip))
    }
}

impl Message<SetCrossZonePeerTip> for StorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        SetCrossZonePeerTip { peer_zone, tip }: SetCrossZonePeerTip,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.db()
            .put(&peer_zone, &entities::CrossZonePeerTip { tip })
            .map_err(Into::into)
    }
}
