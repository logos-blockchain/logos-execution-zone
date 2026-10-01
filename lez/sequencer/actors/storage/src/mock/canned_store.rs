//! A [`MockStorageActor`] serving a canned store.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, MutexGuard},
};

use common::block::{Block, BlockMeta};
use lee::V03State;
use lee_core::BlockId;

use super::MockStorageActor;
use crate::protocol::{
    AtomicUpdate, DropSettledCrossZoneDispatches, GetBlock, MsgId, PendingCrossZoneDispatchRecord,
    PendingDepositEventRecord, RaisePublishedHighWater, SetZoneAnchor, SetZoneCheckpointBytes,
    StoreUpdateOutcome, ZoneAnchorRecord,
};

/// What a mocked store holds.
#[derive(Clone, Default)]
pub struct CannedStore {
    pub blocks: BTreeMap<BlockId, Block>,
    /// State after the last stored block.
    pub head_state: Option<V03State>,
    /// The irreversible tier; `None` until something finalizes.
    pub final_snapshot: Option<(V03State, BlockMeta)>,
    pub anchor: Option<ZoneAnchorRecord>,
    pub checkpoint: Option<Vec<u8>>,
    pub channel_cursor: Option<MsgId>,
    pub published_high_water: Option<BlockId>,
    pub pending_deposits: Vec<PendingDepositEventRecord>,
    pub pending_dispatches: Vec<PendingCrossZoneDispatchRecord>,
}

impl CannedStore {
    #[must_use]
    pub fn share(self) -> SharedStore {
        SharedStore(Arc::new(Mutex::new(self)))
    }

    /// Applies `update` the way the store persists it.
    pub fn apply(&mut self, update: AtomicUpdate) {
        for block in update.blocks {
            self.blocks.insert(block.header.block_id, block);
        }
        if let Some(head_tip) = update.head_tip {
            self.blocks.retain(|block_id, _| *block_id <= head_tip.id);
        }
        self.head_state = Some(V03State::clone(&update.head_state));
        if let Some((state, meta)) = update.final_snapshot {
            self.final_snapshot = Some((V03State::clone(&state), meta));
        }
        self.anchor = update.zone_anchor.or(self.anchor);
        if let Some(checkpoint) = update.checkpoint {
            self.checkpoint = Some(checkpoint);
        }
        self.channel_cursor = update.channel_cursor.or(self.channel_cursor);
        if let Some(block_id) = update.lower_published_high_water {
            self.published_high_water = self.published_high_water.map(|mark| mark.min(block_id));
        }
        for record in update.new_deposit_events {
            if !self.pending_deposits.contains(&record) {
                self.pending_deposits.push(record);
            }
        }
        self.pending_deposits.retain(|record| {
            !update
                .finalized_deposit_records
                .contains(&record.deposit_op_id)
        });
        self.pending_dispatches.retain(|record| {
            !update
                .finalized_dispatch_records
                .contains(&record.message_key)
        });
    }

    /// The last stored block.
    #[must_use]
    pub fn tip(&self) -> Option<BlockMeta> {
        self.blocks.values().next_back().map(BlockMeta::from)
    }
}

/// A [`CannedStore`] every mock built from it serves and writes to, so a test can inspect it and
/// keep it across restarts.
#[derive(Clone, Default)]
pub struct SharedStore(Arc<Mutex<CannedStore>>);

impl SharedStore {
    /// A mock serving every read of this store and applying every write to it.
    #[must_use]
    pub fn mock(&self) -> MockStorageActor {
        let mut mock = MockStorageActor::new();
        mock.expect_handle_get_final_snapshot().returning({
            let store = self.clone();
            move |_msg, _ctx| Ok(store.lock().final_snapshot.clone())
        });
        mock.expect_handle_get_all_blocks().returning({
            let store = self.clone();
            move |_msg, _ctx| Ok(store.blocks())
        });
        mock.expect_handle_get_block().returning({
            let store = self.clone();
            move |GetBlock { block_id }, _ctx| Ok(store.lock().blocks.get(&block_id).cloned())
        });
        mock.expect_handle_get_first_block_id().returning({
            let store = self.clone();
            move |_msg, _ctx| Ok(store.lock().blocks.keys().next().copied())
        });
        mock.expect_handle_get_last_block_id().returning({
            let store = self.clone();
            move |_msg, _ctx| Ok(store.lock().tip().map(|tip| tip.id))
        });
        mock.expect_handle_get_latest_block_meta().returning({
            let store = self.clone();
            move |_msg, _ctx| Ok(store.lock().tip())
        });
        mock.expect_handle_get_lee_state().returning({
            let store = self.clone();
            move |_msg, _ctx| Ok(store.lock().head_state.clone())
        });
        mock.expect_handle_get_channel_cursor().returning({
            let store = self.clone();
            move |_msg, _ctx| Ok(store.lock().channel_cursor)
        });
        mock.expect_handle_get_zone_checkpoint_bytes().returning({
            let store = self.clone();
            move |_msg, _ctx| Ok(store.lock().checkpoint.clone())
        });
        mock.expect_handle_set_zone_checkpoint_bytes().returning({
            let store = self.clone();
            move |SetZoneCheckpointBytes { bytes }, _ctx| {
                store.lock().checkpoint = Some(bytes);
                Ok(())
            }
        });
        mock.expect_handle_get_zone_anchor().returning({
            let store = self.clone();
            move |_msg, _ctx| Ok(store.lock().anchor)
        });
        mock.expect_handle_set_zone_anchor().returning({
            let store = self.clone();
            move |SetZoneAnchor { anchor }, _ctx| {
                store.lock().anchor = Some(anchor);
                Ok(())
            }
        });
        mock.expect_handle_get_published_high_water().returning({
            let store = self.clone();
            move |_msg, _ctx| Ok(store.lock().published_high_water)
        });
        mock.expect_handle_raise_published_high_water().returning({
            let store = self.clone();
            move |RaisePublishedHighWater { block_id }, _ctx| {
                let mut stored = store.lock();
                stored.published_high_water = stored.published_high_water.max(Some(block_id));
                Ok(())
            }
        });
        mock.expect_handle_apply_store_update().returning({
            let store = self.clone();
            move |update, _ctx| {
                store.lock().apply(update);
                Ok(StoreUpdateOutcome::default())
            }
        });
        mock.expect_handle_get_pending_deposit_events().returning({
            let store = self.clone();
            move |_msg, _ctx| Ok(store.lock().pending_deposits.clone())
        });
        mock.expect_handle_get_pending_cross_zone_dispatches()
            .returning({
                let store = self.clone();
                move |_msg, _ctx| Ok(store.lock().pending_dispatches.clone())
            });
        mock.expect_handle_drop_settled_cross_zone_dispatches()
            .returning({
                let store = self.clone();
                move |DropSettledCrossZoneDispatches { message_keys }, _ctx| {
                    store
                        .lock()
                        .pending_dispatches
                        .retain(|record| !message_keys.contains(&record.message_key));
                    Ok(())
                }
            });
        mock.expect_handle_get_slash_record_bytes()
            .returning(|_msg, _ctx| Ok(None));
        mock.expect_handle_get_dead_letter_dispatches()
            .returning(|_msg, _ctx| Ok(Vec::new()));
        mock
    }

    /// Every stored block, lowest first.
    #[must_use]
    pub fn blocks(&self) -> Vec<Block> {
        self.lock().blocks.values().cloned().collect()
    }

    /// # Panics
    ///
    /// If a mock panicked while holding the store.
    pub fn lock(&self) -> MutexGuard<'_, CannedStore> {
        self.0.lock().expect("canned store lock poisoned")
    }
}
