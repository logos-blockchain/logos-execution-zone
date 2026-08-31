use std::sync::Arc;

use anyhow::{Context as _, Result};
use common::block::{Block, BlockMeta};
use kameo::actor::ActorRef;
use lee::V03State;
use lee_core::BlockId;
use logos_blockchain_zone_sdk::sequencer::SequencerCheckpoint;
use sequencer_storage_actor::{
    StorageActorTrait,
    protocol::{
        CleanPendingBlocksUpTo, DeadLetterDispatchRecord, DeadLetterRequeue, DeleteBlock,
        DeleteZoneCheckpoint, DispatchFailure, DispatchOrigin, DropSettledCrossZoneDispatches,
        GetAllBlocks, GetBlock, GetChannelCursor, GetDeadLetterDispatchCount,
        GetDeadLetterDispatches, GetFinalSnapshot, GetFirstBlockId, GetLastBlockId,
        GetLatestBlockMeta, GetLeeState, GetPendingCrossZoneDispatches, GetPendingDepositEvents,
        GetPublishedHighWater, GetZoneAnchor, GetZoneCheckpointBytes, MarkBlockAsFinalized,
        PendingCrossZoneDispatchRecord, PendingDepositEventRecord, RaisePublishedHighWater,
        RecordDispatchFailure, RecordNewBlock, RequeueDeadLetterDispatch, ResetAllBlocksToPending,
        SetZoneAnchor, SetZoneCheckpointBytes, WithdrawalReconciliationKey, ZoneAnchorRecord,
    },
};

// TODO: Remove entirely, asking the storage actor directly and moving the
// remaining fields to [`crate::SequencerCore`].
pub struct SequencerStore<S: StorageActorTrait> {
    storage_ref: ActorRef<S>,
    genesis_id: u64,
    signing_key: lee::PrivateKey,
}

impl<S: StorageActorTrait> SequencerStore<S> {
    pub async fn new(storage_ref: ActorRef<S>, signing_key: lee::PrivateKey) -> Result<Self> {
        let genesis_id = storage_ref
            .ask(GetFirstBlockId)
            .await?
            .context("Store holds no chain; it must be seeded with a genesis block first")?;

        Ok(Self {
            storage_ref,
            genesis_id,
            signing_key,
        })
    }

    pub async fn block_at_id(&self, id: u64) -> Result<Option<Block>> {
        self.storage_ref
            .ask(GetBlock { block_id: id })
            .await
            .map_err(Into::into)
    }

    pub async fn get_all_blocks(&self) -> Result<Vec<Block>> {
        self.storage_ref.ask(GetAllBlocks).await.map_err(Into::into)
    }

    pub async fn delete_block_at_id(&mut self, block_id: u64) -> Result<()> {
        self.storage_ref
            .ask(DeleteBlock { block_id })
            .await
            .map_err(Into::into)
    }

    pub async fn mark_block_as_finalized(&mut self, block_id: u64) -> Result<()> {
        self.storage_ref
            .ask(MarkBlockAsFinalized { block_id })
            .await
            .map_err(Into::into)
    }

    /// Reset every stored block to `Pending` so the next fresh start republishes the whole chain.
    pub async fn reset_all_blocks_to_pending(&self) -> Result<()> {
        self.storage_ref
            .ask(ResetAllBlocksToPending)
            .await
            .map_err(Into::into)
    }

    /// Persists `block` with the effects it covers.
    pub async fn record_new_block(
        &mut self,
        block: Block,
        channel_cursor: Option<[u8; 32]>,
        withdrawals: Vec<WithdrawalReconciliationKey>,
        state: Arc<V03State>,
        checkpoint_bytes: Option<Vec<u8>>,
    ) -> Result<()> {
        self.storage_ref
            .ask(RecordNewBlock {
                block,
                channel_cursor,
                withdrawals,
                state,
                checkpoint_bytes,
            })
            .await?;
        Ok(())
    }

    /// The id of the chain's last block, or `None` on a store holding no chain.
    pub async fn last_block_id(&self) -> Result<Option<BlockId>> {
        self.storage_ref
            .ask(GetLastBlockId)
            .await
            .map_err(Into::into)
    }

    pub async fn latest_block_meta(&self) -> Result<Option<BlockMeta>> {
        self.storage_ref
            .ask(GetLatestBlockMeta)
            .await
            .map_err(Into::into)
    }

    #[must_use]
    pub const fn genesis_id(&self) -> u64 {
        self.genesis_id
    }

    #[must_use]
    pub const fn signing_key(&self) -> &lee::PrivateKey {
        &self.signing_key
    }

    /// The state after the last applied block, or `None` on a store holding no
    /// chain.
    pub async fn get_lee_state(&self) -> Result<Option<V03State>> {
        self.storage_ref.ask(GetLeeState).await.map_err(Into::into)
    }

    /// Remove the persisted zone-sdk checkpoint so the next startup is treated as a fresh start.
    pub async fn delete_zone_checkpoint(&self) -> Result<()> {
        self.storage_ref
            .ask(DeleteZoneCheckpoint)
            .await
            .map_err(Into::into)
    }

    pub async fn get_zone_checkpoint(&self) -> Result<Option<SequencerCheckpoint>> {
        let Some(bytes) = self.storage_ref.ask(GetZoneCheckpointBytes).await? else {
            return Ok(None);
        };
        let checkpoint: SequencerCheckpoint = serde_json::from_slice(&bytes)
            .context("Failed to deserialize stored zone-sdk checkpoint")?;
        Ok(Some(checkpoint))
    }

    /// Persists `checkpoint` on its own. Only valid when the effects it covers
    /// are already durable — otherwise it must ride in the same write as them,
    /// via [`Self::record_new_block`].
    pub async fn set_zone_checkpoint(&self, checkpoint: &SequencerCheckpoint) -> Result<()> {
        self.storage_ref
            .ask(SetZoneCheckpointBytes {
                bytes: checkpoint_bytes(checkpoint)?,
            })
            .await?;
        Ok(())
    }

    /// The last channel block read back and verified from Bedrock (L1 slot +
    /// `id`/`hash`), or `None` before any block has been read from the channel.
    pub async fn get_zone_anchor(&self) -> Result<Option<ZoneAnchorRecord>> {
        self.storage_ref
            .ask(GetZoneAnchor)
            .await
            .map_err(Into::into)
    }

    pub async fn set_zone_anchor(&self, anchor: ZoneAnchorRecord) -> Result<()> {
        self.storage_ref
            .ask(SetZoneAnchor { anchor })
            .await
            .map_err(Into::into)
    }

    /// The highest block id ever inscribed on the channel by this sequencer,
    /// or `None` before it has published anything.
    pub async fn published_high_water(&self) -> Result<Option<u64>> {
        self.storage_ref
            .ask(GetPublishedHighWater)
            .await
            .map_err(Into::into)
    }

    /// The `MsgId` of the newest channel inscription processed, or `None` if
    /// none was recorded.
    pub async fn channel_cursor(&self) -> Result<Option<[u8; 32]>> {
        self.storage_ref
            .ask(GetChannelCursor)
            .await
            .map_err(Into::into)
    }

    /// Raises the published high water mark to `block_id`, never lowering it.
    pub async fn raise_published_high_water(&self, block_id: u64) -> Result<()> {
        self.storage_ref
            .ask(RaisePublishedHighWater { block_id })
            .await
            .map_err(Into::into)
    }

    pub async fn get_pending_deposit_events(&self) -> Result<Vec<PendingDepositEventRecord>> {
        self.storage_ref
            .ask(GetPendingDepositEvents)
            .await
            .map_err(Into::into)
    }

    /// The persisted final-tier `(state, meta)`, or `None` before anything
    /// finalized.
    pub async fn get_final_snapshot(&self) -> Result<Option<(V03State, BlockMeta)>> {
        self.storage_ref
            .ask(GetFinalSnapshot)
            .await
            .map_err(Into::into)
    }

    /// Marks every stored pending block at or below `last_finalized` as
    /// finalized.
    pub async fn clean_pending_blocks_up_to(&self, last_finalized: BlockId) -> Result<()> {
        self.storage_ref
            .ask(CleanPendingBlocksUpTo { last_finalized })
            .await
            .map_err(Into::into)
    }

    pub async fn pending_cross_zone_dispatches(
        &self,
    ) -> Result<Vec<PendingCrossZoneDispatchRecord>> {
        self.storage_ref
            .ask(GetPendingCrossZoneDispatches)
            .await
            .map_err(Into::into)
    }

    pub async fn drop_settled_cross_zone_dispatches(
        &self,
        message_keys: Vec<[u8; 32]>,
    ) -> Result<usize> {
        self.storage_ref
            .ask(DropSettledCrossZoneDispatches { message_keys })
            .await
            .map_err(Into::into)
    }

    /// Counts one failed production attempt against `message_key`, giving up on
    /// it once `retire_at` accumulate.
    pub async fn record_dispatch_failure(
        &self,
        message_key: [u8; 32],
        retire_at: u32,
        origin: DispatchOrigin,
    ) -> Result<DispatchFailure> {
        self.storage_ref
            .ask(RecordDispatchFailure {
                message_key,
                retire_at,
                origin,
            })
            .await
            .map_err(Into::into)
    }

    pub async fn dead_letter_dispatches(&self) -> Result<Vec<DeadLetterDispatchRecord>> {
        self.storage_ref
            .ask(GetDeadLetterDispatches)
            .await
            .map_err(Into::into)
    }

    pub async fn dead_letter_dispatch_count(&self) -> Result<u64> {
        self.storage_ref
            .ask(GetDeadLetterDispatchCount)
            .await
            .map_err(Into::into)
    }

    /// Restores a retained dead-lettered delivery to the pending list, with a
    /// clean attempt count.
    pub async fn requeue_dead_letter_dispatch(
        &self,
        message_key: [u8; 32],
    ) -> Result<DeadLetterRequeue> {
        self.storage_ref
            .ask(RequeueDeadLetterDispatch { message_key })
            .await
            .map_err(Into::into)
    }

    /// The handle to the actor behind this store, for the paths that hold no
    /// store of their own: the publisher's follow sink and the cross-zone
    /// watchers, each of which outlives any one caller.
    #[must_use]
    pub const fn storage_ref(&self) -> &ActorRef<S> {
        &self.storage_ref
    }
}

/// The checkpoint's on-disk encoding. `serde_json` because `SequencerCheckpoint`
/// derives serde but not borsh; paired with `get_zone_checkpoint`'s decode.
pub(crate) fn checkpoint_bytes(checkpoint: &SequencerCheckpoint) -> Result<Vec<u8>> {
    serde_json::to_vec(checkpoint).context("Failed to serialize zone-sdk checkpoint")
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use common::{HashType, block::HashableBlockData, test_utils::sequencer_sign_key_for_testing};
    use kameo::actor::Spawn as _;
    use sequencer_storage_actor::StorageActor;
    use tempfile::tempdir;

    use super::*;

    fn genesis_block(signing_key: &lee::PrivateKey) -> Block {
        HashableBlockData {
            block_id: 0,
            prev_block_hash: HashType([0; 32]),
            timestamp: 0,
            transactions: vec![],
        }
        .into_pending_block(signing_key)
    }

    /// Creates a fresh database at `path` seeded with `genesis` and opens a
    /// store on the actor serving it.
    async fn create_store(
        path: &Path,
        genesis: &Block,
        signing_key: lee::PrivateKey,
    ) -> SequencerStore<StorageActor> {
        let storage_ref = StorageActor::spawn(StorageActor::new(path).unwrap());
        storage_ref
            .ask(RecordNewBlock {
                block: genesis.clone(),
                channel_cursor: None,
                withdrawals: vec![],
                state: Arc::new(testnet_initial_state::initial_state()),
                checkpoint_bytes: None,
            })
            .await
            .unwrap();
        SequencerStore::new(storage_ref, signing_key).await.unwrap()
    }

    #[tokio::test]
    async fn latest_block_meta_returns_genesis_meta_initially() {
        let temp_dir = tempdir().unwrap();
        let signing_key = sequencer_sign_key_for_testing();
        let genesis = genesis_block(&signing_key);
        let genesis_hash = genesis.header.hash;

        let store = create_store(temp_dir.path(), &genesis, signing_key).await;

        // Verify that initially the latest block hash equals genesis hash
        let latest_meta = store.latest_block_meta().await.unwrap().unwrap();
        assert_eq!(latest_meta.hash, genesis_hash);
    }

    #[tokio::test]
    async fn latest_block_meta_updates_after_new_block() {
        let temp_dir = tempdir().unwrap();
        let signing_key = sequencer_sign_key_for_testing();
        let mut store = create_store(
            temp_dir.path(),
            &genesis_block(&signing_key),
            signing_key.clone(),
        )
        .await;

        // Add a new block
        let tx = common::test_utils::produce_dummy_empty_transaction();
        let block = common::test_utils::produce_dummy_block(1, None, vec![tx]);
        let block_hash = block.header.hash;

        store
            .record_new_block(block.clone(), None, vec![], Arc::new(V03State::new()), None)
            .await
            .unwrap();

        // Verify that the latest block meta now equals the new block's hash
        let latest_meta = store.latest_block_meta().await.unwrap().unwrap();
        assert_eq!(latest_meta.hash, block_hash);
    }

    #[tokio::test]
    async fn mark_block_finalized() {
        let temp_dir = tempdir().unwrap();
        let signing_key = sequencer_sign_key_for_testing();
        let mut store = create_store(
            temp_dir.path(),
            &genesis_block(&signing_key),
            signing_key.clone(),
        )
        .await;

        // Add a new block with Pending status
        let tx = common::test_utils::produce_dummy_empty_transaction();
        let block = common::test_utils::produce_dummy_block(1, None, vec![tx]);
        let block_id = block.header.block_id;

        store
            .record_new_block(block.clone(), None, vec![], Arc::new(V03State::new()), None)
            .await
            .unwrap();

        // Verify initial status is Pending
        let retrieved_block = store.block_at_id(block_id).await.unwrap().unwrap();
        assert!(matches!(
            retrieved_block.bedrock_status,
            common::block::BedrockStatus::Pending
        ));

        // Mark block as finalized
        store.mark_block_as_finalized(block_id).await.unwrap();

        // Verify status is now Finalized
        let finalized_block = store.block_at_id(block_id).await.unwrap().unwrap();
        assert!(matches!(
            finalized_block.bedrock_status,
            common::block::BedrockStatus::Finalized
        ));
    }
}
