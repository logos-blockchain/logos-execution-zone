use std::collections::HashSet;

use chain_state::{AcceptOutcome, AnchorConsistencyCheck, ChainConsistency, ChainState};
use common::block::{Block, BlockMeta};
use kameo::actor::ActorRef;
use log::warn;
use sequencer_bedrock_actor::{
    BedrockActorTrait,
    protocol::{BlockData, Ed25519Key, FinalizedBlock, MsgId, Slot},
};
use sequencer_core::config::SequencerConfig;
use sequencer_storage_actor::StorageActorTrait;

use crate::{
    Result,
    actor::state::{ActorsBundle, State, online},
    error::Error,
};

#[cfg(test)]
mod tests;

pub struct BootstrappingState<S: StorageActorTrait, B: BedrockActorTrait> {
    pub(super) config: SequencerConfig,
    pub(super) chain: ChainState,
    pub(super) bedrock_signing_key: Ed25519Key,
    pub(super) consistency_check: Option<AnchorConsistencyCheck>,
    /// Channel tip at startup. Only its message identifies it: a config change moves the tip
    /// slot without a message the finalized stream would carry.
    pub(super) bootstrap_to: MsgId,
    pub(super) actors: ActorsBundle<S, B>,
}

impl<S: StorageActorTrait, B: BedrockActorTrait> BootstrappingState<S, B> {
    pub(super) const fn new(
        config: SequencerConfig,
        chain: ChainState,
        bedrock_signing_key: Ed25519Key,
        consistency_check: Option<AnchorConsistencyCheck>,
        bootstrap_to: MsgId,
        actors: ActorsBundle<S, B>,
    ) -> Self {
        Self {
            config,
            chain,
            bedrock_signing_key,
            consistency_check,
            bootstrap_to,
            actors,
        }
    }

    /// The channel entry bootstrapping completes at.
    pub const fn bootstrap_to(&self) -> MsgId {
        self.bootstrap_to
    }

    pub const fn chain(&self) -> &ChainState {
        &self.chain
    }

    /// Apply a finalized block to the bootstrapping state.
    pub async fn on_finalized_block(mut self, finalized: FinalizedBlock) -> Result<State<S, B>> {
        match finalized.block {
            BlockData::Block(block) => {
                if let Some(check) = &mut self.consistency_check
                    && let Some(ChainConsistency::Inconsistent(mismatch)) =
                        check.observe(&block, finalized.slot)
                {
                    return Err(Error::StoreAndChannelDivergence(mismatch.clone()));
                }

                self.apply_reconstructed_block(&block, finalized.msg_id, finalized.slot)
                    .await?;
            }
            BlockData::Undecodable(_data) => {
                // An offence the channel already carries, so replaying it must not
                // be fatal.
                warn!(
                    "Skipping an undecodable inscription {:?} at slot {}",
                    finalized.msg_id,
                    finalized.slot.into_inner(),
                );
                self.chain.skip_channel_entry(finalized.msg_id);
            }
        }

        if finalized.msg_id == self.bootstrap_to {
            return Ok(State::Online(
                online::OnlineState::from_bootstrapping(self).await?,
            ));
        }

        Ok(State::Bootstrapping(self))
    }

    async fn apply_reconstructed_block(
        &mut self,
        block: &Block,
        this_msg: MsgId,
        slot: Slot,
    ) -> Result<()> {
        let tip = self
            .actors
            .storage_ref
            .ask(sequencer_storage_actor::protocol::GetLatestBlockMeta)
            .await?;
        let block_id = block.header.block_id;
        let block_hash = block.header.hash;

        let record = sequencer_storage_actor::protocol::ZoneAnchorRecord {
            slot: slot.into_inner(),
            block_id,
            hash: block_hash,
        };

        // A block we already hold verbatim needs no replay, but the channel
        // serving it is what makes it irreversible, so its deliveries are
        // settled and their records are owed nothing. Without this a restart
        // leaves a record for every delivery it already published, and nothing
        // downstream would ever remove them.
        if let Some(tip) = &tip
            && block_id <= tip.id
            && let Some(stored) = self
                .actors
                .storage_ref
                .ask(sequencer_storage_actor::protocol::GetBlock { block_id })
                .await?
            && stored.header.hash == block_hash
        {
            // TODO: Should be atomic
            Self::settle_reconstructed_deliveries(&self.actors.storage_ref, &stored).await?;
            self.actors
                .storage_ref
                .ask(sequencer_storage_actor::protocol::SetZoneAnchor { anchor: record })
                .await?;
            return Ok(());
        }

        // A conflict at a height the final tier already settled: the channel
        // carries two inscriptions for one block id — competing sequencers
        // around a turn change — and finality already picked one, so the other
        // is dropped. `apply_adopted` ignores the same conflict. A genuinely
        // foreign channel is caught upstream by the anchor consistency check,
        // not here; the anchor stays on the block we hold.
        if let Some(final_tip) = self.chain.final_tip()
            && block_id <= final_tip.block_id
        {
            warn!(
                "Ignoring channel block {block_id} with hash {block_hash} conflicting with the \
                 finalized block at this height"
            );
            return Ok(());
        }

        // Above the final tier the head is reorg-able, so finalized history wins:
        // the head rebases onto what the channel settled. Validation happens inside.
        match self.chain.apply_reconstructed(block, slot, this_msg) {
            AcceptOutcome::Applied | AcceptOutcome::AlreadyApplied => {}
            AcceptOutcome::Parked(err) | AcceptOutcome::RetryableFailure(err) => {
                return Err(Error::BlockReconstructionFailed {
                    block_id,
                    source: err,
                });
            }
        }

        // A reconstructed block is finalized, so any deposit it mints is
        // permanently reflected in state (its receipt PDA); drop the pending
        // record backfill may have re-delivered, so the drain stops re-minting.
        let finalized_deposit_ids: HashSet<_> = block
            .body
            .transactions
            .iter()
            .filter_map(sequencer_core::extract_bridge_deposit_id)
            .collect();
        // The same for the deliveries it carries: the inbox has seen them, so
        // the drain would skip them anyway, and the records are owed nothing.
        let finalized_dispatch_keys =
            sequencer_core::settled_dispatch_keys(&self.actors.storage_ref, block).await;

        // The tip meta stays pinned to the head tip even when the reconstructed
        // block lands below it, and the anchor only advances if the block
        // itself landed.
        let head_tip = self.chain.head_tip().map(|head| BlockMeta::from(&head));
        let final_meta = self.chain.final_tip().map(|meta| BlockMeta::from(&meta));
        self.actors
            .storage_ref
            .ask(sequencer_storage_actor::protocol::AtomicUpdate {
                blocks: vec![block.clone()],
                head_tip,
                channel_cursor: Some(this_msg.into()),
                head_state: self.chain.share_head_state(),
                final_snapshot: final_meta.map(|meta| (self.chain.share_final_state(), meta)),
                finalized_deposit_records: finalized_deposit_ids,
                finalized_dispatch_records: finalized_dispatch_keys,
                zone_anchor: Some(record),
                checkpoint: None,
                finalized_up_to: Some(block.header.block_id),
                new_deposit_events: Vec::new(),
                consumed_withdrawals: HashSet::new(),
                new_withdraw_intents: HashSet::new(),
                lower_published_high_water: None,
            })
            .await?;

        Ok(())
    }

    /// Drops the records of deliveries carried by a reconstructed block.
    ///
    /// A persist failure is only logged: the deliveries are already irreversible, so
    /// the worst case is a record the next drain drops instead.
    async fn settle_reconstructed_deliveries(
        storage_ref: &ActorRef<S>,
        block: &Block,
    ) -> Result<()> {
        let keys = sequencer_core::settled_dispatch_keys(storage_ref, block).await;
        if keys.is_empty() {
            return Ok(());
        }
        storage_ref
            .ask(
                sequencer_storage_actor::protocol::DropSettledCrossZoneDispatches {
                    message_keys: keys,
                },
            )
            .await?;

        Ok(())
    }
}
