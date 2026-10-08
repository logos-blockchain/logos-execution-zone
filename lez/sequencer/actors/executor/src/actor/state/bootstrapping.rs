use std::collections::HashSet;

use chain_state::{AcceptOutcome, AnchorConsistencyCheck, ChainConsistency, ChainState};
use common::{
    HashType,
    block::{Block, BlockMeta},
};
use kameo::actor::ActorRef;
use log::warn;
use sequencer_bedrock_actor::{
    BedrockActorTrait,
    protocol::{BlockData, Ed25519Key, FinalizedBlock, MsgId, Slot},
};
use sequencer_core::config::SequencerConfig;
use sequencer_storage_actor::{StorageActorTrait, protocol::ZoneAnchorRecord};

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
    /// The final entry the store held at startup. Finalized history is read in lineage order,
    /// but a warm start re-reads what the final tier holds, so the lineage resumes past it.
    pub(super) stored_final: MsgId,
    /// Whether the replay is past [`Self::stored_final`].
    pub(super) on_lineage: bool,
    /// The last finalized entry replayed.
    pub(super) replayed_to: Option<MsgId>,
    pub(super) actors: ActorsBundle<S, B>,
}

impl<S: StorageActorTrait, B: BedrockActorTrait> BootstrappingState<S, B> {
    pub(super) fn new(
        config: SequencerConfig,
        chain: ChainState,
        bedrock_signing_key: Ed25519Key,
        consistency_check: Option<AnchorConsistencyCheck>,
        bootstrap_to: MsgId,
        actors: ActorsBundle<S, B>,
    ) -> Self {
        let stored_final = chain.final_msg();
        Self {
            config,
            chain,
            bedrock_signing_key,
            consistency_check,
            bootstrap_to,
            stored_final,
            on_lineage: stored_final == MsgId::root(),
            replayed_to: None,
            actors,
        }
    }

    /// The channel entry bootstrapping completes at.
    pub const fn bootstrap_to(&self) -> MsgId {
        self.bootstrap_to
    }

    /// The last finalized entry replayed, [`None`] before the first.
    pub const fn replayed_to(&self) -> Option<MsgId> {
        self.replayed_to
    }

    pub const fn chain(&self) -> &ChainState {
        &self.chain
    }

    /// Apply a finalized block to the bootstrapping state.
    pub async fn on_finalized_block(mut self, finalized: &FinalizedBlock) -> Result<State<S, B>> {
        let block = match &finalized.block {
            BlockData::Block(block) => {
                if let Some(check) = &mut self.consistency_check
                    && let Some(ChainConsistency::Inconsistent(mismatch)) =
                        check.observe(block, finalized.slot)
                {
                    return Err(Error::StoreAndChannelDivergence(mismatch.clone()));
                }
                Some(block)
            }
            BlockData::Undecodable(_data) => {
                // An offence the channel already carries, so replaying it must not
                // be fatal: the entry carries no block, and the lineage moves past it.
                warn!(
                    "Skipping an undecodable inscription {:?} at slot {}",
                    finalized.msg_id,
                    finalized.slot.into_inner(),
                );
                None
            }
        };

        self.apply_finalized_entry(finalized.msg_id, block, finalized.slot)
            .await?;
        self.on_lineage = self.on_lineage || finalized.msg_id == self.stored_final;
        self.replayed_to = Some(finalized.msg_id);

        if finalized.msg_id == self.bootstrap_to {
            if !self.on_lineage {
                warn!(
                    "Bootstrapping never re-read the stored final entry {}, so it left the \
                     lineage untouched; the Bedrock node's finality may lag behind it",
                    self.stored_final
                );
            }
            return Ok(State::Online(
                online::OnlineState::from_bootstrapping(self).await?,
            ));
        }

        Ok(State::Bootstrapping(self))
    }

    /// Applies one finalized channel entry, moving the final entry to it only on the lineage. A
    /// block the store already holds only settles its deliveries, a block that does not apply is
    /// skipped, like the follow path does. Advances the persisted anchor to a block the store
    /// holds after this.
    async fn apply_finalized_entry(
        &mut self,
        msg: MsgId,
        entry_block: Option<&Block>,
        slot: Slot,
    ) -> Result<()> {
        let storage_ref = &self.actors.storage_ref;
        let head_before: HashSet<HashType> = self
            .chain
            .head_blocks()
            .iter()
            .map(|block| block.header.hash)
            .collect();
        let was_empty = self.chain.final_tip().is_none();
        let outcome = if self.on_lineage {
            self.chain.apply_reconstructed(msg, entry_block)
        } else {
            self.chain.apply_finalized_redelivery(msg, entry_block)
        };

        // The channel's first finalized block is its genesis: one that is not
        // ours means a different chain, not an offence to step over.
        if was_empty
            && let Some(block) = &entry_block
            && let Some(AcceptOutcome::Parked(err) | AcceptOutcome::RetryableFailure(err)) =
                &outcome
        {
            return Err(Error::BlockReconstructionFailed {
                block_id: block.header.block_id,
                source: err.clone(),
            });
        }

        let newly_final = self.chain.take_newly_final();
        let mut update = sequencer_core::chain_update(&self.chain);
        update.blocks = sequencer_core::new_head_blocks(&self.chain, &head_before);
        if !newly_final.is_empty() {
            // A reconstructed block is finalized, so any deposit it mints is
            // permanently reflected in state (its receipt PDA); drop the
            // pending record backfill may have re-delivered, so the drain
            // stops re-minting. The same for the deliveries it carries.
            update.finalized_deposit_records = newly_final
                .iter()
                .flat_map(|block| block.body.transactions.iter())
                .filter_map(sequencer_core::extract_bridge_deposit_id)
                .collect();
            for block in &newly_final {
                update
                    .finalized_dispatch_records
                    .extend(sequencer_core::settled_dispatch_keys(storage_ref, block).await);
            }
            update.blocks.extend(newly_final.iter().cloned());
            update.final_snapshot = self
                .chain
                .final_tip()
                .map(|tip| (self.chain.share_final_state(), BlockMeta::from(&tip)));
            update.finalized_up_to = self.chain.final_tip().map(|tip| tip.block_id);
        }

        if let Some(block) = &entry_block {
            let block_id = block.header.block_id;
            let record = ZoneAnchorRecord {
                slot: slot.into_inner(),
                block_id,
                hash: block.header.hash,
            };
            let held_final = if self
                .chain
                .final_tip()
                .is_some_and(|tip| tip.block_id >= block_id)
            {
                storage_ref
                    .ask(sequencer_storage_actor::protocol::GetBlock { block_id })
                    .await?
                    .filter(|stored| stored.header.hash == block.header.hash)
            } else {
                None
            };
            match outcome {
                Some(AcceptOutcome::Applied(events)) => {
                    update.zone_anchor = Some(record);
                    update.events = events;
                }
                // A block we already hold verbatim needs no replay, but the
                // channel serving it is what makes it irreversible, so its
                // deliveries are settled and their records are owed nothing.
                Some(AcceptOutcome::AlreadyApplied | AcceptOutcome::Parked(_))
                    if let Some(stored) = held_final =>
                {
                    Self::settle_reconstructed_deliveries(storage_ref, &stored).await?;
                    update.zone_anchor = Some(record);
                }
                Some(AcceptOutcome::AlreadyApplied) | None => {}
                Some(AcceptOutcome::Parked(err) | AcceptOutcome::RetryableFailure(err)) => {
                    warn!(
                        "Finalized channel block {block_id} does not apply, skipping it: {:#}",
                        anyhow::anyhow!(err)
                    );
                }
            }
        }

        storage_ref.ask(update).await?;
        Ok(())
    }

    /// Drops the records of deliveries carried by a reconstructed block.
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
