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
    protocol::{
        BlockData, DepositInfo, Ed25519Key, FinalizedBlock, FinalizedUpTo, MsgId, Slot,
        WithdrawInfo,
    },
};
use sequencer_core::{config::SequencerConfig, faults};
use sequencer_slasher_actor::protocol::{Report, ReportedOffence};
use sequencer_storage_actor::{
    StorageActorTrait,
    protocol::{AtomicUpdate, ZoneAnchorRecord},
};

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
    pub(super) channel_signing_key: Ed25519Key,
    pub(super) consistency_check: Option<AnchorConsistencyCheck>,
    /// The final entry the store held at startup. Finalized history is read in lineage order,
    /// but a warm start re-reads what the final tier holds, so the lineage resumes past it.
    pub(super) stored_final: MsgId,
    /// Whether the replay is past [`Self::stored_final`].
    pub(super) on_lineage: bool,
    /// How far the finalized history is replayed, [`None`] before the first batch.
    pub(super) replayed: Option<FinalizedUpTo>,
    pub(super) actors: ActorsBundle<S, B>,
}

impl<S: StorageActorTrait, B: BedrockActorTrait> BootstrappingState<S, B> {
    pub(super) fn new(
        config: SequencerConfig,
        chain: ChainState,
        channel_signing_key: Ed25519Key,
        consistency_check: Option<AnchorConsistencyCheck>,
        actors: ActorsBundle<S, B>,
    ) -> Self {
        let stored_final = chain.final_msg();
        Self {
            config,
            chain,
            channel_signing_key,
            consistency_check,
            stored_final,
            on_lineage: stored_final == MsgId::root(),
            replayed: None,
            actors,
        }
    }

    /// The slot bootstrapping completes at: the last one the node had finalized, as of the
    /// latest batch. [`None`] before the first batch.
    pub fn bootstrap_to(&self) -> Option<Slot> {
        self.replayed.map(|replayed| replayed.last_finalized_slot)
    }

    /// The slot the finalized history is replayed up to, [`None`] before the first batch.
    pub fn replayed_up_to(&self) -> Option<Slot> {
        self.replayed.map(|replayed| replayed.slot)
    }

    pub const fn chain(&self) -> &ChainState {
        &self.chain
    }

    /// Apply a finalized block to the bootstrapping state.
    pub async fn on_finalized_block(&mut self, finalized: &FinalizedBlock) -> Result<()> {
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

        self.apply_finalized_entry(finalized, block).await?;
        self.on_lineage = self.on_lineage || finalized.msg_id == self.stored_final;
        Ok(())
    }

    /// Goes online once the finalized history is replayed up to [`Self::bootstrap_to`].
    ///
    /// A chain holding no block yet waits for the channel's first one to finalize, as it has
    /// nothing to follow the channel from.
    pub async fn on_finalized_up_to(mut self, up_to: FinalizedUpTo) -> Result<State<S, B>> {
        self.replayed = Some(up_to);
        if !up_to.is_caught_up() || self.chain.head_tip().is_none() {
            return Ok(State::Bootstrapping(self));
        }

        if !self.on_lineage {
            warn!(
                "Bootstrapping never re-read the stored final entry {}, so it left the lineage \
                 untouched; the Bedrock node's finality may lag behind it",
                self.stored_final
            );
        }
        Ok(State::Online(
            online::OnlineState::from_bootstrapping(self, up_to.slot).await?,
        ))
    }

    /// Hands the slasher an offence the replay proves.
    async fn report_offence(&self, offence: ReportedOffence) -> Result<()> {
        self.actors
            .slasher_ref
            .ask(Report {
                offences: vec![offence],
            })
            .await?;
        Ok(())
    }

    /// Records a finalized deposit read alongside the finalized blocks.
    pub async fn on_finalized_deposit(&self, deposit: &DepositInfo) -> Result<()> {
        let outcome = self
            .actors
            .storage_ref
            .ask(AtomicUpdate {
                new_deposit_events: vec![sequencer_core::pending_deposit_event_record(deposit)],
                ..sequencer_core::chain_update(&self.chain)
            })
            .await?;
        sequencer_core::log_recorded_deposits(&outcome);
        Ok(())
    }

    /// Reconciles a finalized withdrawal read alongside the finalized blocks.
    pub async fn on_finalized_withdrawal(&self, withdrawal: &WithdrawInfo) -> Result<()> {
        let outcome = self
            .actors
            .storage_ref
            .ask(AtomicUpdate {
                consumed_withdrawals: sequencer_core::released_note_keys(withdrawal).collect(),
                ..sequencer_core::chain_update(&self.chain)
            })
            .await?;
        sequencer_core::log_unmatched_withdrawals(&outcome);
        Ok(())
    }

    /// Applies one finalized channel entry, moving the final entry to it only on the lineage. A
    /// block the store already holds only settles its deliveries, a block that does not apply is
    /// skipped, like the follow path does. Advances the persisted anchor to a block the store
    /// holds after this, and reports the offence the entry proves before that.
    async fn apply_finalized_entry(
        &mut self,
        finalized: &FinalizedBlock,
        entry_block: Option<&Block>,
    ) -> Result<()> {
        let msg = finalized.msg_id;
        let slot = finalized.slot;
        let storage_ref = &self.actors.storage_ref;
        let head_before: HashSet<HashType> = self
            .chain
            .head_blocks()
            .map(|block| block.header.hash)
            .collect();
        let was_empty = self.chain.final_tip().is_none();
        // A root lineage over a held tier is a store restored without its view.
        let judgeable = !was_empty && self.chain.final_msg() != MsgId::root();
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

        let next = judgeable && self.chain.final_msg() == msg;
        let offence = finalized
            .signer
            .and_then(|signer| match (&finalized.block, &outcome) {
                // An empty payload is a missed turn, not this offence.
                (BlockData::Undecodable(data), _) if !data.is_empty() => {
                    Some(faults::not_a_block(msg, signer))
                }
                (BlockData::Block(_), Some(outcome)) => {
                    faults::block_offence(msg, outcome, next, signer)
                }
                (BlockData::Undecodable(_) | BlockData::Block(_), _) => None,
            });
        if let Some(offence) = offence {
            self.report_offence(offence).await?;
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
                // deposits and deliveries are settled and their records are
                // owed nothing.
                Some(AcceptOutcome::AlreadyApplied | AcceptOutcome::Parked(_))
                    if let Some(stored) = held_final =>
                {
                    Self::settle_reconstructed_deliveries(storage_ref, &stored).await?;
                    update.finalized_deposit_records.extend(
                        stored
                            .body
                            .transactions
                            .iter()
                            .filter_map(sequencer_core::extract_bridge_deposit_id),
                    );
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
