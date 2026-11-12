use std::collections::HashSet;

use chain_state::{AnchorConsistencyCheck, ChainConsistency, ChainState, ChannelEntry, Verdict};
use common::HashType;
use log::warn;
use sequencer_bedrock_actor::{
    BedrockActorTrait,
    protocol::{
        BlockData, DepositInfo, Ed25519Key, Ed25519PublicKey, FinalizedBlock, FinalizedUpTo, MsgId,
        Slot, WithdrawInfo,
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
    /// The entry the next finalized one chains on: the one replayed before it.
    pub(super) parent: MsgId,
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
            parent: MsgId::root(),
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
            BlockData::Block(block) => Some(block),
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
        if let Some(check) = &mut self.consistency_check
            && let Some(ChainConsistency::Inconsistent(mismatch)) =
                check.observe(block, finalized.slot)
        {
            return Err(Error::StoreAndChannelDivergence(mismatch.clone()));
        }

        let entry = ChannelEntry {
            msg: finalized.msg_id,
            parent: self.parent,
            signer: finalized.signer.map(|signer| signer.to_bytes()),
            slot: Some(finalized.slot),
            block: block.cloned(),
        };
        self.parent = finalized.msg_id;
        let undecodable: Vec<_> = match (&finalized.block, finalized.signer) {
            // An empty payload is a missed turn, not this offence.
            (BlockData::Undecodable(data), Some(signer)) if !data.is_empty() => {
                vec![(finalized.msg_id, signer)]
            }
            _ => Vec::new(),
        };
        // Only the slots before the entry's own are known complete.
        let lib_slot = finalized.slot.saturating_sub(Slot::from(1));
        self.apply_finalized_entry(Some(entry), &undecodable, lib_slot)
            .await?;
        self.on_lineage = self.on_lineage || finalized.msg_id == self.stored_final;
        Ok(())
    }

    /// Goes online once the finalized history is replayed up to [`Self::bootstrap_to`].
    ///
    /// A chain holding no block yet waits for the channel's first one to finalize, as it has
    /// nothing to follow the channel from.
    pub async fn on_finalized_up_to(mut self, up_to: FinalizedUpTo) -> Result<State<S, B>> {
        self.replayed = Some(up_to);
        // Every slot up to it is complete.
        self.apply_finalized_entry(None, &[], up_to.slot).await?;
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
            Box::pin(online::OnlineState::from_bootstrapping(self, up_to.slot)).await?,
        ))
    }

    /// Hands the slasher the offences the replay proves.
    async fn report_offences(&self, offences: Vec<ReportedOffence>) -> Result<()> {
        if offences.is_empty() {
            return Ok(());
        }
        self.actors.slasher_ref.ask(Report { offences }).await?;
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

    /// Folds one finalized channel entry, or none once a slot is complete, with the LIB at
    /// `lib_slot`, as the follow path folds an update's finalized entries. A block the store
    /// already holds as final only settles its deliveries. Advances the persisted anchor to a
    /// block the store holds after this, and reports the offences `undecodable` and the fold
    /// prove before that.
    async fn apply_finalized_entry(
        &mut self,
        entry: Option<ChannelEntry>,
        undecodable: &[(MsgId, Ed25519PublicKey)],
        lib_slot: Slot,
    ) -> Result<()> {
        let head_before: HashSet<HashType> = self
            .chain
            .head_blocks()
            .map(|block| block.header.hash)
            .collect();
        let was_empty = self.chain.final_tip().is_none();
        let folded = self.chain.apply_finalized(entry.as_slice(), lib_slot);
        let judged = folded
            .judged
            .iter()
            .find(|judged| entry.as_ref().is_some_and(|read| read.msg == judged.msg));

        // The channel's first finalized block is its genesis: one that is not
        // ours means a different chain, not an offence to step over.
        if was_empty
            && let Some(failed) = judged.filter(|first| !matches!(first.verdict, Verdict::Settled))
        {
            return Err(Error::BlockReconstructionFailed {
                block_id: failed.block.header.block_id,
                verdict: Box::new(failed.verdict.clone()),
            });
        }
        self.report_offences(faults::judge(undecodable, &folded.judged))
            .await?;

        // A reconstructed block is finalized, so any deposit it mints is
        // permanently reflected in state (its receipt PDA); the update drops the
        // pending record backfill may have re-delivered, so the drain stops
        // re-minting. The same for the deliveries it carries.
        let storage_ref = &self.actors.storage_ref;
        let (mut update, newly_final) = sequencer_core::settlement_update(
            storage_ref,
            &self.chain,
            &head_before,
            folded.settled,
            folded.skipped,
            &[],
        )
        .await;

        if let Some(ChannelEntry {
            block: Some(block),
            slot: Some(slot),
            ..
        }) = &entry
        {
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
            let settled = newly_final
                .iter()
                .any(|final_block| final_block.header.hash == block.header.hash);
            match held_final {
                _ if settled => update.zone_anchor = Some(record),
                // A block we already hold verbatim needs no replay, but the
                // channel serving it is what makes it irreversible, so its
                // deposits and deliveries are settled and their records are
                // owed nothing.
                Some(stored) => {
                    update
                        .finalized_dispatch_records
                        .extend(sequencer_core::settled_dispatch_keys(storage_ref, &stored).await);
                    update.finalized_deposit_records.extend(
                        stored
                            .body
                            .transactions
                            .iter()
                            .filter_map(sequencer_core::extract_bridge_deposit_id),
                    );
                    update.zone_anchor = Some(record);
                }
                None => {
                    if let Some(Verdict::Dropped { error, .. }) =
                        judged.map(|judged_entry| &judged_entry.verdict)
                    {
                        warn!(
                            "Finalized channel block {block_id} does not apply, skipping it: {:#}",
                            anyhow::anyhow!(error.clone())
                        );
                    }
                }
            }
        }

        storage_ref.ask(update).await?;
        Ok(())
    }
}
