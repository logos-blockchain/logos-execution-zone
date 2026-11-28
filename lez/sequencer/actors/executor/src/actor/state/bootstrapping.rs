use std::collections::{BTreeSet, HashSet};

use chain_state::{AcceptOutcome, AnchorConsistencyCheck, ChainConsistency, ChainState};
use common::{HashType, block::BlockMeta};
use sequencer_bedrock_actor::{
    BedrockActorTrait,
    protocol::{
        ChannelEntry, ChannelEventKind, ChannelUpdate, Ed25519Key, Ed25519PublicKey, FollowStart,
        L1Position, MsgId, Slot, ViewChange,
    },
};
use sequencer_core::{config::SequencerConfig, faults, release_finality};
use sequencer_slasher_actor::protocol::{Report, ReportedOffence};
use sequencer_storage_actor::{
    StorageActorTrait,
    protocol::{AtomicUpdate, ZoneAnchorRecord},
};
use tracing::{debug, info, warn};

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
    /// The last config entry that reached finality, as of the last update applied.
    pub(super) finalized_config: MsgId,
    /// The last slot the node had finalized when following started.
    pub(super) bootstrap_to: Option<Slot>,
    /// LIB slot of the last update applied, [`None`] before the first one.
    pub(super) replayed_up_to: Option<Slot>,
    /// Whether the finalized history is read up to the node's LIB.
    pub(super) ready: bool,
    /// The channel's first message, while it is not final yet: the genesis a chain holding no
    /// block goes online from, as it would otherwise wait for it to finalize.
    pub(super) unfinalized_genesis: Option<ChannelEntry>,
    pub(super) actors: ActorsBundle<S, B>,
}

impl<S: StorageActorTrait, B: BedrockActorTrait> BootstrappingState<S, B> {
    pub(super) const fn new(
        config: SequencerConfig,
        chain: ChainState,
        channel_signing_key: Ed25519Key,
        consistency_check: Option<AnchorConsistencyCheck>,
        follow_start: FollowStart,
        actors: ActorsBundle<S, B>,
    ) -> Self {
        Self {
            config,
            chain,
            channel_signing_key,
            consistency_check,
            finalized_config: follow_start.finalized_config,
            bootstrap_to: follow_start.lib_slot,
            replayed_up_to: None,
            ready: false,
            unfinalized_genesis: None,
            actors,
        }
    }

    /// The slot bootstrapping completes at: the last one the node had finalized when following
    /// started.
    pub const fn bootstrap_to(&self) -> Option<Slot> {
        self.bootstrap_to
    }

    /// The slot the finalized history is replayed up to, [`None`] before the first update.
    pub const fn replayed_up_to(&self) -> Option<Slot> {
        self.replayed_up_to
    }

    pub const fn chain(&self) -> &ChainState {
        &self.chain
    }

    /// Replays the finalized history `event` reports, going online once it is read up to the
    /// node's LIB.
    ///
    /// The view is left to the online state, which zone-sdk reports it to again once the
    /// publisher is initialized.
    pub async fn on_channel_event(mut self, event: &ChannelEventKind) -> Result<State<S, B>> {
        match event {
            ChannelEventKind::Update(update) => self.on_channel_update(update).await?,
            ChannelEventKind::Ready => self.ready = true,
            ChannelEventKind::Turn { .. } | ChannelEventKind::Config(_) => {
                debug!("Ignoring a channel event about the live chain while bootstrapping");
            }
        }
        self.go_online_if_caught_up().await
    }

    /// Goes online once the finalized history is read up to the node's LIB.
    ///
    /// A chain holding no block yet has nothing to follow the channel from, so it first adopts
    /// the channel's genesis from the view, before it finalizes, as the channel's creator holds it.
    /// It keeps bootstrapping while the view holds none.
    async fn go_online_if_caught_up(mut self) -> Result<State<S, B>> {
        if !self.ready {
            return Ok(State::Bootstrapping(self));
        }
        if self.chain.head_tip().is_none() {
            self.adopt_unfinalized_genesis().await?;
        }
        if self.chain.head_tip().is_none() {
            return Ok(State::Bootstrapping(self));
        }
        Ok(State::Online(
            online::OnlineState::from_bootstrapping(self).await?,
        ))
    }

    /// Applies and persists the finalized entries, deposits and withdrawals of `update`.
    async fn on_channel_update(&mut self, update: &ChannelUpdate) -> Result<()> {
        let ChannelUpdate {
            lib_slot,
            finalized_config,
            view,
            finalized,
            deposits,
            pending_deposits: _,
            withdrawals,
            undecodable,
            finalized_signers,
        } = update;

        let mut store_update = sequencer_core::chain_update(&self.chain);
        for entry in finalized {
            let signer = |signed: &[(MsgId, Ed25519PublicKey)]| {
                signed
                    .iter()
                    .find(|(msg, _)| *msg == entry.msg)
                    .map(|(_, signer)| *signer)
            };
            let signed = if entry.block.is_some() {
                signer(finalized_signers).map(Signed::Block)
            } else {
                signer(undecodable).map(Signed::NotABlock)
            };
            self.apply_finalized_entry(entry, signed, &mut store_update)
                .await?;
        }

        let AtomicUpdate {
            channel_view,
            head_tip,
            head_state,
            ..
        } = sequencer_core::chain_update(&self.chain);
        let outcome = self
            .actors
            .storage_ref
            .ask(AtomicUpdate {
                channel_view,
                head_tip,
                head_state,
                new_deposit_events: deposits
                    .iter()
                    .map(sequencer_core::pending_deposit_event_record)
                    .collect(),
                consumed_withdrawals: withdrawals
                    .iter()
                    .flat_map(sequencer_core::released_note_keys)
                    .collect(),
                ..store_update
            })
            .await?;
        sequencer_core::log_recorded_deposits(&outcome);
        sequencer_core::log_unmatched_withdrawals(&outcome);

        self.track_unfinalized_genesis(view);
        self.finalized_config = *finalized_config;
        self.replayed_up_to = Some(*lib_slot);
        Ok(())
    }

    /// Keeps [`Self::unfinalized_genesis`] to what `view` leaves as the channel's first message.
    ///
    /// The rest of the view is left to the online state, which zone-sdk reports it to again.
    fn track_unfinalized_genesis(&mut self, view: &ViewChange) {
        let first = |entries: &[ChannelEntry]| {
            entries
                .iter()
                .find(|entry| entry.parent == MsgId::root())
                .cloned()
        };
        match view {
            ViewChange::Extension(adopted) => {
                if self.unfinalized_genesis.is_none() {
                    self.unfinalized_genesis = first(adopted);
                }
            }
            ViewChange::Conflict { canonical, .. } => {
                self.unfinalized_genesis = first(canonical);
            }
        }
    }

    /// Applies the channel's genesis from the view to a chain holding no block, and persists it.
    ///
    /// The genesis is checked once it finalizes, as any held block is: one the channel finalizes
    /// differently fails the replay, and one L1 orphans leaves the view.
    async fn adopt_unfinalized_genesis(&mut self) -> Result<()> {
        // Taken, so one that does not apply is tried once, until a conflict reports another.
        let Some(mut entry) = self.unfinalized_genesis.take() else {
            return Ok(());
        };
        let Some(block) = &entry.block else {
            warn!(
                msg_id = %entry.msg,
                "The channel's first message carries no block, waiting for it to finalize"
            );
            return Ok(());
        };
        let block_id = block.header.block_id;
        entry.finally_absent_keys = release_finality::finally_absent_keys(
            &self.actors.bedrock_pool_ref,
            self.config.bedrock_config.channel_id,
            L1Position::Msg(entry.msg),
            block,
            release_finality::finality_depth(self.chain.final_state()),
        )
        .await;

        let head_before: HashSet<HashType> = self
            .chain
            .head_blocks()
            .map(|held| held.header.hash)
            .collect();
        self.chain.apply_extension(vec![entry.clone()]);
        if self.chain.head_tip().is_none() {
            warn!(
                msg_id = %entry.msg,
                block_id,
                "The channel's unfinalized genesis does not apply, waiting for it to finalize"
            );
            return Ok(());
        }
        info!(
            msg_id = %entry.msg,
            block_id,
            "Adopted the channel's genesis before it finalized"
        );
        self.actors
            .storage_ref
            .ask(AtomicUpdate {
                blocks: sequencer_core::new_head_blocks(&self.chain, &head_before),
                ..sequencer_core::chain_update(&self.chain)
            })
            .await?;
        Ok(())
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

    /// Applies one finalized channel entry, signed as `signed` says, adding what it changes to
    /// `store_update`. A block the store already holds only settles its deposits, a block that
    /// does not apply is skipped, like the online state does. Advances the persisted anchor to a
    /// block the store holds after this, and reports the offence the entry proves before that.
    async fn apply_finalized_entry(
        &mut self,
        entry: &ChannelEntry,
        signed: Option<Signed>,
        store_update: &mut AtomicUpdate,
    ) -> Result<()> {
        let msg = entry.msg;
        let slot = Slot::from(
            entry
                .final_slot
                .expect("A finalized entry carries its slot"),
        );
        let entry_block = entry.block.as_ref();
        if entry_block.is_none() && matches!(signed, Some(Signed::NotABlock(_))) {
            // An offence the channel already carries, so replaying it must not be fatal: the
            // entry carries no block, and the lineage moves past it.
            warn!(
                msg_id = %msg,
                slot = slot.into_inner(),
                "Skipping an undecodable inscription"
            );
        }
        if let Some(check) = &mut self.consistency_check
            && let Some(ChainConsistency::Inconsistent(mismatch)) = check.observe(entry_block, slot)
        {
            return Err(Error::StoreAndChannelDivergence(mismatch.clone()));
        }

        let finally_absent_keys = match entry_block {
            Some(block) => {
                release_finality::finally_absent_keys(
                    &self.actors.bedrock_pool_ref,
                    self.config.bedrock_config.channel_id,
                    L1Position::FinalSlot(slot.into_inner()),
                    block,
                    release_finality::finality_depth(self.chain.final_state()),
                )
                .await
            }
            None => BTreeSet::new(),
        };
        let storage_ref = &self.actors.storage_ref;
        let head_before: HashSet<HashType> = self
            .chain
            .head_blocks()
            .map(|block| block.header.hash)
            .collect();
        let was_empty = self.chain.final_tip().is_none();
        // A root lineage over a held tier is a store restored without its view.
        let judgeable = !was_empty && self.chain.final_msg() != MsgId::root();
        let outcome =
            self.chain
                .apply_finalized(msg, entry.parent, entry_block, &finally_absent_keys);

        // The channel's first finalized block is its genesis: one that is not
        // ours means a different chain, not an offence to step over.
        if was_empty
            && let Some(block) = entry_block
            && let Some(AcceptOutcome::Parked(err) | AcceptOutcome::RetryableFailure(err)) =
                &outcome
        {
            return Err(Error::BlockReconstructionFailed {
                block_id: block.header.block_id,
                source: err.clone(),
            });
        }

        let next = judgeable && self.chain.final_msg() == msg;
        let offence = match (signed, &outcome) {
            (Some(Signed::NotABlock(signer)), _) => Some(faults::not_a_block(msg, signer)),
            (Some(Signed::Block(signer)), Some(outcome)) => {
                faults::block_offence(msg, outcome, next, signer)
            }
            (Some(Signed::Block(_)) | None, _) => None,
        };
        if let Some(offence) = offence {
            self.report_offence(offence).await?;
        }

        let newly_final = self.chain.take_newly_final();
        store_update
            .blocks
            .extend(sequencer_core::new_head_blocks(&self.chain, &head_before));
        if !newly_final.is_empty() {
            // A reconstructed block is finalized, so any deposit it mints is
            // permanently reflected in state (its receipt PDA); drop the
            // pending record backfill may have re-delivered, so the drain
            // stops re-minting.
            store_update.finalized_deposit_records.extend(
                newly_final
                    .iter()
                    .flat_map(|block| block.body.transactions.iter())
                    .filter_map(sequencer_core::extract_bridge_deposit_id),
            );
            store_update.blocks.extend(newly_final.iter().cloned());
            store_update.final_snapshot = self
                .chain
                .final_tip()
                .map(|tip| (self.chain.share_final_state(), BlockMeta::from(&tip)));
            store_update.finalized_up_to = self.chain.final_tip().map(|tip| tip.block_id);
        }

        if let Some(block) = entry_block {
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
                    store_update.zone_anchor = Some(record);
                    store_update.events.extend(events);
                }
                // A block we already hold verbatim needs no replay, but the
                // channel serving it is what makes it irreversible, so its
                // deposits are settled and their records are owed nothing.
                Some(AcceptOutcome::AlreadyApplied | AcceptOutcome::Parked(_))
                    if let Some(stored) = held_final =>
                {
                    store_update.finalized_deposit_records.extend(
                        stored
                            .body
                            .transactions
                            .iter()
                            .filter_map(sequencer_core::extract_bridge_deposit_id),
                    );
                    store_update.zone_anchor = Some(record);
                }
                Some(AcceptOutcome::AlreadyApplied) | None => {}
                Some(AcceptOutcome::Parked(err) | AcceptOutcome::RetryableFailure(err)) => {
                    let err = anyhow::anyhow!(err);
                    warn!(
                        block_id,
                        error = format_args!("{err:#}"),
                        "Finalized channel block does not apply, skipping it"
                    );
                }
            }
        }

        Ok(())
    }
}

/// The key that signed a finalized entry, by what the entry carries.
#[derive(Clone, Copy)]
enum Signed {
    Block(Ed25519PublicKey),
    /// A payload that is not a block, which is an offence, unlike an empty one.
    NotABlock(Ed25519PublicKey),
}
