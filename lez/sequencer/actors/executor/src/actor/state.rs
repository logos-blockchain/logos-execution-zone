use chain_state::{Anchor, AnchorConsistencyCheck, ChainConsistency, ChainState, Tip};
use kameo::actor::ActorRef;
use kameo_actors::pubsub::PubSub;
use log::{info, warn};
use sequencer_actors_common::SendErrorExt;
use sequencer_bedrock_actor::{
    BedrockActorTrait,
    protocol::{ChannelId, ChannelSeq, Checkpoint, Ed25519Key, MsgId, SerializeOp as _, Slot},
};
use sequencer_channel_config_actor::ChannelConfigActor;
use sequencer_core::{StakeConfigKeys, config::SequencerConfig};
use sequencer_slasher_actor::SlasherActor;
use sequencer_storage_actor::{
    StorageActorTrait,
    protocol::{ZoneAnchorRecord, ZoneCheckpointRecord},
};
use sharding_pool_actor::ShardingPoolActor;

use crate::{Result, error::Error};

pub mod bootstrapping;
pub mod online;

#[expect(
    clippy::large_enum_variant,
    reason = "Bootstrapping and Online states have the same size and None is never accessible"
)]
pub enum State<S: StorageActorTrait, B: BedrockActorTrait> {
    /// An error or future cancellation happened during [`Self::modify()`].
    Error(String),
    Bootstrapping(bootstrapping::BootstrappingState<S, B>),
    Online(online::OnlineState<S, B>),
}

impl<S: StorageActorTrait, B: BedrockActorTrait> State<S, B> {
    pub async fn initialize(
        config: SequencerConfig,
        bedrock_signing_key: Ed25519Key,
        storage_ref: ActorRef<S>,
        bedrock_pool_ref: ActorRef<ShardingPoolActor<B, ChannelId>>,
        stake_config_keys_pubsub_ref: ActorRef<PubSub<StakeConfigKeys>>,
        slasher_ref: ActorRef<SlasherActor<S>>,
        config_manager_ref: ActorRef<ChannelConfigActor>,
    ) -> Result<Self> {
        // TODO: Rework this encapsulation cringe
        sequencer_core_metrics::init();

        let channel_id = config.bedrock_config.channel_id;

        let chain = Self::restore_chain_state(&config, &storage_ref).await?;
        let channel_tip_slot = bedrock_pool_ref
            .ask(sequencer_bedrock_actor::protocol::GetChannelTipSlot { channel_id })
            .await
            .map_err(SendErrorExt::flatten)?;

        let channel_tip_msg_id = bedrock_pool_ref
            .ask(sequencer_bedrock_actor::protocol::GetChannelTipMessageId { channel_id })
            .await
            .map_err(SendErrorExt::flatten)?;

        let local_tip = storage_ref
            .ask(sequencer_storage_actor::protocol::GetLatestBlockMeta)
            .await?;
        let anchor = storage_ref
            .ask(sequencer_storage_actor::protocol::GetZoneAnchor)
            .await?;
        let consistency_check =
            Self::validate(channel_tip_slot, local_tip.is_some(), anchor, &storage_ref).await?;

        let actors = ActorsBundle {
            storage_ref,
            bedrock_pool_ref,
            stake_config_keys_pubsub_ref,
            slasher_ref,
            config_manager_ref,
        };

        // A channel only configured so far has the root as its tip message.
        if let Some(bootstrap_to) = channel_tip_slot
            .and(channel_tip_msg_id)
            .filter(|msg_id| *msg_id != MsgId::root())
        {
            info!("Channel already exists; joining as a non channel creator");

            Ok(Self::Bootstrapping(bootstrapping::BootstrappingState::new(
                config,
                chain,
                bedrock_signing_key,
                consistency_check,
                bootstrap_to,
                actors,
            )))
        } else if channel_tip_slot.is_some() && local_tip.is_some() {
            info!("Channel holds nothing to bootstrap from; resuming on the stored chain");

            Ok(Self::Online(
                online::OnlineState::from_stored_chain(config, chain, bedrock_signing_key, actors)
                    .await?,
            ))
        } else {
            info!("Channel does not exist yet; starting it as channel creator");

            Ok(Self::Online(
                online::OnlineState::creating_channel(config, chain, bedrock_signing_key, actors)
                    .await?,
            ))
        }
    }

    pub const fn online(&self) -> Result<&online::OnlineState<S, B>> {
        if let Self::Online(online) = self {
            Ok(online)
        } else {
            Err(Error::NotOnline)
        }
    }

    /// Modify internal state by value.
    ///
    /// In case of `f` failing or cancelling a [`Self::Error`] will be set as the current state.
    pub async fn modify<FN, F>(&mut self, f: FN) -> Result<()>
    where
        FN: FnOnce(Self) -> F,
        F: std::future::Future<Output = Result<Self>>,
    {
        let current = std::mem::replace(
            self,
            Self::Error("State modification future cancelled".to_owned()),
        );
        match f(current).await {
            Ok(new_state) => {
                *self = new_state;
                Ok(())
            }
            Err(err) => {
                let chain =
                    std::iter::successors(Some::<&dyn std::error::Error>(&err), |err| err.source())
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(": ");
                *self = Self::Error(format!("State modification failed: {chain}"));
                Err(err)
            }
        }
    }

    /// Rebuilds the two-tier [`ChainState`]: the final tier from the persisted
    /// final snapshot (pre-genesis state when absent), the head by folding the
    /// persisted channel view over it.
    async fn restore_chain_state(
        config: &SequencerConfig,
        storage_ref: &ActorRef<S>,
    ) -> Result<ChainState> {
        let final_snapshot = storage_ref
            .ask(sequencer_storage_actor::protocol::GetFinalSnapshot)
            .await?;
        let (final_state, final_tip) = match final_snapshot {
            Some((state, meta)) => (state, Some(Tip::from(meta))),
            // Nothing finalized yet: replay the whole stored chain.
            None => (
                sequencer_genesis::build_initial_state(config.cross_zone.is_some()),
                None,
            ),
        };

        let mut chain = ChainState::from_final(final_state, final_tip);
        let view = storage_ref
            .ask(sequencer_storage_actor::protocol::GetChannelViewBytes)
            .await?;
        let restored = view.is_some_and(|bytes| {
            chain
                .restore_view(&bytes)
                .inspect_err(|err| warn!("Stored channel view does not decode: {err}"))
                .is_ok()
        });
        if !restored {
            // Nothing the channel reported yet: the view fills from the
            // channel, or from our bootstrap publishes.
            info!("No stored channel view; starting on the final tier");
            return Ok(chain);
        }

        let stored_head_state = storage_ref
            .ask(sequencer_storage_actor::protocol::GetLeeState)
            .await?;

        // The replayed head must reproduce the persisted state, else store
        // and config disagree (e.g. edited genesis actions). Skipped only when
        // nothing is anchored yet: no final tip and no folded block.
        if chain.head_tip().is_some()
            && let Some(state) = &stored_head_state
            && chain.head_state() != state
        {
            return Err(Error::StorageInconsistency(
                "Persisted state does not match the replayed chain; \
                 reset the store or restore the original config \
                 (cross_zone presence included)"
                    .to_owned(),
            ));
        }

        Ok(chain)
    }

    async fn validate(
        channel_tip_slot: Option<Slot>,
        holds_blocks: bool,
        anchor: Option<ZoneAnchorRecord>,
        storage_ref: &ActorRef<S>,
    ) -> Result<Option<AnchorConsistencyCheck>> {
        // If this sequencer has already committed blocks to the channel, that
        // channel must still exist. A missing channel then means a wiped/rewound
        // Bedrock or a node pointing at a different chain, so refuse to resume
        // onto a foreign channel. Committed takes both stored blocks and a
        // checkpoint from an earlier run: blocks alone are a store seeded
        // offline, whose chain then creates the channel.
        let committed = holds_blocks
            && storage_ref
                .ask(sequencer_storage_actor::protocol::GetZoneCheckpoint)
                .await?
                .is_some();
        if committed && channel_tip_slot.is_none() {
            return Err(Error::StoreAndChannelDivergence(
                chain_state::ChainMismatch::ChannelMissing,
            ));
        }

        // With a recorded anchor, probe the channel for positive evidence of a
        // different chain: the frontier upfront (a missing/behind channel serves
        // no messages to scan), then the anchor block as messages stream in.
        let consistency_check = anchor.map(|record| {
            let mut check = AnchorConsistencyCheck::new(Anchor::new(
                Slot::from(record.slot),
                Some((record.block_id, record.hash)),
            ));
            check.check_frontier(channel_tip_slot);
            check
        });

        if let Some(ChainConsistency::Inconsistent(mismatch)) = consistency_check
            .as_ref()
            .and_then(AnchorConsistencyCheck::verdict)
        {
            return Err(Error::StoreAndChannelDivergence(mismatch.clone()));
        }

        Ok(consistency_check)
    }
}

#[expect(
    clippy::struct_field_names,
    reason = "Every field is an actor ref, named the way they are everywhere else"
)]
struct ActorsBundle<S: StorageActorTrait, B: BedrockActorTrait> {
    storage_ref: ActorRef<S>,
    bedrock_pool_ref: ActorRef<ShardingPoolActor<B, ChannelId>>,
    stake_config_keys_pubsub_ref: ActorRef<PubSub<StakeConfigKeys>>,
    slasher_ref: ActorRef<SlasherActor<S>>,
    config_manager_ref: ActorRef<ChannelConfigActor>,
}

/// The checkpoint record `checkpoint` and `seq` persist as.
fn checkpoint_record(checkpoint: &Checkpoint, seq: ChannelSeq) -> Result<ZoneCheckpointRecord> {
    Ok(ZoneCheckpointRecord {
        bytes: checkpoint
            .to_bytes()
            .map_err(|err| Error::CheckpointEncodingFailed(err.into()))?
            .into(),
        seq: seq.into_inner(),
    })
}
