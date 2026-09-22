use chain_state::{Anchor, AnchorConsistencyCheck, ChainConsistency, ChainState, Tip};
use kameo::actor::ActorRef;
use log::info;
use sequencer_actors_common::SendErrorExt;
use sequencer_bedrock_actor::{
    BedrockActorTrait,
    protocol::{ChannelId, Checkpoint, DeserializeOp as _, Ed25519Key, MsgId, Slot},
};
use sequencer_core::config::SequencerConfig;
use sequencer_storage_actor::StorageActorTrait;
use sharding_pool_actor::ShardingPoolActor;

use crate::{Result, error::Error};

pub mod bootstrapping;
mod genesis;
pub mod online;

pub enum State<S: StorageActorTrait, B: BedrockActorTrait> {
    /// Unreachable state used in [`Self::modify`].
    None,
    Bootstrapping(bootstrapping::BootstrappingState<S, B>),
    Online(online::OnlineState<S, B>),
}

impl<S: StorageActorTrait, B: BedrockActorTrait> State<S, B> {
    pub async fn initialize(
        config: SequencerConfig,
        bedrock_signing_key: Ed25519Key,
        storage_ref: ActorRef<S>,
        bedrock_pool_ref: ActorRef<ShardingPoolActor<B, ChannelId>>,
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

        let consistency_check = Self::validate(channel_tip_slot, &storage_ref).await?;

        if let Some((channel_tip_slot, channel_tip_msg_id)) =
            channel_tip_slot.zip(channel_tip_msg_id)
        {
            info!("Channel already exists; joining as a non channel creator");

            let bootstrap_to = bootstrapping::Tip {
                msg_id: channel_tip_msg_id,
                slot: channel_tip_slot,
            };
            Ok(Self::Bootstrapping(bootstrapping::BootstrappingState::new(
                config,
                chain,
                bedrock_signing_key,
                consistency_check,
                bootstrap_to,
                storage_ref,
                bedrock_pool_ref,
            )))
        } else {
            info!("Channel does not exist yet; starting it as channel creator");

            Ok(Self::Online(
                online::OnlineState::from_empty_chain(
                    config,
                    chain,
                    bedrock_signing_key,
                    storage_ref,
                    bedrock_pool_ref,
                )
                .await?,
            ))
        }
    }

    pub fn online(&self) -> Result<&online::OnlineState<S, B>> {
        if let State::Online(online) = self {
            Ok(online)
        } else {
            Err(Error::NotOnline)
        }
    }

    pub fn online_mut(&mut self) -> Result<&mut online::OnlineState<S, B>> {
        if let State::Online(online) = self {
            Ok(online)
        } else {
            Err(Error::NotOnline)
        }
    }

    /// Modify internal state by value.
    ///
    /// Requires closure to be infallible to never leave the state in [`State::None`].
    pub async fn modify<FN, F>(&mut self, f: FN)
    where
        FN: FnOnce(Self) -> F,
        F: std::future::Future<Output = Self>,
    {
        let current = std::mem::replace(self, State::None);
        let new_state = f(current).await;
        *self = new_state;
    }

    /// Rebuilds the two-tier [`ChainState`]: the final tier from the persisted
    /// final snapshot (pre-genesis state when absent), the head tier by replaying
    /// every stored block above it, so a post-restart orphan can still revert.
    async fn restore_chain_state(
        config: &SequencerConfig,
        storage_ref: &ActorRef<S>,
    ) -> Result<ChainState> {
        let final_snapshot = storage_ref
            .ask(sequencer_storage_actor::protocol::GetFinalSnapshot)
            .await
            .expect("Failed to read final snapshot from store");
        let (final_state, final_tip) = match final_snapshot {
            Some((state, meta)) => (state, Some(Tip::from(meta))),
            // Nothing finalized yet: replay the whole stored chain.
            None => (genesis::build_initial_state(config), None),
        };
        let boundary = final_tip.as_ref().map_or(0, |tip| tip.block_id);

        let mut head_blocks = storage_ref
            .ask(sequencer_storage_actor::protocol::GetAllBlocks)
            .await
            .expect("Failed to read blocks from store while restoring chain state")
            .into_iter()
            .filter(|block| block.header.block_id > boundary)
            .collect::<Vec<_>>();
        head_blocks.sort_unstable_by_key(|block| block.header.block_id);

        let mut chain = ChainState::from_final(final_state, final_tip);
        for block in head_blocks {
            let block_id = block.header.block_id;
            chain
                .restore_head_block(block)
                .map_err(|err| Error::BlockReconstructionFailed {
                    block_id,
                    source: err,
                })?;
        }
        if let Some(cursor) = storage_ref
            .ask(sequencer_storage_actor::protocol::GetChannelCursor)
            .await?
        {
            chain.restore_cursor(MsgId::from(cursor));
        } else if let Some(checkpoint) = zone_checkpoint(storage_ref).await? {
            // A store from before the cursor cell existed still pins: the sdk
            // checkpoint carries the channel tip it was built on.
            chain.restore_cursor(checkpoint.last_msg_id);
        } else {
            // Nothing followed yet; the bootstrap publishes seed the pin.
        }

        let stored_head_state = storage_ref
            .ask(sequencer_storage_actor::protocol::GetLeeState)
            .await?;

        // The replayed head must reproduce the persisted state, else store
        // and config disagree (e.g. edited genesis actions).
        if let Some(state) = &stored_head_state {
            if chain.head_state() != state {
                return Err(Error::StorageInconsistency(
                    "Persisted state does not match the replayed chain; \
                     reset the store or restore the original config \
                     (cross_zone presence included)"
                        .to_owned(),
                ));
            }
        }

        Ok(chain)
    }

    async fn validate(
        channel_tip_slot: Option<Slot>,
        storage_ref: &ActorRef<S>,
    ) -> Result<Option<AnchorConsistencyCheck>> {
        // If this sequencer has already committed blocks to the channel, that
        // channel must still exist. A missing channel then means a wiped/rewound
        // Bedrock or a node pointing at a different chain, so refuse to resume
        // onto a foreign channel.
        let local_tip = storage_ref
            .ask(sequencer_storage_actor::protocol::GetLatestBlockMeta)
            .await?
            .map(|meta| meta.id);
        if local_tip.is_some() && channel_tip_slot.is_none() {
            return Err(Error::StoreAndChannelDivergence(
                chain_state::ChainMismatch::ChannelMissing,
            ));
        }

        // With a recorded anchor, probe the channel for positive evidence of a
        // different chain: the frontier upfront (a missing/behind channel serves
        // no messages to scan), then the anchor block as messages stream in.
        let anchor_record = storage_ref
            .ask(sequencer_storage_actor::protocol::GetZoneAnchor)
            .await?;
        let consistency_check = anchor_record.map(|record| {
            let anchor = Anchor::new(
                Slot::from(record.slot),
                Some((record.block_id, record.hash)),
            );
            let mut check = AnchorConsistencyCheck::new(anchor);
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

/// The persisted zone-sdk checkpoint, decoded from the encoding
/// [`checkpoint_bytes`] writes.
async fn zone_checkpoint<S: StorageActorTrait>(
    storage_ref: &ActorRef<S>,
) -> Result<Option<Checkpoint>> {
    let Some(bytes) = storage_ref
        .ask(sequencer_storage_actor::protocol::GetZoneCheckpointBytes)
        .await?
    else {
        return Ok(None);
    };
    let checkpoint = Checkpoint::from_bytes(&bytes)
        .map_err(|err| Error::CheckpointEncodingFailed(err.into()))?;
    Ok(Some(checkpoint))
}
