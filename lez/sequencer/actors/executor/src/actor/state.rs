use std::{collections::HashSet, fmt::Display, future::Future, time::Duration};

use chain_state::{Anchor, AnchorConsistencyCheck, ChainConsistency, ChainState, Tip};
use common::{
    HashType,
    block::{BedrockStatus, Block},
};
use kameo::actor::ActorRef;
use kameo_actors::pubsub::PubSub;
use sequencer_actors_common::SendErrorExt;
use sequencer_bedrock_actor::{
    BedrockActorTrait,
    protocol::{ChannelId, FollowStart, MsgId, Slot},
};
use sequencer_channel_signing_actor::ChannelSigningActor;
use sequencer_core::{
    StakeConfigUpdate,
    config::SequencerConfig,
    storage::{
        ChannelViewRecord, CoreStorage, FinalSnapshotRecord, HeadStateRecord, ZoneAnchorRecord,
        blocks::{BlockRecord, block_deletes, head_writes},
    },
};
use sequencer_slasher_actor::SlasherActorTrait;
use sequencer_storage_actor::{
    encoding::BigEndian,
    protocol::{Get, GetFirst, GetLast},
    utils::Pages,
};
use sharding_pool_actor::ShardingPoolActor;
use tracing::{info, warn};

use crate::{Result, actor::Args, error::Error};

pub mod bootstrapping;
pub mod online;

/// How often a node waiting for its channel's creator checks for the channel, and how long a
/// failed startup read of the channel waits before it is retried.
const CHANNEL_PROBE_DELAY: Duration = Duration::from_secs(2);
/// Retries a failed startup read of the channel gets, so a node that is not ready yet does not fail
/// the start.
const CHANNEL_PROBE_RETRIES: u32 = 29;
/// How many stored blocks one read takes when going over all of them.
const STORED_BLOCKS_PAGE: usize = 64;

pub enum State<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> {
    /// An error or future cancellation happened during [`Self::modify()`].
    Error(String),
    Bootstrapping(bootstrapping::BootstrappingState<S, B, Sl>),
    Online(online::OnlineState<S, B, Sl>),
}

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> State<S, B, Sl> {
    /// The state a start following the channel from `follow_start` begins in.
    pub async fn initialize(
        Args {
            mut config,
            channel_signing_key,
            storage_ref,
            bedrock_pool_ref,
            stake_config_pubsub_ref,
            slasher_ref,
            channel_signer_ref,
        }: Args<S, B, Sl>,
        follow_start: FollowStart,
    ) -> Result<Self> {
        // TODO: Rework this encapsulation cringe
        sequencer_core_metrics::init();

        let channel_id = config.bedrock_config.channel_id;

        if let Some(genesis) = &config.genesis {
            check_startup_channel_params(&genesis.channel_params, &config)?;
        }

        let chain = Self::restore_chain_state(&storage_ref).await?;
        let get_channel_tip_slot = || async {
            bedrock_pool_ref
                .ask(sequencer_bedrock_actor::protocol::GetChannelTipSlot { channel_id })
                .await
                .map_err(SendErrorExt::flatten)
        };
        let mut channel_tip_slot =
            with_retries("Reading the channel tip slot", get_channel_tip_slot).await?;
        if channel_tip_slot.is_none() && config.genesis.is_none() && config.wait_for_channel {
            info!(%channel_id, "Channel does not exist yet, waiting for its creator");
            while channel_tip_slot.is_none() {
                tokio::time::sleep(CHANNEL_PROBE_DELAY).await;
                channel_tip_slot = get_channel_tip_slot().await.unwrap_or_else(|err| {
                    warn!(
                        %channel_id,
                        error = format_args!("{err:#}"),
                        "Failed to check for the channel, still waiting"
                    );
                    None
                });
            }
        }

        let channel_tip_msg_id = with_retries("Reading the channel tip message", || async {
            bedrock_pool_ref
                .ask(sequencer_bedrock_actor::protocol::GetChannelTipMessageId { channel_id })
                .await
                .map_err(SendErrorExt::flatten)
        })
        .await?;

        let local_tip = storage_ref.ask(GetLast::<BlockRecord>::new()).await?;
        let anchor = storage_ref.ask(Get::<ZoneAnchorRecord>::default()).await?;
        let consistency_check = Self::validate(
            channel_tip_slot,
            Self::holds_finalized_block(&storage_ref).await?,
            anchor,
        )?;

        let actors = ActorsBundle {
            storage_ref,
            bedrock_pool_ref,
            stake_config_pubsub_ref,
            slasher_ref,
            channel_signer_ref,
        };

        // A channel only configured so far has the root as its tip message.
        if channel_tip_slot
            .and(channel_tip_msg_id)
            .is_some_and(|msg_id| msg_id != MsgId::root())
        {
            info!("Channel already exists; joining as a non channel creator");
            // The channel's own genesis is replayed instead, so a creator restarting (or a second
            // one) cannot diverge from it.
            config.genesis = None;

            Ok(Self::Bootstrapping(bootstrapping::BootstrappingState::new(
                config,
                chain,
                channel_signing_key,
                consistency_check,
                follow_start,
                actors,
            )))
        } else if channel_tip_slot.is_some() {
            // Creation would configure the channel anew, which an existing one rejects.
            if local_tip.is_none() {
                return Err(Error::ChannelWithoutBlocks(channel_id));
            }
            info!("Channel holds nothing to bootstrap from; resuming on the stored chain");

            Ok(Self::Online(
                online::OnlineState::from_stored_chain(
                    config,
                    chain,
                    channel_signing_key,
                    follow_start.finalized_config,
                    actors,
                )
                .await?,
            ))
        } else {
            if config.genesis.is_none() {
                return Err(Error::MissingGenesisConfig(channel_id));
            }
            info!("Channel does not exist yet; starting it as channel creator");

            Ok(Self::Online(
                online::OnlineState::creating_channel(
                    config,
                    chain,
                    channel_signing_key,
                    follow_start.finalized_config,
                    actors,
                )
                .await?,
            ))
        }
    }

    pub const fn online(&self) -> Result<&online::OnlineState<S, B, Sl>> {
        if let Self::Online(online) = self {
            Ok(online)
        } else {
            Err(Error::NotOnline)
        }
    }

    pub const fn online_mut(&mut self) -> Result<&mut online::OnlineState<S, B, Sl>> {
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
    async fn restore_chain_state(storage_ref: &ActorRef<S>) -> Result<ChainState> {
        let final_snapshot = storage_ref
            .ask(Get::<FinalSnapshotRecord>::default())
            .await?
            .map(FinalSnapshotRecord::into_parts);
        let (final_state, final_tip) = match final_snapshot {
            Some((state, meta)) => (state, Some(Tip::from(meta))),
            // Nothing finalized yet: replay the whole stored chain.
            None => (sequencer_genesis::build_initial_state(), None),
        };

        let mut chain = ChainState::from_final(final_state, final_tip);
        let Some(view) = storage_ref.ask(Get::<ChannelViewRecord>::default()).await? else {
            // Nothing the channel reported yet: the view fills from the
            // channel, or from our bootstrap publishes.
            info!("No stored channel view; starting on the final tier");
            return Ok(chain);
        };
        if let Err(err) = chain.restore_view(&view.bytes) {
            warn!(
                error = %err,
                "Stored channel view does not decode; starting on the final tier"
            );
            trim_stored_head(storage_ref, &chain).await?;
            return Ok(chain);
        }

        let stored_head_state = storage_ref
            .ask(Get::<HeadStateRecord>::default())
            .await?
            .map(HeadStateRecord::into_state);

        // The replayed head must reproduce the persisted state, else store
        // and config disagree (e.g. edited genesis actions). Skipped only when
        // nothing is anchored yet: no final tip and no folded block.
        if chain.head_tip().is_some()
            && let Some(state) = &stored_head_state
            && chain.head_state() != state
        {
            return Err(Error::StorageInconsistency(
                "Persisted state does not match the replayed chain; \
                 reset the store or restore the original config"
                    .to_owned(),
            ));
        }

        Ok(chain)
    }

    /// Whether the store holds a block the channel finalized.
    ///
    /// Blocks are finalized in order, so the first stored block is finalized
    /// whenever any is.
    async fn holds_finalized_block(storage_ref: &ActorRef<S>) -> Result<bool> {
        let first = storage_ref.ask(GetFirst::<BlockRecord>::new()).await?;
        Ok(first.is_some_and(|(_block_id, record)| {
            matches!(record.block.bedrock_status, BedrockStatus::Finalized)
        }))
    }

    /// `committed` is whether this sequencer has already committed blocks to the channel.
    fn validate(
        channel_tip_slot: Option<Slot>,
        committed: bool,
        anchor: Option<ZoneAnchorRecord>,
    ) -> Result<Option<AnchorConsistencyCheck>> {
        // If this sequencer has already committed blocks to the channel, that
        // channel must still exist. A missing channel then means a wiped/rewound
        // Bedrock or a node pointing at a different chain, so refuse to resume
        // onto a foreign channel. Committed takes a block the channel finalized:
        // blocks it never finalized are a store seeded offline, whose chain then
        // creates the channel.
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
struct ActorsBundle<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> {
    storage_ref: ActorRef<S>,
    bedrock_pool_ref: ActorRef<ShardingPoolActor<B, ChannelId>>,
    stake_config_pubsub_ref: ActorRef<PubSub<StakeConfigUpdate>>,
    slasher_ref: ActorRef<Sl>,
    channel_signer_ref: ActorRef<ChannelSigningActor>,
}

/// Refuses a `max_block_size` no block can use, and warns when this node's blocks are too slow
/// to hold a turn.
fn check_startup_channel_params(
    params: &sequencer_core::config::ChannelParams,
    config: &SequencerConfig,
) -> Result<()> {
    if !sequencer_core::config::keeps_turn(params, config.block_create_timeout) {
        warn!(
            block_create_timeout = ?config.block_create_timeout,
            posting_timeout_secs = params.posting_timeout,
            "block_create_timeout is not under posting_timeout: this node loses its turn between \
             its own blocks"
        );
    }
    sequencer_core::config::check_max_block_size(params).map_err(Error::UnsupportedChannelParams)
}

/// Runs `request`, retrying a failure up to [`CHANNEL_PROBE_RETRIES`] times,
/// [`CHANNEL_PROBE_DELAY`] apart.
async fn with_retries<T, E, Fut>(
    what: &str,
    mut request: impl FnMut() -> Fut,
) -> std::result::Result<T, E>
where
    Fut: Future<Output = std::result::Result<T, E>>,
    E: Display,
{
    let mut retries_left = CHANNEL_PROBE_RETRIES;
    loop {
        match request().await {
            Ok(value) => return Ok(value),
            Err(err) if retries_left > 0 => {
                warn!(
                    request = what,
                    delay = ?CHANNEL_PROBE_DELAY,
                    error = format_args!("{err:#}"),
                    "Channel request failed, retrying"
                );
                retries_left = retries_left.saturating_sub(1);
                tokio::time::sleep(CHANNEL_PROBE_DELAY).await;
            }
            Err(err) => return Err(err),
        }
    }
}

/// Deletes the stored blocks above the final tier of `chain` that its head does not hold, then
/// writes its head state and view. Its head holds only stored blocks.
///
/// Reads the blocks a page at a time, and writes the view last, so a restart midway does not find
/// the new view over blocks left to delete.
async fn trim_stored_head<S: CoreStorage>(
    storage_ref: &ActorRef<S>,
    chain: &ChainState,
) -> Result<()> {
    let held: HashSet<HashType> = chain.head_blocks().map(|block| block.header.hash).collect();
    let first_above = chain
        .final_tip()
        .map(|tip| BigEndian::new(&tip.block_id.saturating_add(1)));
    let mut pages =
        Pages::<_, BlockRecord>::new(storage_ref, first_above, None, STORED_BLOCKS_PAGE);
    while let Some(records) = pages.next().await? {
        let dropped: Vec<Block> = records
            .into_iter()
            .map(|(_block_id, record)| record.block)
            .filter(|block| !held.contains(&block.header.hash))
            .collect();
        if !dropped.is_empty() {
            storage_ref.ask(block_deletes(&dropped)).await?;
        }
    }
    storage_ref.ask(head_writes(chain)).await?;
    Ok(())
}
