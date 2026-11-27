use chain_state::{ChainState, ChannelEntry};
use common::{
    block::{BedrockStatus, Block},
    transaction::LeeTransaction,
};
use kameo::actor::ActorRef;
use mempool::{MemPool, MemPoolHandle};
use sequencer_actors_common::SendErrorExt;
use sequencer_bedrock_actor::{
    BedrockActorTrait,
    protocol::{
        ChannelId, Ed25519Key, Ed25519PublicKey, MsgId, PendingBlock, PublishOutcome, Slot,
    },
};
use sequencer_core::{
    SequencerCore, TransactionOrigin,
    config::SequencerConfig,
    storage::{
        CoreStorage, HeadStateRecord,
        blocks::{BlockRecord, StoredChain, chain_writes},
    },
};
use sequencer_slasher_actor::SlasherActorTrait;
use sequencer_storage_actor::{
    protocol::{Get, GetLast, WriteBatch},
    utils::Pages,
};
use sharding_pool_actor::ShardingPoolActor;
use tracing::info;

use self::turn::Turn;
use crate::{
    Result,
    actor::state::{
        ActorsBundle, STORED_BLOCKS_PAGE, bootstrapping, check_startup_channel_params,
        trim_stored_head,
    },
    error::Error,
};

#[cfg(test)]
mod tests;
mod turn;

pub struct OnlineState<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> {
    sequencer: SequencerCore<S, B, Sl>,
    mempool_handle: MemPoolHandle<(TransactionOrigin, LeeTransaction)>,
    /// Whose turn it is to write: blocks are only produced in ours.
    turn: Turn,
}

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> OnlineState<S, B, Sl> {
    /// Goes online once bootstrapping replayed the channel's finalized history.
    pub(super) async fn from_bootstrapping(
        bootstrapping_state: bootstrapping::BootstrappingState<S, B, Sl>,
    ) -> Result<Self> {
        Self::start(
            true,
            bootstrapping_state.finalized_config,
            bootstrapping_state.config,
            bootstrapping_state.chain,
            bootstrapping_state.channel_signing_key,
            bootstrapping_state.actors,
        )
        .await
    }

    pub(super) async fn from_stored_chain(
        config: SequencerConfig,
        chain: ChainState,
        channel_signing_key: Ed25519Key,
        finalized_config: MsgId,
        actors: ActorsBundle<S, B, Sl>,
    ) -> Result<Self> {
        Self::start(
            true,
            finalized_config,
            config,
            chain,
            channel_signing_key,
            actors,
        )
        .await
    }

    /// Creates the channel, inscribing the stored chain onto it, or a new genesis when the store
    /// holds none.
    pub(super) async fn creating_channel(
        config: SequencerConfig,
        chain: ChainState,
        channel_signing_key: Ed25519Key,
        finalized_config: MsgId,
        actors: ActorsBundle<S, B, Sl>,
    ) -> Result<Self> {
        Self::start(
            false,
            finalized_config,
            config,
            chain,
            channel_signing_key,
            actors,
        )
        .await
    }

    pub const fn sequencer(&self) -> &SequencerCore<S, B, Sl> {
        &self.sequencer
    }

    pub const fn sequencer_mut(&mut self) -> &mut SequencerCore<S, B, Sl> {
        &mut self.sequencer
    }

    pub const fn mempool_handle(&self) -> &MemPoolHandle<(TransactionOrigin, LeeTransaction)> {
        &self.mempool_handle
    }

    pub const fn is_our_turn(&self) -> bool {
        self.turn.is_ours()
    }

    pub fn update_turn(&mut self, our_turn_to_write: bool, starting_slot: Option<Slot>) {
        if self.turn.update(our_turn_to_write, starting_slot) {
            sequencer_executor_actor_metrics::increment_turns_to_write_total();
        }
        sequencer_executor_actor_metrics::record_turn_to_write(self.turn.is_ours());
    }

    /// Starts producing on `chain`, whose last final config entry is `finalized_config`.
    async fn start(
        channel_exists: bool,
        finalized_config: MsgId,
        config: SequencerConfig,
        mut chain: ChainState,
        channel_signing_key: Ed25519Key,
        actors: ActorsBundle<S, B, Sl>,
    ) -> Result<Self> {
        let ActorsBundle {
            storage_ref,
            bedrock_pool_ref,
            stake_config_pubsub_ref,
            slasher_ref,
            channel_signer_ref,
        } = actors;

        let own_sequencer_key =
            sequencer_stake_core::SequencerKey::new(channel_signing_key.public_key().to_bytes())
                .ok_or(Error::InvalidSequencerKey)?;

        let pending_blocks = bedrock_pool_ref
            .ask(
                sequencer_bedrock_actor::protocol::InitializeChannelPublisher {
                    channel_id: config.bedrock_config.channel_id,
                    channel_signing_key: channel_signing_key.clone(),
                    funding_pk: config
                        .load_funding_public_key()
                        .map_err(Error::FundingKeyUnavailable)?,
                    priority_fee_percent: config.bedrock_config.priority_fee_percent,
                    resubmit_interval: config.retry_pending_blocks_timeout,
                    stale_refund_slots: config.bedrock_config.stale_refund_slots,
                },
            )
            .await
            .map_err(SendErrorExt::flatten)?;

        if channel_exists {
            Self::recover_pending_blocks(&mut chain, &storage_ref, pending_blocks).await?;
        } else {
            let holds_blocks = storage_ref
                .ask(GetLast::<BlockRecord>::new())
                .await?
                .is_some();
            if holds_blocks {
                Self::create_channel_from_store(
                    &mut chain,
                    &config,
                    own_sequencer_key,
                    &storage_ref,
                    &bedrock_pool_ref,
                )
                .await?;
            } else {
                Self::create_channel_with_genesis(
                    &mut chain,
                    &config,
                    own_sequencer_key,
                    &storage_ref,
                    &bedrock_pool_ref,
                )
                .await?;
            }
        }

        // A joining node's config carries no channel params, so check the finalized chain's.
        if let Some(params) =
            sequencer_core::committee_discovery::channel_params(chain.final_state())
        {
            check_startup_channel_params(&params, &config)?;
        }

        let state = storage_ref
            .ask(Get::<HeadStateRecord>::default())
            .await?
            .ok_or_else(|| {
                Error::StorageInconsistency(
                    "State was written either during bootstrapping or genesis creation \
                     but could not be retrieved"
                        .to_owned(),
                )
            })?
            .into_state();

        let stake_config = sequencer_core::committee_discovery::read_config(&state)
            .ok_or(Error::SequencerStakeConfigNotFound)?;

        // print your own sequencer entry,
        // allowing to see that fees land to your account on explorer
        if let Some(reward_account) = stake_config
            .entries
            .get(&own_sequencer_key)
            .map(|entry| entry.account_id)
        {
            info!(%reward_account, "Producer reward account (stake ownership)");
        }

        let mempool = MemPool::new(config.mempool_max_size);
        let mempool_handle = mempool.handle().clone();

        let is_our_turn = bedrock_pool_ref
            .ask(sequencer_bedrock_actor::protocol::CheckIsOurTurn {
                channel_id: config.bedrock_config.channel_id,
            })
            .await
            .map_err(SendErrorExt::flatten)?;
        sequencer_executor_actor_metrics::record_turn_to_write(is_our_turn);
        if is_our_turn {
            sequencer_executor_actor_metrics::increment_turns_to_write_total();
        }

        let sequencer = SequencerCore::new(
            config,
            mempool,
            chain,
            finalized_config,
            channel_signing_key,
            storage_ref,
            bedrock_pool_ref,
            stake_config_pubsub_ref,
            slasher_ref,
            channel_signer_ref,
        )
        .await
        .map_err(Error::SequencerStartFailed)?;

        Ok(Self {
            mempool_handle,
            turn: Turn::new(is_our_turn),
            sequencer,
        })
    }

    /// Records the `pending_blocks` the store does not hold yet, so production chains on them.
    async fn recover_pending_blocks(
        chain: &mut ChainState,
        storage_ref: &ActorRef<S>,
        pending_blocks: Vec<PendingBlock>,
    ) -> Result<()> {
        for PendingBlock { block, outcome } in pending_blocks {
            sequencer_core::record_published_block(chain, storage_ref, outcome, block)
                .await
                .map_err(Error::SequencerStartFailed)?;
        }
        Ok(())
    }

    async fn create_channel_with_genesis(
        chain: &mut ChainState,
        config: &SequencerConfig,
        own_sequencer_key: sequencer_stake_core::SequencerKey,
        storage_ref: &ActorRef<S>,
        bedrock_pool_ref: &ActorRef<ShardingPoolActor<B, ChannelId>>,
    ) -> Result<()> {
        let genesis_spec = config
            .genesis_spec(Some(own_sequencer_key))
            .map_err(Error::InvalidGenesisConfig)?;

        let (block, state, events) = sequencer_genesis::genesis_block_and_state(&genesis_spec);

        let outcome =
            Self::inscribe_genesis(&block, &state, config, own_sequencer_key, bedrock_pool_ref)
                .await?;

        let block_id = block.header.block_id;
        let stored = StoredChain::of(chain);
        chain.apply_conflict(vec![published_entry(&outcome, &block)]);
        storage_ref
            .ask(WriteBatch(chain_writes(
                &stored,
                chain,
                &[],
                vec![(block_id, events)],
            )))
            .await?;

        Ok(())
    }

    /// Inscribes the pending blocks the store holds, genesis first, onto a channel that does not
    /// exist yet.
    async fn create_channel_from_store(
        chain: &mut ChainState,
        config: &SequencerConfig,
        own_sequencer_key: sequencer_stake_core::SequencerKey,
        storage_ref: &ActorRef<S>,
        bedrock_pool_ref: &ActorRef<ShardingPoolActor<B, ChannelId>>,
    ) -> Result<()> {
        let mut published = Vec::new();
        let mut pages = Pages::<_, BlockRecord>::new(storage_ref, None, None, STORED_BLOCKS_PAGE);
        while let Some(records) = pages.next().await? {
            let pending = records
                .into_iter()
                .map(|(_block_id, record)| record.block)
                .filter(|block| matches!(block.bedrock_status, BedrockStatus::Pending));
            for block in pending {
                let outcome = if published.is_empty() {
                    Self::inscribe_stored_genesis(
                        &block,
                        config,
                        own_sequencer_key,
                        storage_ref,
                        bedrock_pool_ref,
                    )
                    .await?
                } else {
                    bedrock_pool_ref
                        .ask(sequencer_bedrock_actor::protocol::PublishBlock {
                            channel_id: config.bedrock_config.channel_id,
                            block: block.clone(),
                            withdrawals: Vec::new(),
                            parent: None,
                        })
                        .await
                        .map_err(SendErrorExt::flatten)?
                };
                published.push(published_entry(&outcome, &block));
            }
        }
        if published.is_empty() {
            return Ok(());
        }

        chain.apply_conflict(published);
        trim_stored_head(storage_ref, chain).await
    }

    /// Inscribes `genesis`, the first pending block the store holds, as the first entry of a new
    /// channel.
    async fn inscribe_stored_genesis(
        genesis: &Block,
        config: &SequencerConfig,
        own_sequencer_key: sequencer_stake_core::SequencerKey,
        storage_ref: &ActorRef<S>,
        bedrock_pool_ref: &ActorRef<ShardingPoolActor<B, ChannelId>>,
    ) -> Result<PublishOutcome> {
        if genesis.header.block_id != lee::GENESIS_BLOCK_ID {
            return Err(Error::StorageInconsistency(format!(
                "The first pending block {} is not genesis, but the channel does not exist",
                genesis.header.block_id
            )));
        }
        let genesis_state = storage_ref
            .ask(Get::<HeadStateRecord>::default())
            .await?
            .ok_or_else(|| {
                Error::StorageInconsistency("The store holds blocks but no state".to_owned())
            })?
            .into_state();
        Self::inscribe_genesis(
            genesis,
            &genesis_state,
            config,
            own_sequencer_key,
            bedrock_pool_ref,
        )
        .await
    }

    /// Inscribes `genesis` as the first entry of a new channel.
    async fn inscribe_genesis(
        genesis: &Block,
        genesis_state: &lee::V03State,
        config: &SequencerConfig,
        own_sequencer_key: sequencer_stake_core::SequencerKey,
        bedrock_pool_ref: &ActorRef<ShardingPoolActor<B, ChannelId>>,
    ) -> Result<PublishOutcome> {
        let channel_id = config.bedrock_config.channel_id;

        // The channel is born holding only its creator's key, so a configured
        // founding set is applied by the same tx that writes genesis; the
        // committee is never observable without it.
        let founding_committee = config.genesis.as_ref().and_then(|genesis_config| {
            sequencer_genesis::founding_committee(&genesis_config.actions, own_sequencer_key)
        });
        let outcome = match founding_committee {
            Some(keys) => {
                // The account, not the config: the genesis tx already wrote the
                // configured values there, and the account is what every later
                // update reads, so creation must not have a second source.
                let channel_params =
                    sequencer_core::committee_discovery::channel_params(genesis_state)
                        .ok_or(Error::SequencerStakeConfigNotFound)?;
                let configuration_threshold =
                    sequencer_core::committee_discovery::channel_config_threshold(keys.len());
                let keys = keys
                    .into_iter()
                    .map(|key| {
                        Ed25519PublicKey::from_bytes(&key.to_bytes())
                            .expect("sequencer key was decoded from a valid Ed25519 public key")
                    })
                    .collect();
                bedrock_pool_ref
                    .ask(sequencer_bedrock_actor::protocol::CreateChannel {
                        channel_id,
                        genesis: genesis.clone(),
                        keys,
                        channel_params,
                        configuration_threshold,
                        transfer_threshold: configuration_threshold,
                    })
                    .await
                    .map_err(SendErrorExt::flatten)?
            }
            None => bedrock_pool_ref
                .ask(sequencer_bedrock_actor::protocol::PublishBlock {
                    channel_id,
                    block: genesis.clone(),
                    withdrawals: Vec::new(),
                    parent: None,
                })
                .await
                .map_err(SendErrorExt::flatten)?,
        };

        Ok(outcome)
    }
}

/// The view entry a publish of `block` produced; our own blocks are trusted for every key they
/// name.
fn published_entry(outcome: &PublishOutcome, block: &Block) -> ChannelEntry {
    ChannelEntry {
        msg: outcome.this_msg,
        parent: outcome.parent,
        block: Some(block.clone()),
        finally_absent_keys: chain_state::full_stake_releases::finalize_unstake_keys(block),
        final_slot: None,
    }
}
