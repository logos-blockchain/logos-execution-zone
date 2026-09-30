use std::sync::Arc;

use chain_state::ChainState;
use common::transaction::LeeTransaction;
use kameo::actor::ActorRef;
use log::info;
use mempool::{MemPool, MemPoolHandle};
use sequencer_actors_common::SendErrorExt;
use sequencer_bedrock_actor::{
    BedrockActorTrait,
    protocol::{ChannelId, Ed25519Key, Ed25519PublicKey, SerializeOp as _},
};
use sequencer_core::{SequencerCore, TransactionOrigin, config::SequencerConfig};
use sequencer_storage_actor::{StorageActorTrait, protocol::AtomicUpdate};
use sharding_pool_actor::ShardingPoolActor;

use crate::{
    Result,
    actor::state::{ActorsBundle, bootstrapping, zone_checkpoint},
    error::Error,
};

pub struct OnlineState<S: StorageActorTrait, B: BedrockActorTrait> {
    sequencer: SequencerCore<S, B>,
    mempool_handle: MemPoolHandle<(TransactionOrigin, LeeTransaction)>,
    /// Is it our turn to produce a blocks.
    is_our_turn: bool,
    // TODO: Remove this field
    background_tasks: sequencer_core::task_group::TaskGroup,
}

impl<S: StorageActorTrait, B: BedrockActorTrait> OnlineState<S, B> {
    pub(super) async fn from_bootstrapping(
        bootstrapping_state: bootstrapping::BootstrappingState<S, B>,
    ) -> Result<Self> {
        Self::start(
            true,
            bootstrapping_state.config,
            bootstrapping_state.chain,
            bootstrapping_state.bedrock_signing_key,
            bootstrapping_state.actors,
        )
        .await
    }

    pub(super) async fn from_empty_chain(
        config: SequencerConfig,
        chain: ChainState,
        bedrock_signing_key: Ed25519Key,
        actors: ActorsBundle<S, B>,
    ) -> Result<Self> {
        Self::start(false, config, chain, bedrock_signing_key, actors).await
    }

    pub const fn sequencer(&self) -> &SequencerCore<S, B> {
        &self.sequencer
    }

    pub const fn sequencer_mut(&mut self) -> &mut SequencerCore<S, B> {
        &mut self.sequencer
    }

    pub const fn mempool_handle(&self) -> &MemPoolHandle<(TransactionOrigin, LeeTransaction)> {
        &self.mempool_handle
    }

    pub const fn is_our_turn(&self) -> bool {
        self.is_our_turn
    }

    pub const fn set_is_our_turn(&mut self, is_our_turn: bool) {
        self.is_our_turn = is_our_turn;
    }

    pub const fn background_tasks(&self) -> &sequencer_core::task_group::TaskGroup {
        &self.background_tasks
    }

    async fn start(
        channel_exists: bool,
        config: SequencerConfig,
        mut chain: ChainState,
        bedrock_signing_key: Ed25519Key,
        actors: ActorsBundle<S, B>,
    ) -> Result<Self> {
        let ActorsBundle {
            storage_ref,
            bedrock_pool_ref,
            accredited_keys_pubsub_ref,
            slasher_prepared,
        } = actors;

        let initial_checkpoint = zone_checkpoint(&storage_ref).await?;

        let own_sequencer_key =
            sequencer_stake_core::SequencerKey::new(bedrock_signing_key.public_key().to_bytes())
                .ok_or(Error::InvalidSequencerKey)?;

        bedrock_pool_ref
            .ask(
                sequencer_bedrock_actor::protocol::InitializeChannelPublisher {
                    channel_id: config.bedrock_config.channel_id,
                    bedrock_signing_key: bedrock_signing_key.clone(),
                    funding_pk: config.bedrock_config.funding_key,
                    priority_fee_percent: config.bedrock_config.priority_fee_percent,
                    initial_checkpoint,
                    resubmit_interval: config.retry_pending_blocks_timeout,
                },
            )
            .await
            .map_err(SendErrorExt::flatten)?;

        if !channel_exists {
            Self::create_channel_with_genesis(
                &mut chain,
                &config,
                own_sequencer_key,
                &storage_ref,
                &bedrock_pool_ref,
            )
            .await?;
        }

        let state = storage_ref
            .ask(sequencer_storage_actor::protocol::GetLeeState)
            .await?
            .ok_or_else(|| {
                Error::StorageInconsistency(
                    "State was written either during bootstrapping or genesis creation \
                     but could not be retrieved"
                        .to_owned(),
                )
            })?;

        let stake_config = sequencer_core::committee_discovery::read_config(&state)
            .ok_or(Error::SequencerStakeConfigNotFound)?;

        // print your own sequencer entry,
        // allowing to see that fees land to your account on explorer
        if let Some(reward_account) = stake_config
            .entries
            .get(&own_sequencer_key)
            .map(|entry| entry.account_id)
        {
            info!("Producer reward account (stake ownership): {reward_account}");
        }

        if let Some(tip) = storage_ref
            .ask(sequencer_storage_actor::protocol::GetLatestBlockMeta)
            .await?
        {
            storage_ref
                .ask(sequencer_storage_actor::protocol::RaisePublishedHighWater {
                    block_id: tip.id,
                })
                .await?;
        }

        let mempool = MemPool::new(config.mempool_max_size);
        let mempool_handle = mempool.handle().clone();

        let is_our_turn = bedrock_pool_ref
            .ask(sequencer_bedrock_actor::protocol::CheckIsOurTurn {
                channel_id: config.bedrock_config.channel_id,
            })
            .await
            .map_err(SendErrorExt::flatten)?;

        let sequencer = SequencerCore::new(
            config,
            mempool,
            chain,
            bedrock_signing_key,
            storage_ref,
            bedrock_pool_ref,
            accredited_keys_pubsub_ref,
            slasher_prepared,
        )
        .await
        .map_err(Error::SequencerStartFailed)?;

        Ok(Self {
            background_tasks: sequencer.background_task(),
            mempool_handle,
            is_our_turn,
            sequencer,
        })
    }

    async fn create_channel_with_genesis(
        chain: &mut ChainState,
        config: &SequencerConfig,
        own_sequencer_key: sequencer_stake_core::SequencerKey,
        storage_ref: &ActorRef<S>,
        bedrock_pool_ref: &ActorRef<ShardingPoolActor<B, ChannelId>>,
    ) -> Result<()> {
        let channel_id = config.bedrock_config.channel_id;
        let signing_key = config
            .block_signing_key()
            .map_err(Error::InvalidSigningKey)?;
        let genesis_config = config
            .genesis_config(Some(own_sequencer_key))
            .map_err(Error::InvalidGenesisConfig)?;

        let (block, state) =
            sequencer_genesis::genesis_block_and_state(&signing_key, &genesis_config);
        chain.restore_head_block(block.clone()).map_err(|err| {
            Error::BlockReconstructionFailed {
                block_id: block.header.block_id,
                source: err,
            }
        })?;

        // The channel is born holding only its creator's key, so a configured
        // founding set is applied by the same tx that writes genesis; the
        // committee is never observable without it.
        let outcome =
            match sequencer_genesis::founding_committee(&config.genesis, own_sequencer_key) {
                Some(keys) => {
                    let channel_params =
                        sequencer_core::committee_discovery::channel_params(chain.head_state())
                            .ok_or(Error::SequencerStakeConfigNotFound)?;
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
                            genesis: block.clone(),
                            keys,
                            channel_params,
                        })
                        .await
                        .map_err(SendErrorExt::flatten)?
                }
                None => bedrock_pool_ref
                    .ask(sequencer_bedrock_actor::protocol::PublishBlock {
                        channel_id,
                        block: block.clone(),
                        withdrawals: Vec::new(),
                        parent: None,
                    })
                    .await
                    .map_err(SendErrorExt::flatten)?,
            };

        chain.record_own_inscription(outcome.checkpoint.last_msg_id, block.header.hash);
        storage_ref
            .ask(AtomicUpdate {
                checkpoint: Some(
                    outcome
                        .checkpoint
                        .to_bytes()
                        .map_err(|err| Error::CheckpointEncodingFailed(err.into()))?
                        .into(),
                ),
                ..AtomicUpdate::from_block(block, Arc::new(state))
            })
            .await?;

        sequencer_core_metrics::increment_blocks_produced_total();

        Ok(())
    }
}
