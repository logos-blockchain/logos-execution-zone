use chain_state::{ChainState, ChannelEntry};
use common::{
    block::{BedrockStatus, Block},
    transaction::LeeTransaction,
};
use kameo::actor::ActorRef;
use log::info;
use mempool::{MemPool, MemPoolHandle};
use sequencer_actors_common::SendErrorExt;
use sequencer_bedrock_actor::{
    BedrockActorTrait,
    protocol::{ChannelId, ChannelSeq, Ed25519Key, Ed25519PublicKey, PublishOutcome},
};
use sequencer_core::{SequencerCore, TransactionOrigin, config::SequencerConfig};
use sequencer_storage_actor::{StorageActorTrait, protocol::AtomicUpdate};
use sharding_pool_actor::ShardingPoolActor;

use crate::{
    Result,
    actor::state::{ActorsBundle, bootstrapping, checkpoint_record},
    error::Error,
};

#[cfg(test)]
mod tests;

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

    pub(super) async fn from_stored_chain(
        config: SequencerConfig,
        chain: ChainState,
        bedrock_signing_key: Ed25519Key,
        actors: ActorsBundle<S, B>,
    ) -> Result<Self> {
        Self::start(true, config, chain, bedrock_signing_key, actors).await
    }

    /// Creates the channel, inscribing the stored chain onto it, or a new genesis when the store
    /// holds none.
    pub(super) async fn creating_channel(
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
            stake_config_keys_pubsub_ref,
            slasher_ref,
            config_manager_ref,
        } = actors;

        let own_sequencer_key =
            sequencer_stake_core::SequencerKey::new(bedrock_signing_key.public_key().to_bytes())
                .ok_or(Error::InvalidSequencerKey)?;

        // Production waits for every update the publisher broadcasts past the
        // sequence it started at.
        let mut applied_seq = bedrock_pool_ref
            .ask(
                sequencer_bedrock_actor::protocol::InitializeChannelPublisher {
                    channel_id: config.bedrock_config.channel_id,
                    bedrock_signing_key: bedrock_signing_key.clone(),
                    funding_pk: config.bedrock_config.funding_key,
                    priority_fee_percent: config.bedrock_config.priority_fee_percent,
                    resubmit_interval: config.retry_pending_blocks_timeout,
                },
            )
            .await
            .map_err(SendErrorExt::flatten)?;

        if !channel_exists {
            let holds_blocks = storage_ref
                .ask(sequencer_storage_actor::protocol::GetLatestBlockMeta)
                .await?
                .is_some();
            let created_seq = if holds_blocks {
                Self::create_channel_from_store(
                    &mut chain,
                    &config,
                    own_sequencer_key,
                    &storage_ref,
                    &bedrock_pool_ref,
                )
                .await?
            } else {
                Some(
                    Self::create_channel_with_genesis(
                        &mut chain,
                        &config,
                        own_sequencer_key,
                        &storage_ref,
                        &bedrock_pool_ref,
                    )
                    .await?,
                )
            };
            applied_seq = created_seq.or(applied_seq);
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
            applied_seq,
            bedrock_signing_key,
            storage_ref,
            bedrock_pool_ref,
            stake_config_keys_pubsub_ref,
            slasher_ref,
            config_manager_ref,
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
    ) -> Result<ChannelSeq> {
        let signing_key = config
            .block_signing_key()
            .map_err(Error::InvalidSigningKey)?;
        let genesis_config = config
            .genesis_config(Some(own_sequencer_key))
            .map_err(Error::InvalidGenesisConfig)?;

        let (block, state, events) =
            sequencer_genesis::genesis_block_and_state(&signing_key, &genesis_config);

        let outcome =
            Self::inscribe_genesis(&block, &state, config, own_sequencer_key, bedrock_pool_ref)
                .await?;

        let block_id = block.header.block_id;
        chain.apply_conflict(vec![published_entry(&outcome, &block)]);
        storage_ref
            .ask(AtomicUpdate {
                checkpoint: Some(checkpoint_record(&outcome.checkpoint, outcome.seq)?),
                blocks: vec![block],
                events: vec![(block_id, events)],
                ..sequencer_core::chain_update(chain)
            })
            .await?;

        sequencer_core_metrics::increment_blocks_produced_total();

        Ok(outcome.seq)
    }

    /// Inscribes the pending blocks the store holds, genesis first, onto a channel that does not
    /// exist yet. Returns the channel sequence the last publish left, [`None`] if nothing was
    /// pending.
    async fn create_channel_from_store(
        chain: &mut ChainState,
        config: &SequencerConfig,
        own_sequencer_key: sequencer_stake_core::SequencerKey,
        storage_ref: &ActorRef<S>,
        bedrock_pool_ref: &ActorRef<ShardingPoolActor<B, ChannelId>>,
    ) -> Result<Option<ChannelSeq>> {
        let mut pending_blocks = storage_ref
            .ask(sequencer_storage_actor::protocol::GetAllBlocks)
            .await?
            .into_iter()
            .filter(|block| matches!(block.bedrock_status, BedrockStatus::Pending))
            .collect::<Vec<_>>();
        pending_blocks.sort_unstable_by_key(|block| block.header.block_id);

        let Some((genesis, descendants)) = pending_blocks.split_first() else {
            return Ok(None);
        };
        if genesis.header.block_id != lee::GENESIS_BLOCK_ID {
            return Err(Error::StorageInconsistency(format!(
                "The first pending block {} is not genesis, but the channel does not exist",
                genesis.header.block_id
            )));
        }
        let genesis_state = storage_ref
            .ask(sequencer_storage_actor::protocol::GetLeeState)
            .await?
            .ok_or_else(|| {
                Error::StorageInconsistency("The store holds blocks but no state".to_owned())
            })?;

        let mut outcome = Self::inscribe_genesis(
            genesis,
            &genesis_state,
            config,
            own_sequencer_key,
            bedrock_pool_ref,
        )
        .await?;
        let mut published = vec![published_entry(&outcome, genesis)];
        for block in descendants {
            outcome = bedrock_pool_ref
                .ask(sequencer_bedrock_actor::protocol::PublishBlock {
                    channel_id: config.bedrock_config.channel_id,
                    block: block.clone(),
                    withdrawals: Vec::new(),
                    parent: None,
                    expected_seq: None,
                })
                .await
                .map_err(SendErrorExt::flatten)?;
            published.push(published_entry(&outcome, block));
        }

        // These blocks are already stored, so only the view and the sdk's
        // pending set moved. Checkpoints are cumulative, so the last one
        // covers every publish above.
        chain.apply_conflict(published);
        storage_ref
            .ask(AtomicUpdate {
                checkpoint: Some(checkpoint_record(&outcome.checkpoint, outcome.seq)?),
                ..sequencer_core::chain_update(chain)
            })
            .await?;

        Ok(Some(outcome.seq))
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
        let outcome =
            match sequencer_genesis::founding_committee(&config.genesis, own_sequencer_key) {
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
                        expected_seq: None,
                    })
                    .await
                    .map_err(SendErrorExt::flatten)?,
            };

        Ok(outcome)
    }
}

/// The view entry a publish of `block` produced.
fn published_entry(outcome: &PublishOutcome, block: &Block) -> ChannelEntry {
    ChannelEntry {
        msg: outcome.this_msg,
        parent: outcome.parent,
        block: Some(block.clone()),
    }
}
