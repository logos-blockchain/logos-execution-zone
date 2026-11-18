use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use chain_state::{ChainState, ChannelEntry};
use common::{
    block::{BedrockStatus, Block},
    storage_cid::StorageCid,
    transaction::LeeTransaction,
};
use kameo::actor::ActorRef;
use kameo_actors::pubsub::{PubSub, Publish};
use lee::privacy_preserving_transaction::circuit::ProofDigest;
use mempool::{MemPool, MemPoolHandle};
use sequencer_actors_common::SendErrorExt;
use sequencer_bedrock_actor::{
    BedrockActorTrait,
    protocol::{ChannelId, ChannelSeq, Ed25519Key, Ed25519PublicKey, PublishOutcome, Slot},
};
use sequencer_core::{
    SequencerCore, TransactionOrigin,
    availability::{AvailabilityApproval, AvailabilityMessage, CandidateId},
    config::SequencerConfig,
    proof_objects::{Admission, ProofObjects},
};
use sequencer_gossip_actor::protocol::FetchProof;
use sequencer_stake_core::SequencerKey;
use sequencer_storage_actor::{StorageActorTrait, protocol::AtomicUpdate};
use sharding_pool_actor::ShardingPoolActor;
use tracing::{debug, info};

use self::{skip::SkipPolicy, turn::Turn};
use crate::{
    Result,
    actor::state::{ActorsBundle, bootstrapping, check_startup_channel_params, checkpoint_record},
    error::Error,
};

mod skip;
#[cfg(test)]
mod tests;
mod turn;

/// How many of this node's own candidates approvals are kept for.
const TRACKED_CANDIDATES: usize = 8;

/// The first wait before a missing proof is sought again; it doubles per attempt, up to 64 times.
const RECOVERY_BACKOFF: Duration = Duration::from_secs(1);

/// One missing proof's recovery.
struct Recovery {
    in_flight: bool,
    attempts: u32,
    next_attempt: Instant,
}

pub struct OnlineState<S: StorageActorTrait, B: BedrockActorTrait> {
    sequencer: SequencerCore<S, B>,
    mempool_handle: MemPoolHandle<(TransactionOrigin, LeeTransaction)>,
    /// Whose turn it is to write: blocks are only produced in ours.
    turn: Turn,
    skip_policy: SkipPolicy,
    /// Where this node asks its peers for the CIDs of the proofs its chain state lacks.
    proof_requests_ref: ActorRef<PubSub<FetchProof>>,
    /// The missing proofs being recovered, each retried with backoff.
    recoveries: Arc<Mutex<BTreeMap<ProofDigest, Recovery>>>,
    /// The keys that approved this node's own recent candidates, by candidate.
    availability_approvals: BTreeMap<CandidateId, BTreeSet<SequencerKey>>,
    // TODO: Remove this field
    background_tasks: sequencer_core::task_group::TaskGroup,
}

impl<S: StorageActorTrait, B: BedrockActorTrait> OnlineState<S, B> {
    /// Goes online once bootstrapping replayed the channel up to its tip, read at `tip_slot`.
    pub(super) async fn from_bootstrapping(
        bootstrapping_state: bootstrapping::BootstrappingState<S, B>,
        replayed_up_to: Slot,
    ) -> Result<Self> {
        Self::start(
            true,
            Some(replayed_up_to),
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
        actors: ActorsBundle<S, B>,
    ) -> Result<Self> {
        Self::start(true, None, config, chain, channel_signing_key, actors).await
    }

    /// Creates the channel, inscribing the stored chain onto it, or a new genesis when the store
    /// holds none.
    pub(super) async fn creating_channel(
        config: SequencerConfig,
        chain: ChainState,
        channel_signing_key: Ed25519Key,
        actors: ActorsBundle<S, B>,
    ) -> Result<Self> {
        Self::start(false, None, config, chain, channel_signing_key, actors).await
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
        self.turn.is_ours()
    }

    pub fn update_turn(&mut self, our_turn_to_write: bool, starting_slot: Option<Slot>) {
        if self.turn.update(our_turn_to_write, starting_slot) {
            sequencer_executor_actor_metrics::increment_turns_to_write_total();
            self.skip_policy.start_turn();
        }
        sequencer_executor_actor_metrics::record_turn_to_write(self.turn.is_ours());
    }

    /// Refolds on the proofs that arrived, then recovers those still missing: from the CID their
    /// block inscribes, then from one a peer names.
    pub async fn fetch_proofs(&mut self) {
        let missing = self.sequencer.hydrate().await;
        let located: Vec<_> = self
            .sequencer
            .with_chain(|chain| {
                missing
                    .iter()
                    .map(|digest| (*digest, chain.inscribed_locator(digest)))
                    .collect()
            })
            .await;
        let now = Instant::now();
        let mut recoveries = self
            .recoveries
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        recoveries.retain(|digest, _| missing.contains(digest));
        for (digest, locator) in located {
            let recovery = recoveries.entry(digest).or_insert(Recovery {
                in_flight: false,
                attempts: 0,
                next_attempt: now,
            });
            if recovery.in_flight || now < recovery.next_attempt {
                continue;
            }
            recovery.in_flight = true;
            let proof_objects = self.sequencer.proof_objects();
            let proof_requests_ref = self.proof_requests_ref.clone();
            let shared = Arc::clone(&self.recoveries);
            tokio::spawn(async move {
                let recovered = match locator {
                    Some(locator) => proof_objects
                        .fetch(digest, locator, Admission::Live, |_proof| true)
                        .await
                        .inspect_err(|err| {
                            debug!(%locator, error = %err, "Failed to fetch a proof from its inscribed CID");
                        })
                        .is_ok(),
                    None => false,
                };
                if !recovered
                    && proof_requests_ref
                        .tell(Publish(FetchProof(digest)))
                        .try_send()
                        .is_err()
                {
                    debug!("Dropped a request for proof {digest:?}");
                }
                let mut held = shared.lock().unwrap_or_else(PoisonError::into_inner);
                if let Some(done) = held.get_mut(&digest) {
                    done.in_flight = false;
                    done.attempts = done.attempts.saturating_add(1);
                    done.next_attempt = Instant::now()
                        .checked_add(RECOVERY_BACKOFF.saturating_mul(1 << done.attempts.min(6)))
                        .unwrap_or_else(Instant::now);
                }
            });
        }
    }

    /// Takes in a peer's candidate or availability approval. Only approvals of this node's own
    /// candidates are kept, for its most recent turns.
    pub fn on_availability(&mut self, message: AvailabilityMessage) {
        match message {
            AvailabilityMessage::Approval(approval) => {
                if approval.candidate.producer.to_bytes()
                    != self.sequencer.channel_signing_public_key()
                {
                    return;
                }
                let AvailabilityApproval {
                    candidate, signer, ..
                } = *approval;
                self.availability_approvals
                    .entry(candidate)
                    .or_default()
                    .insert(signer);
                // Candidates of one producer order by turn, so the first is the oldest.
                while self.availability_approvals.len() > TRACKED_CANDIDATES {
                    self.availability_approvals.pop_first();
                }
            }
            AvailabilityMessage::Candidate(_) => {}
        }
    }

    /// Whether this turn may build on the head tip, which skips the block past it, if any.
    pub async fn may_produce(&mut self) -> bool {
        let own = self.sequencer.channel_signing_public_key();
        self.sequencer
            .with_chain(|chain| self.skip_policy.may_produce(chain, own, &self.turn))
            .await
    }

    /// Keeps when each entry of the view was first seen.
    pub async fn observe_view(&mut self) {
        self.sequencer
            .with_chain(|chain| self.skip_policy.observe(chain.view()))
            .await;
    }

    pub const fn background_tasks(&self) -> &sequencer_core::task_group::TaskGroup {
        &self.background_tasks
    }

    async fn start(
        channel_exists: bool,
        replayed_up_to: Option<Slot>,
        config: SequencerConfig,
        mut chain: ChainState,
        channel_signing_key: Ed25519Key,
        actors: ActorsBundle<S, B>,
    ) -> Result<Self> {
        let ActorsBundle {
            storage_ref,
            bedrock_pool_ref,
            stake_config_pubsub_ref,
            slasher_ref,
            channel_signer_ref,
            proof_requests_ref,
            proof_objects,
        } = actors;

        let own_sequencer_key =
            sequencer_stake_core::SequencerKey::new(channel_signing_key.public_key().to_bytes())
                .ok_or(Error::InvalidSequencerKey)?;

        // Production waits for every update the publisher broadcasts past the
        // sequence it started at.
        let mut applied_seq = bedrock_pool_ref
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
                    replayed_up_to,
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
                    &proof_objects,
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

        // A joining node's config carries no channel params, so check the finalized chain's.
        if let Some(params) = chain_state::stake_config::channel_params(chain.final_state()) {
            check_startup_channel_params(&params, &config)?;
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

        let stake_config = chain_state::stake_config::read_config(&state)
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
            applied_seq,
            channel_signing_key,
            storage_ref,
            bedrock_pool_ref,
            stake_config_pubsub_ref,
            slasher_ref,
            channel_signer_ref,
            proof_objects,
        )
        .await
        .map_err(Error::SequencerStartFailed)?;

        Ok(Self {
            background_tasks: sequencer.background_task(),
            mempool_handle,
            turn: Turn::new(is_our_turn),
            skip_policy: SkipPolicy::default(),
            proof_requests_ref,
            recoveries: Arc::default(),
            availability_approvals: BTreeMap::new(),
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
        let genesis_spec = config
            .genesis_spec(Some(own_sequencer_key))
            .map_err(Error::InvalidGenesisConfig)?;

        let (block, state, events) = sequencer_genesis::genesis_block_and_state(&genesis_spec);

        let outcome =
            Self::inscribe_genesis(&block, &state, config, own_sequencer_key, bedrock_pool_ref)
                .await?;

        let block_id = block.header.block_id;
        chain.replace_unfinalized_view(vec![published_entry(
            &outcome,
            &block,
            own_sequencer_key,
            Vec::new(),
        )]);
        storage_ref
            .ask(AtomicUpdate {
                checkpoint: Some(checkpoint_record(&outcome.checkpoint, outcome.seq)?),
                blocks: vec![block],
                events: vec![(block_id, events)],
                ..sequencer_core::chain_update(chain)
            })
            .await?;

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
        proof_objects: &ProofObjects,
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
        let mut published = vec![published_entry(
            &outcome,
            genesis,
            own_sequencer_key,
            Vec::new(),
        )];
        for block in descendants {
            let mut locators = Vec::new();
            for proof in block.body.proofs() {
                locators.push(
                    proof_objects
                        .seed(proof)
                        .await
                        .map_err(Error::ProofSeedingFailed)?,
                );
            }
            outcome = bedrock_pool_ref
                .ask(sequencer_bedrock_actor::protocol::PublishBlock {
                    channel_id: config.bedrock_config.channel_id,
                    block: block.clone(),
                    locators: locators.clone(),
                    withdrawals: Vec::new(),
                    parent: None,
                    expected_seq: None,
                })
                .await
                .map_err(SendErrorExt::flatten)?;
            for proof in block.body.proofs() {
                chain.proofs().insert(proof);
            }
            published.push(published_entry(
                &outcome,
                block,
                own_sequencer_key,
                locators,
            ));
        }

        // These blocks are already stored, so only the view and the sdk's
        // pending set moved. Checkpoints are cumulative, so the last one
        // covers every publish above.
        chain.replace_unfinalized_view(published);
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
        let founding_committee = config.genesis.as_ref().and_then(|genesis_config| {
            sequencer_genesis::founding_committee(&genesis_config.actions, own_sequencer_key)
        });
        let outcome = match founding_committee {
            Some(keys) => {
                // The account, not the config: the genesis tx already wrote the
                // configured values there, and the account is what every later
                // update reads, so creation must not have a second source.
                let channel_params = chain_state::stake_config::channel_params(genesis_state)
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
                    locators: Vec::new(),
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

/// The view entry a publish of `block` by `signer` produced; our own blocks are trusted for every
/// key they name.
fn published_entry(
    outcome: &PublishOutcome,
    block: &Block,
    signer: sequencer_stake_core::SequencerKey,
    locators: Vec<StorageCid>,
) -> ChannelEntry {
    ChannelEntry {
        msg: outcome.this_msg,
        parent: outcome.parent,
        signer: Some(signer.to_bytes()),
        slot: None,
        block: Some(block.digested()),
        finally_absent_keys: chain_state::full_stake_releases::finalize_unstake_keys(&block.body),
        locators,
    }
}
