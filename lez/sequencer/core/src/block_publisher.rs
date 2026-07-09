use std::{pin::Pin, sync::Arc, time::Duration};

use anyhow::{Context as _, Result, anyhow};
use common::block::Block;
use log::{info, warn};
pub use logos_blockchain_core::mantle::ops::channel::MsgId;
use logos_blockchain_core::mantle::ops::channel::{ChannelId, inscribe::Inscription};
pub use logos_blockchain_key_management_system_service::keys::{Ed25519Key, ZkKey};
pub use logos_blockchain_zone_sdk::sequencer::SequencerCheckpoint;
use logos_blockchain_zone_sdk::{
    CommonHttpClient,
    adapter::NodeHttpClient,
    sequencer::{
        DepositInfo, Event, FinalizedOp, InscriptionInfo,
        SequencerConfig as ZoneSdkSequencerConfig, TurnNotification, WithdrawArg, WithdrawInfo,
        ZoneSequencer,
    },
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};

use crate::config::BedrockConfig;

/// Channel capacity for the publish inbox. One publish per produced block, drained
/// in microseconds by the drive task — 32 is huge headroom and just provides
/// backpressure if the drive task stalls (reconnect, long backfill).
const PUBLISH_INBOX_CAPACITY: usize = 32;

/// Sink for `Event::Published` checkpoints emitted by the drive task.
/// Caller is responsible for persistence (e.g. writing to rocksdb).
pub type CheckpointSink = Box<dyn Fn(SequencerCheckpoint) + Send + 'static>;

/// Sink for finalized L2 block ids derived from `Event::TxsFinalized` and
/// `Event::FinalizedInscriptions`. Caller is responsible for cleanup
/// (e.g. marking pending blocks as finalized in storage).
pub type FinalizedBlockSink = Box<dyn Fn(u64) + Send + 'static>;

/// Sink for finalized Bedrock deposit events.
pub type OnDepositEventSink =
    Box<dyn Fn(DepositInfo) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + 'static>;

/// Sink for finalized Bedrock withdraw events.
pub type OnWithdrawEventSink =
    Box<dyn Fn(WithdrawInfo) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + 'static>;

#[expect(async_fn_in_trait, reason = "We don't care about Send/Sync here")]
pub trait BlockPublisherTrait: Clone {
    #[expect(
        clippy::too_many_arguments,
        reason = "Looks better than bundling all those callbacks into a struct"
    )]
    async fn new(
        config: &BedrockConfig,
        bedrock_signing_key: Ed25519Key,
        resubmit_interval: Duration,
        initial_checkpoint: Option<SequencerCheckpoint>,
        on_checkpoint: CheckpointSink,
        on_finalized_block: FinalizedBlockSink,
        on_deposit_event: OnDepositEventSink,
        on_withdraw_event: OnWithdrawEventSink,
    ) -> Result<Self>;

    /// Fire-and-forget publish. Zone-sdk drives the actual submission and
    /// retries internally; this just hands the payload off.
    async fn publish_block(&self, block: &Block, withdrawals: Vec<WithdrawArg>) -> Result<()>;

    fn channel_id(&self) -> ChannelId;

    /// Whether this sequencer is currently authorized to write to the channel.
    fn is_our_turn(&self) -> bool;
}

/// Real block publisher backed by zone-sdk's `ZoneSequencer`.
#[derive(Clone)]
pub struct ZoneSdkPublisher {
    channel_id: ChannelId,
    publish_tx: mpsc::Sender<(Inscription, Vec<WithdrawArg>)>,
    turn_rx: watch::Receiver<TurnNotification>,
    // Aborts the drive task when the last clone is dropped.
    _drive_task: Arc<DriveTaskGuard>,
}

struct DriveTaskGuard(JoinHandle<()>);

impl Drop for DriveTaskGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl BlockPublisherTrait for ZoneSdkPublisher {
    async fn new(
        config: &BedrockConfig,
        bedrock_signing_key: Ed25519Key,
        resubmit_interval: Duration,
        initial_checkpoint: Option<SequencerCheckpoint>,
        on_checkpoint: CheckpointSink,
        on_finalized_block: FinalizedBlockSink,
        on_deposit_event: OnDepositEventSink,
        on_withdraw_event: OnWithdrawEventSink,
    ) -> Result<Self> {
        let basic_auth = config.auth.clone().map(Into::into);
        let node = NodeHttpClient::new(CommonHttpClient::new(basic_auth), config.node_url.clone());

        let zone_sdk_config = ZoneSdkSequencerConfig {
            resubmit_interval,
            ..ZoneSdkSequencerConfig::default()
        };

        let mut sequencer = ZoneSequencer::init_with_config(
            config.channel_id,
            bedrock_signing_key,
            node,
            zone_sdk_config,
            initial_checkpoint,
        );

        // Grab readiness receiver before moving the sequencer into the drive
        // task so we can await cold-start completion below.
        let mut ready_rx = sequencer.subscribe_ready();
        // Grab the turn watch before the move; the sdk actor keeps it current.
        let turn_rx = sequencer.subscribe_turn_to_write();

        let (publish_tx, mut publish_rx) =
            mpsc::channel::<(Inscription, Vec<WithdrawArg>)>(PUBLISH_INBOX_CAPACITY);

        let drive_task = tokio::spawn(async move {
            loop {
                #[expect(
                    clippy::integer_division_remainder_used,
                    reason = "tokio::select! expansion uses `%` for random branch selection"
                )]
                {
                    tokio::select! {
                        // Drain external publish requests by calling the
                        // borrowing handle — `&mut sequencer` is only
                        // available here.
                        Some((data_bounded, withdrawals)) = publish_rx.recv() => {
                            let data_byte_size = data_bounded.len();
                            if withdrawals.is_empty() {
                                if let Err(e) = sequencer.handle()
                                                .publish(data_bounded)
                                                .context("Failed to publish block") {
                                                    warn!("zone-sdk publish failed: {e:?}");
                                                }

                                info!("Published block with the size of {data_byte_size} bytes");
                            } else {
                                let withdraw_count = withdrawals.len();
                                if let Err(e) = sequencer.handle()
                                                .publish_atomic_withdraw(data_bounded, withdrawals)
                                                .context("Failed to publish block with withdrawals") {
                                                    warn!("zone-sdk publish failed: {e:?}");
                                                }

                                info!(
                                    "Published block with the size of {data_byte_size} bytes and {withdraw_count} bridge withdrawals",
                                );
                            }
                        }
                        event = sequencer.next_event() => {
                            let Some(event) = event else {
                                continue;
                            };
                            match event {
                                Event::BlocksProcessed {
                                    checkpoint,
                                    channel_update: _,
                                    finalized,
                                } => {
                                    on_checkpoint(checkpoint);
                                    for op in finalized.into_iter().flat_map(|item| item.ops) {
                                        match op {
                                            FinalizedOp::Inscription(inscription) => {
                                                if let Some(block_id) =
                                                    block_id_from_inscription(&inscription)
                                                {
                                                    on_finalized_block(block_id);
                                                }
                                            }
                                            FinalizedOp::Deposit(deposit) => {
                                                on_deposit_event(deposit).await;
                                            }
                                            FinalizedOp::Withdraw(withdraw) => {
                                                on_withdraw_event(withdraw).await;
                                            }
                                        }
                                    }
                                }
                                Event::Ready | Event::TurnNotification { .. } => {}
                            }
                        }
                    }
                }
            }
        });

        // Wait for cold-start backfill to complete before returning so callers
        // can publish immediately (e.g. genesis block) without racing readiness.
        ready_rx
            .wait_for(|v| *v)
            .await
            .context("Zone-sdk readiness channel closed before becoming ready")?;

        Ok(Self {
            channel_id: config.channel_id,
            publish_tx,
            turn_rx,
            _drive_task: Arc::new(DriveTaskGuard(drive_task)),
        })
    }

    async fn publish_block(&self, block: &Block, withdrawals: Vec<WithdrawArg>) -> Result<()> {
        let data = borsh::to_vec(block).context("Failed to serialize block")?;
        let data_bounded: Inscription = data
            .try_into()
            .context("Block data exceeds maximum allowed size")?;

        self.publish_tx
            .send((data_bounded, withdrawals))
            .await
            .map_err(|_closed| anyhow!("Drive task is no longer running"))?;

        Ok(())
    }

    fn channel_id(&self) -> ChannelId {
        self.channel_id
    }

    fn is_our_turn(&self) -> bool {
        self.turn_rx.borrow().our_turn_to_write
    }
}

/// Deserialize inscription payload as a `Block` and return it's`block_id`.
/// Bad payloads are logged and skipped.
fn block_id_from_inscription(inscription: &InscriptionInfo) -> Option<u64> {
    borsh::from_slice::<Block>(&inscription.payload)
        .inspect_err(|err| {
            warn!("Failed to deserialize block from inscription: {err:?}");
        })
        .ok()
        .map(|block| block.header.block_id)
}
