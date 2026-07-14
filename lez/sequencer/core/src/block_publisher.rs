use std::{pin::Pin, sync::Arc, time::Duration};

use anyhow::{Context as _, Result, anyhow};
use common::block::Block;
use log::{info, warn};
pub use logos_blockchain_core::mantle::ops::channel::{Ed25519PublicKey, MsgId};
use logos_blockchain_core::mantle::{
    channel::{SlotTimeframe, SlotTimeout},
    ops::channel::{ChannelId, config::Keys, inscribe::Inscription},
};
pub use logos_blockchain_key_management_system_service::keys::{Ed25519Key, ZkKey};
pub use logos_blockchain_zone_sdk::sequencer::SequencerCheckpoint;
use logos_blockchain_zone_sdk::{
    CommonHttpClient,
    adapter::NodeHttpClient,
    sequencer::{
        DepositInfo, Event, FinalizedOp, InscriptionInfo, OrphanedTx,
        SequencerConfig as ZoneSdkSequencerConfig, TurnNotification, WithdrawArg, WithdrawInfo,
        ZoneSequencer,
    },
};
use tokio::{
    sync::{mpsc, oneshot, watch},
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

/// The channel delta the follow path consumes from one `Event::BlocksProcessed`,
/// with inscription payloads decoded into `(MsgId, Block)` pairs.
pub struct FollowUpdate {
    pub adopted: Vec<(MsgId, Block)>,
    pub orphaned: Vec<(MsgId, Block)>,
    pub finalized: Vec<(MsgId, Block)>,
}

/// Sink for the follow path: apply adopted/finalized blocks to chain state and
/// revert orphaned ones.
pub type OnFollowSink =
    Box<dyn Fn(FollowUpdate) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + 'static>;

/// Commands the drive task executes with `&mut sequencer`.
enum Command {
    /// Publish an inscription (+ atomic withdrawals); responds with the assigned `MsgId`.
    Publish {
        inscription: Inscription,
        withdrawals: Vec<WithdrawArg>,
        resp: oneshot::Sender<Result<MsgId>>,
    },
    /// Post a `ChannelConfig` op replacing the accredited keys / rotation params.
    ConfigureChannel {
        keys: Keys,
        posting_timeframe: SlotTimeframe,
        posting_timeout: SlotTimeout,
        configuration_threshold: u16,
        withdraw_threshold: u16,
        resp: oneshot::Sender<Result<()>>,
    },
}

type CommandSender = mpsc::Sender<Command>;

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
        on_follow: OnFollowSink,
    ) -> Result<Self>;

    /// Publish a block and return the `MsgId` zone-sdk assigned its inscription.
    /// Zone-sdk drives the actual submission and retries internally.
    async fn publish_block(&self, block: &Block, withdrawals: Vec<WithdrawArg>) -> Result<MsgId>;

    /// Update the channel's accredited key set and rotation parameters via a
    /// `ChannelConfig` op. The sequencer's bedrock key must be the channel
    /// admin (`keys[0]`); the L1 rejects non-admin signers, so this is not
    /// re-validated here.
    ///
    /// `Ok(())` only means the signed op was queued locally, not that the
    /// L1 accepted it — acceptance is asynchronous.
    ///
    /// Desugared (not `async fn`) so the returned future is provably `Send` —
    /// generic callers awaiting it inside jsonrpsee handlers require that.
    fn configure_channel(
        &self,
        keys: Vec<Ed25519PublicKey>,
        posting_timeframe: u32,
        posting_timeout: u32,
        configuration_threshold: u16,
        withdraw_threshold: u16,
    ) -> impl Future<Output = Result<()>> + Send;

    fn channel_id(&self) -> ChannelId;

    /// Whether this sequencer is currently authorized to write to the channel.
    fn is_our_turn(&self) -> bool;
}

/// Real block publisher backed by zone-sdk's `ZoneSequencer`.
#[derive(Clone)]
pub struct ZoneSdkPublisher {
    channel_id: ChannelId,
    command_tx: CommandSender,
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
        on_follow: OnFollowSink,
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

        let (command_tx, mut command_rx): (CommandSender, _) =
            mpsc::channel(PUBLISH_INBOX_CAPACITY);

        let drive_task = tokio::spawn(async move {
            loop {
                #[expect(
                    clippy::integer_division_remainder_used,
                    reason = "tokio::select! expansion uses `%` for random branch selection"
                )]
                {
                    tokio::select! {
                        // Drain external commands by calling the borrowing
                        // handle — `&mut sequencer` is only available here.
                        Some(command) = command_rx.recv() => match command {
                            Command::Publish { inscription: data_bounded, withdrawals, resp: resp_tx } => {
                                let data_byte_size = data_bounded.len();
                                let withdraw_count = withdrawals.len();
                                let published = if withdrawals.is_empty() {
                                    sequencer.handle()
                                        .publish(data_bounded)
                                        .context("Failed to publish block")
                                } else {
                                    sequencer.handle()
                                        .publish_atomic_withdraw(data_bounded, withdrawals)
                                        .context("Failed to publish block with withdrawals")
                                };

                                let msg_result = published
                                    .map(|(result, _checkpoint)| result.tx.inscription().this_msg);
                                match &msg_result {
                                    Ok(_) if withdraw_count == 0 => {
                                        info!("Published block with the size of {data_byte_size} bytes");
                                    }
                                    Ok(_) => {
                                        info!(
                                            "Published block with the size of {data_byte_size} bytes and {withdraw_count} bridge withdrawals",
                                        );
                                    }
                                    Err(e) => warn!("zone-sdk publish failed: {e:?}"),
                                }
                                let _dontcare = resp_tx.send(msg_result);
                            }
                            Command::ConfigureChannel {
                                keys,
                                posting_timeframe,
                                posting_timeout,
                                configuration_threshold,
                                withdraw_threshold,
                                resp,
                            } => {
                                let result = sequencer
                                    .handle()
                                    .channel_config(
                                        keys,
                                        posting_timeframe,
                                        posting_timeout,
                                        configuration_threshold,
                                        withdraw_threshold,
                                    )
                                    .map(|_queued| ())
                                    .context("Failed to post channel config");
                                if let Err(err) = &result {
                                    warn!("zone-sdk channel config failed: {err:?}");
                                }
                                let _dontcare = resp.send(result);
                            }
                        },
                        event = sequencer.next_event() => {
                            let Some(event) = event else {
                                continue;
                            };
                            match event {
                                Event::BlocksProcessed {
                                    checkpoint,
                                    channel_update,
                                    finalized,
                                } => {
                                    on_checkpoint(checkpoint);

                                    let adopted = channel_update
                                        .adopted
                                        .iter()
                                        .filter_map(block_from_inscription)
                                        .collect();
                                    let orphaned = channel_update
                                        .orphaned
                                        .iter()
                                        .map(orphan_inscription)
                                        .filter_map(block_from_inscription)
                                        .collect();

                                    let mut finalized_blocks = Vec::new();
                                    for op in finalized.into_iter().flat_map(|item| item.ops) {
                                        match op {
                                            FinalizedOp::Inscription(inscription) => {
                                                if let Some((msg, block)) =
                                                    block_from_inscription(&inscription)
                                                {
                                                    on_finalized_block(block.header.block_id);
                                                    finalized_blocks.push((msg, block));
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

                                    on_follow(FollowUpdate {
                                        adopted,
                                        orphaned,
                                        finalized: finalized_blocks,
                                    })
                                    .await;
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
            command_tx,
            turn_rx,
            _drive_task: Arc::new(DriveTaskGuard(drive_task)),
        })
    }

    async fn publish_block(&self, block: &Block, withdrawals: Vec<WithdrawArg>) -> Result<MsgId> {
        let data = borsh::to_vec(block).context("Failed to serialize block")?;
        let data_bounded: Inscription = data
            .try_into()
            .context("Block data exceeds maximum allowed size")?;

        let (resp_tx, resp_rx) = oneshot::channel();
        self.command_tx
            .send(Command::Publish {
                inscription: data_bounded,
                withdrawals,
                resp: resp_tx,
            })
            .await
            .map_err(|_closed| anyhow!("Drive task is no longer running"))?;

        resp_rx
            .await
            .map_err(|_closed| anyhow!("Drive task dropped the publish response"))?
    }

    async fn configure_channel(
        &self,
        keys: Vec<Ed25519PublicKey>,
        posting_timeframe: u32,
        posting_timeout: u32,
        configuration_threshold: u16,
        withdraw_threshold: u16,
    ) -> Result<()> {
        let keys = Keys::try_from(keys)
            .map_err(|_err| anyhow!("Channel key list must be non-empty and within bounds"))?;
        let (resp_tx, resp_rx) = oneshot::channel();
        self.command_tx
            .send(Command::ConfigureChannel {
                keys,
                posting_timeframe: posting_timeframe.into(),
                posting_timeout: posting_timeout.into(),
                configuration_threshold,
                withdraw_threshold,
                resp: resp_tx,
            })
            .await
            .map_err(|_closed| anyhow!("Drive task is no longer running"))?;
        resp_rx
            .await
            .map_err(|_closed| anyhow!("Drive task dropped the config response"))?
    }

    fn channel_id(&self) -> ChannelId {
        self.channel_id
    }

    fn is_our_turn(&self) -> bool {
        self.turn_rx.borrow().our_turn_to_write
    }
}

/// Deserialize an inscription payload into `(this_msg, Block)`. Bad payloads are
/// logged and skipped.
fn block_from_inscription(inscription: &InscriptionInfo) -> Option<(MsgId, Block)> {
    borsh::from_slice::<Block>(&inscription.payload)
        .inspect_err(|err| {
            warn!("Failed to deserialize block from inscription: {err:?}");
        })
        .ok()
        .map(|block| (inscription.this_msg, block))
}

/// The inscription carried by an orphaned tx (plain or atomic-withdraw bundle).
const fn orphan_inscription(orphan: &OrphanedTx) -> &InscriptionInfo {
    match orphan {
        OrphanedTx::Inscription(info) => info,
        OrphanedTx::AtomicWithdraw(bundle) => &bundle.inscription,
    }
}
