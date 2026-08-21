use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, ensure};
use common::block::Block;
use futures::{Stream, future::BoxFuture};
use log::{info, warn};
pub use logos_blockchain_core::mantle::{
    ledger::NoteId,
    ops::channel::{Ed25519PublicKey, MsgId},
};
use logos_blockchain_core::{
    mantle::{
        SignedMantleTx,
        channel::{ChannelState, SlotTimeframe, SlotTimeout},
        gas::GasCost,
        ops::{
            Op, OpProof,
            channel::{
                ChannelId,
                config::{ChannelConfigOp, Keys},
                inscribe::{Inscription, InscriptionOp},
            },
        },
        traits::Hashable as _,
        transactions::{MantleTxBuilder, OpsProofs, states::Unverified},
    },
    proofs::channel_multi_sig_proof::{ChannelMultiSigProof, IndexedSignature},
};
use logos_blockchain_http_api_common::bodies::wallet::fund::WalletFundRequestBody;
pub use logos_blockchain_key_management_system_service::keys::{
    ED25519_SECRET_KEY_SIZE, Ed25519Key, ZkKey, ZkPublicKey,
};
pub use logos_blockchain_zone_sdk::sequencer::SequencerCheckpoint;
use logos_blockchain_zone_sdk::{
    CommonHttpClient, Slot, ZoneMessage,
    adapter::{Node as _, NodeHttpClient},
    sequencer::{
        ChannelUpdateTx, DepositInfo, Event, FinalizedOp, FundingConfig, InscriptionInfo,
        PendingTx, SequencerConfig as ZoneSdkSequencerConfig, TurnNotification, WithdrawArg,
        WithdrawInfo, ZoneSequencer,
    },
};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;

use crate::{config::BedrockConfig, task_group::TaskGroup};

/// Channel capacity for the publish inbox. One publish per produced block, drained
/// in microseconds by the drive task — 32 is huge headroom and just provides
/// backpressure if the drive task stalls (reconnect, long backfill).
const PUBLISH_INBOX_CAPACITY: usize = 32;

/// Everything one `Event::BlocksProcessed` carries, with inscription payloads
/// decoded into `(MsgId, Block)` pairs.
///
/// One struct rather than a sink per effect, because the `checkpoint` and
/// everything it covers must reach the store in a single write.
pub struct FollowUpdate {
    /// Resume cursor for this event. Persist only together with the effects
    /// below, never ahead of them.
    pub checkpoint: SequencerCheckpoint,
    /// Inscriptions newly on the followed L1 branch, in channel order: they
    /// extend (or, after a reorg, replace part of) the `head` tier.
    pub adopted: Vec<(MsgId, Block)>,
    /// Inscriptions dropped from the branch by an L1 reorg: their blocks are
    /// reverted from the `head` and their user txs resubmitted to the mempool.
    pub orphaned: Vec<(MsgId, Block)>,
    /// Inscriptions whose containing L1 block reached finality: their blocks
    /// move into the irreversible `final` tier.
    pub finalized: Vec<(MsgId, Block)>,
    /// Finalized Bedrock deposit events, to record and mint on L2.
    pub deposits: Vec<DepositInfo>,
    /// Finalized Bedrock withdraw events, to reconcile against local intents.
    pub withdrawals: Vec<WithdrawInfo>,
}

/// Sink for the follow path: apply the channel delta to chain state and
/// persist the whole event in one write.
pub type OnFollowSink = Box<dyn Fn(FollowUpdate) -> BoxFuture<'static, ()> + Send + Sync + 'static>;

/// What one publish produced.
pub struct PublishOutcome {
    /// The `MsgId` zone-sdk assigned the published inscription.
    pub this_msg: MsgId,
    /// The checkpoint that now holds the inscription as pending.
    pub checkpoint: SequencerCheckpoint,
    /// Channel notes the bundled withdrawals release, empty for a plain
    /// publish.
    /// A [`ChannelWithdrawOp`](logos_blockchain_core::mantle::ops::channel::withdraw::ChannelWithdrawOp)
    /// carries nothing but the note ids it releases, so these are the only
    /// handle the local withdraw intent shares with the Bedrock Withdraw event
    /// that later reports it.
    pub released_notes: Vec<NoteId>,
}

/// Commands the drive task executes with `&mut sequencer`.
enum Command {
    /// Publish an inscription (+ atomic withdrawals); responds with the
    /// [`PublishOutcome`].
    Publish {
        inscription: Inscription,
        withdrawals: Vec<WithdrawArg>,
        resp: oneshot::Sender<Result<PublishOutcome>>,
    },
    /// Submit a committee `ChannelConfigOp` as its own, independent Mantle tx
    /// — not bundled with any block publish.
    SubmitChannelConfig {
        new_keys: Keys,
        resp: oneshot::Sender<Result<()>>,
    },
    /// Hand zone-sdk a pre-built tx to track and post, keyed by the channel tip
    /// it leaves behind.
    SubmitSignedTx {
        tx: Box<SignedMantleTx<Unverified>>,
        msg_id: MsgId,
        resp: oneshot::Sender<Result<PublishOutcome>>,
    },
}

type CommandSender = mpsc::Sender<Command>;

#[trait_variant::make(BlockPublisherTrait: Send)]
pub trait LocalBlockPublisherTrait: Sized + Sync {
    async fn new(
        config: &BedrockConfig,
        bedrock_signing_key: Ed25519Key,
        resubmit_interval: Duration,
        initial_checkpoint: Option<SequencerCheckpoint>,
        on_follow: OnFollowSink,
    ) -> Result<Self>;

    /// Whether the channel already exists, checked before anything else is
    /// set up (no instance, no store, no genesis yet).
    async fn channel_exists(config: &BedrockConfig) -> Result<bool>;

    /// Publish a block and return what zone-sdk made of it. Zone-sdk drives the
    /// actual submission and retries internally.
    ///
    /// The checkpoint must be persisted with the block — restoring an older one
    /// drops the inscription from the pending set, and it is never resubmitted.
    async fn publish_block(
        &self,
        block: &Block,
        withdrawals: Vec<WithdrawArg>,
    ) -> Result<PublishOutcome>;

    /// Create the channel and write `block` into it in one Mantle tx. Only valid
    /// while the channel does not exist, and `keys[0]` must be this sequencer's
    /// own key, since creation hands the first turn to index 0.
    async fn publish_genesis_creating_channel(
        &self,
        block: &Block,
        keys: Vec<Ed25519PublicKey>,
    ) -> Result<PublishOutcome>;

    /// Live (adopted, possibly not yet finalized) accredited-key snapshot for
    /// this channel, read directly from the connected Bedrock node.
    async fn accredited_keys(&self) -> Result<Vec<Ed25519PublicKey>>;

    /// Submit a committee `ChannelConfigOp` as its own, independent Mantle
    /// tx (not bundled with any block publish). `new_keys` is the full
    /// replacement accredited-keys list; the channel administration
    /// parameters posted alongside it are the `system_accounts` defaults.
    async fn submit_channel_config(&self, new_keys: Vec<Ed25519PublicKey>) -> Result<()>;

    fn channel_id(&self) -> ChannelId;

    /// Whether this sequencer is currently authorized to write to the channel.
    fn is_our_turn(&self) -> bool;

    /// A [`CancellationToken`] cancelled when the publisher's background driver
    /// terminates (a panicked sink, an ended event stream). No channel events
    /// are processed past that point, so the node must halt.
    fn driver_cancellation(&self) -> CancellationToken;

    /// The publisher's background tasks, for a caller that needs to know when
    /// they have actually stopped. Its sinks capture a store handle, so the
    /// `RocksDB` lock outlives the sequencer until the drive task is gone.
    /// Empty by default, for publishers that run no tasks.
    fn background_tasks(&self) -> TaskGroup {
        TaskGroup::default()
    }

    /// Current channel frontier slot on the connected chain, or `None` if the
    /// channel does not exist there. Drives the startup frontier check.
    async fn channel_tip_slot(&self) -> Result<Option<Slot>>;

    /// Finalized channel messages from `after_slot` (exclusive) up to LIB, used
    /// for the startup consistency check and reconstruction. Pass `None` to read
    /// from the channel's genesis.
    async fn read_channel_after(
        &self,
        checkpoint: Option<SequencerCheckpoint>,
    ) -> impl Stream<Item = (ZoneMessage, SequencerCheckpoint)> + Send + '_;
}

/// Real block publisher backed by zone-sdk's `ZoneSequencer`.
pub struct ZoneSdkPublisher {
    channel_id: ChannelId,
    /// Direct node handle retained for channel reads (startup consistency check
    /// and reconstruction); the sequencer itself lives in the drive task.
    node: NodeHttpClient,
    command_tx: CommandSender,
    turn_rx: watch::Receiver<TurnNotification>,
    // Cancelled when the drive task ends for any reason, including a panic.
    driver_cancellation: CancellationToken,
    // Stops the drive task when the last clone is dropped, and lets a shutdown
    // path wait until it has actually stopped.
    drive_task: TaskGroup,
    bedrock_signing_key: Ed25519Key,
    funding_key: ZkPublicKey,
    priority_fee: u64,
}

impl ZoneSdkPublisher {
    /// Runs one [`Command`] on the drive task and waits for its reply.
    async fn dispatch<T>(
        &self,
        command: impl FnOnce(oneshot::Sender<Result<T>>) -> Command,
    ) -> Result<T> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.command_tx
            .send(command(resp_tx))
            .await
            .map_err(|_closed| anyhow!("Drive task is no longer running"))?;
        resp_rx
            .await
            .map_err(|_closed| anyhow!("Drive task dropped the response"))?
    }
}

impl BlockPublisherTrait for ZoneSdkPublisher {
    async fn channel_exists(config: &BedrockConfig) -> Result<bool> {
        Ok(read_channel_state(config).await?.is_some())
    }

    async fn new(
        config: &BedrockConfig,
        bedrock_signing_key: Ed25519Key,
        resubmit_interval: Duration,
        initial_checkpoint: Option<SequencerCheckpoint>,
        on_follow: OnFollowSink,
    ) -> Result<Self> {
        let basic_auth = config.auth.clone().map(Into::into);
        let node = NodeHttpClient::new(CommonHttpClient::new(basic_auth), config.node_url.clone());

        let zone_sdk_config = ZoneSdkSequencerConfig {
            resubmit_interval,
            ..ZoneSdkSequencerConfig::new(FundingConfig {
                funding_pk: config.funding_key,
                max_tx_fee: GasCost::new(logos_blockchain_core::mantle::Value::MAX),
                priority_fee_percent: config.priority_fee,
            })
        };

        let mut sequencer = ZoneSequencer::init_with_config(
            config.channel_id,
            bedrock_signing_key.clone(),
            node.clone(),
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

        let driver_cancellation = CancellationToken::new();
        let driver_guard = driver_cancellation.clone().drop_guard();
        let drive_task = tokio::spawn(async move {
            // Dropped when this task ends (including panics in the sinks),
            // cancelling every `driver_cancellation`.
            let _driver_guard = driver_guard;
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
                                            .await
                                            .context("Failed to publish block")
                                    } else {
                                        sequencer.handle()
                                            .publish_atomic_withdraw(data_bounded, withdrawals)
                                            .await
                                            .context("Failed to publish block with withdrawals")
                                    };

                                    let msg_result = published.map(|(result, checkpoint)| PublishOutcome {
                                        this_msg: result.tx.inscription().this_msg,
                                        checkpoint,
                                        released_notes: released_notes(&result.tx),
                                    });
                                    match &msg_result {
                                        Ok(_) if withdraw_count == 0 => {
                                            log::info!("Published block with the size of {data_byte_size} bytes");
                                        }
                                        Ok(_) => {
                                            log::info!(
                                                "Published block with the size of {data_byte_size} bytes and {withdraw_count} bridge withdrawals",
                                            );
                                        }
                                        Err(e) => warn!("zone-sdk publish failed: {e:?}"),
                                    }
                                    let _dontcare = resp_tx.send(msg_result);
                                }
                                Command::SubmitChannelConfig {
                                    new_keys,
                                    resp: resp_tx,
                                } => {
                                    // zone-sdk funds from the node wallet, signs,
                                    // and enqueues this as its own independent
                                    // Mantle tx onto the drive loop's in-flight
                                    // pool — no manual bundling with any block
                                    // inscription.
                                    let result = sequencer
                                        .handle()
                                        .channel_config(
                                            new_keys,
                                            SlotTimeframe::from(
                                                system_accounts::DEFAULT_SEQUENCER_POSTING_TIMEFRAME,
                                            ),
                                            SlotTimeout::from(
                                                system_accounts::DEFAULT_SEQUENCER_POSTING_TIMEOUT,
                                            ),
                                            system_accounts::DEFAULT_SEQUENCER_CONFIGURATION_THRESHOLD,
                                            system_accounts::DEFAULT_SEQUENCER_WITHDRAW_THRESHOLD,
                                        )
                                        .await
                                        .map(|_| ())
                                        .context("Failed to submit channel-config update");

                                    match &result {
                                        Ok(()) => info!("Submitted committee channel-config update"),
                                        Err(err) => {
                                            warn!("Channel-config update submission failed: {err:?}");
                                        }
                                    }

                                    let _dontcare = resp_tx.send(result);
                                }
                                Command::SubmitSignedTx { tx, msg_id, resp: resp_tx } => {
                                    let submitted = sequencer
                                        .handle()
                                        .submit_signed_tx(*tx, msg_id)
                                        .context("Failed to submit pre-built channel transaction");
                                    let msg_result = submitted.map(|(result, checkpoint)| PublishOutcome {
                                        this_msg: result.tx.inscription().this_msg,
                                        checkpoint,
                                        released_notes: released_notes(&result.tx),
                                    });
                                    if let Err(e) = &msg_result {
                                        warn!("zone-sdk rejected the pre-built transaction: {e:?}");
                                    }
                                    let _dontcare = resp_tx.send(msg_result);
                                }
                            },
                        event = sequencer.next_event() => {
                            log::info!("========================== Received event {event:#?}");

                            match event {
                                Event::BlocksProcessed {
                                    checkpoint,
                                    channel_update,
                                    finalized,
                                } => {
                                    let adopted = channel_update
                                        .adopted
                                        .iter()
                                        .filter_map(channel_update_inscription)
                                        .filter_map(block_from_inscription)
                                        .collect();
                                    let orphaned = channel_update
                                        .orphaned
                                        .iter()
                                        .filter_map(channel_update_inscription)
                                        .filter_map(block_from_inscription)
                                        .collect();

                                    let mut finalized_blocks = Vec::new();
                                    let mut deposits = Vec::new();
                                    let mut withdrawals = Vec::new();
                                    for op in finalized.into_iter().flat_map(|item| item.ops) {
                                        match op {
                                            FinalizedOp::Inscription(inscription) => {
                                                if let Some(entry) = block_from_inscription(&inscription)
                                                {
                                                    finalized_blocks.push(entry);
                                                }
                                            }
                                            FinalizedOp::Deposit(deposit) => deposits.push(deposit),
                                            FinalizedOp::Withdraw(withdraw) => {
                                                withdrawals.push(withdraw);
                                            }
                                        }
                                    }

                                    on_follow(FollowUpdate {
                                        checkpoint,
                                        adopted,
                                        orphaned,
                                        finalized: finalized_blocks,
                                        deposits,
                                        withdrawals,
                                    }).await;
                                }
                                Event::Ready => {}
                                Event::TurnNotification { notification } => {
                                    log::info!(
                                        "Turn update: our_turn={}, starting_slot={:?}, ends_at_slot={:?}",
                                        notification.our_turn_to_write,
                                        notification.starting_slot,
                                        notification.ends_at_slot
                                    );
                                }
                                Event::MempoolPending(_tx_hash) => {}
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
            node,
            command_tx,
            turn_rx,
            driver_cancellation,
            drive_task: TaskGroup::new(vec![drive_task]),
            bedrock_signing_key,
            funding_key: config.funding_key,
            priority_fee: config.priority_fee,
        })
    }

    async fn publish_block(
        &self,
        block: &Block,
        withdrawals: Vec<WithdrawArg>,
    ) -> Result<PublishOutcome> {
        let data = borsh::to_vec(block).context("Failed to serialize block")?;
        let data_bounded: Inscription = data
            .try_into()
            .context("Block data exceeds maximum allowed size")?;

        self.dispatch(|resp| Command::Publish {
            inscription: data_bounded,
            withdrawals,
            resp,
        })
        .await
    }

    async fn publish_genesis_creating_channel(
        &self,
        block: &Block,
        keys: Vec<Ed25519PublicKey>,
    ) -> Result<PublishOutcome> {
        let own_key = self.bedrock_signing_key.public_key();
        ensure!(
            keys.first() == Some(&own_key),
            "Creating the channel requires our own key first; creation gives the turn to index 0"
        );
        let key_count = keys.len();
        let keys =
            Keys::try_from(keys).map_err(|err| anyhow!("Invalid channel key list: {err}"))?;

        let config_op = ChannelConfigOp {
            channel: self.channel_id,
            keys,
            posting_timeframe: SlotTimeframe::from(
                system_accounts::DEFAULT_SEQUENCER_POSTING_TIMEFRAME,
            ),
            posting_timeout: SlotTimeout::from(system_accounts::DEFAULT_SEQUENCER_POSTING_TIMEOUT),
            configuration_threshold: system_accounts::DEFAULT_SEQUENCER_CONFIGURATION_THRESHOLD,
            transfer_threshold: system_accounts::DEFAULT_SEQUENCER_WITHDRAW_THRESHOLD,
        };

        let data = borsh::to_vec(block).context("Failed to serialize genesis block")?;
        let inscription: Inscription = data
            .try_into()
            .context("Genesis block exceeds maximum allowed size")?;
        // The config op runs first and becomes the tip, so it is the parent.
        let inscribe_op = InscriptionOp {
            channel_id: self.channel_id,
            inscription,
            parent: config_op.id(),
            signer: own_key,
        };
        let msg_id = inscribe_op.id();

        let funded = fund_ops(
            &self.node,
            self.funding_key,
            self.priority_fee,
            [
                Op::ChannelConfig(config_op),
                Op::ChannelInscribe(inscribe_op),
            ],
        )
        .await?;
        let mantle_tx = funded.funded_tx;

        let signature = self
            .bedrock_signing_key
            .sign_payload(mantle_tx.hash().as_signing_bytes().as_ref());
        // Creation skips the channel-config signature check, but the proof must
        // still be well formed; index 0 is our own key.
        let config_proof =
            ChannelMultiSigProof::try_new(IndexedSignature::new(0, signature).into())
                .map_err(|err| anyhow!("Failed to assemble channel multi-sig proof: {err:?}"))?;

        let mut ops_proofs: OpsProofs = OpProof::ChannelMultiSigProof(config_proof).into();
        ops_proofs
            .try_push(OpProof::Ed25519Sig(signature))
            .map_err(|err| anyhow!("Too many operation proofs: {err:?}"))?;
        if let Some(transfer_proof) = funded.transfer_proof {
            ops_proofs
                .try_push(transfer_proof)
                .map_err(|err| anyhow!("Too many operation proofs: {err:?}"))?;
        }

        info!("Creating the channel with {key_count} accredited key(s), genesis block bundled");

        let tx = Box::new(SignedMantleTx::new(mantle_tx, ops_proofs));
        self.dispatch(|resp| Command::SubmitSignedTx { tx, msg_id, resp })
            .await
    }

    async fn accredited_keys(&self) -> Result<Vec<Ed25519PublicKey>> {
        Ok(self
            .node
            .channel_state(self.channel_id)
            .await
            .context("Failed to read channel state")?
            .map(|state| state.accredited_keys.to_vec())
            .unwrap_or_default())
    }

    async fn submit_channel_config(&self, new_keys: Vec<Ed25519PublicKey>) -> Result<()> {
        ensure!(
            !new_keys.is_empty(),
            "Refusing to submit a committee update with no accredited keys"
        );
        let new_keys =
            Keys::try_from(new_keys).map_err(|err| anyhow!("Invalid channel key list: {err}"))?;

        self.dispatch(|resp| Command::SubmitChannelConfig { new_keys, resp })
            .await
    }

    fn channel_id(&self) -> ChannelId {
        self.channel_id
    }

    fn is_our_turn(&self) -> bool {
        self.turn_rx.borrow().our_turn_to_write
    }

    fn driver_cancellation(&self) -> CancellationToken {
        self.driver_cancellation.clone()
    }

    fn background_tasks(&self) -> TaskGroup {
        self.drive_task.clone()
    }

    async fn channel_tip_slot(&self) -> Result<Option<Slot>> {
        Ok(self
            .node
            .channel_state(self.channel_id)
            .await
            .context("Failed to read channel state")?
            .map(|state| state.tip_slot))
    }

    /// Creates indexer in-place, then reads channel after checkpoint.
    async fn read_channel_after(
        &self,
        checkpoint: Option<SequencerCheckpoint>,
    ) -> impl Stream<Item = (ZoneMessage, SequencerCheckpoint)> + Send + '_ {
        chain_state::consistency::next_messages_own(self.node.clone(), self.channel_id, checkpoint)
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

/// Channel notes the withdraws bundled with a published tx release; empty for a
/// plain inscription. See [`PublishOutcome::released_notes`].
fn released_notes(tx: &PendingTx) -> Vec<NoteId> {
    match tx {
        PendingTx::Inscription(_) => Vec::new(),
        PendingTx::AtomicWithdraw(bundle) => bundle
            .withdraws
            .iter()
            .flat_map(|withdraw| withdraw.op.inputs.iter().copied())
            .collect(),
    }
}

/// The inscription carried by an orphaned tx (plain or atomic-withdraw bundle).
const fn channel_update_inscription(orphan: &ChannelUpdateTx) -> Option<&InscriptionInfo> {
    match orphan {
        ChannelUpdateTx::Inscription(info) => Some(info),
        ChannelUpdateTx::AtomicWithdraw(bundle) => Some(&bundle.inscription),
        ChannelUpdateTx::Custom(_signed_mantle_tx) => None,
    }
}

/// Funds `ops` from the node's wallet, which appends a fee transfer (paid from
/// `funding_key`, change back to it) and returns its proof.
async fn fund_ops(
    node: &NodeHttpClient,
    funding_key: ZkPublicKey,
    priority_fee: u64,
    ops: impl IntoIterator<Item = Op>,
) -> Result<logos_blockchain_http_api_common::bodies::wallet::fund::WalletFundResponseBody> {
    let tx_builder = MantleTxBuilder::new()
        .extend_ops(ops)
        .map_err(|err| anyhow!("Too many ops in channel transaction: {err:?}"))?;
    node.fund_tx(WalletFundRequestBody {
        tip: None,
        tx_builder,
        change_public_key: funding_key,
        funding_public_keys: vec![funding_key],
        max_tx_fee: GasCost::new(logos_blockchain_core::mantle::Value::MAX),
        priority_fee_percent: priority_fee,
    })
    .await
    .context("Failed to fund channel transaction")
}

/// Reads the channel's committee state from the bedrock node, without a running
/// sequencer. `None` means the channel does not exist yet.
pub async fn read_channel_state(config: &BedrockConfig) -> Result<Option<ChannelState>> {
    let node = NodeHttpClient::new(
        CommonHttpClient::new(config.auth.clone().map(Into::into)),
        config.node_url.clone(),
    );
    node.channel_state(config.channel_id)
        .await
        .context("Failed to read channel state")
}

/// Signs a `ChannelConfig` op (accredited keys + rotation params) with
/// `signing_key`, funds it from `config.funding_key` via the node's wallet,
/// and posts it straight to the bedrock node.
///
/// A standalone one-shot — no running sequencer involved, so authorization is
/// holding the admin key: the L1 rejects non-admin signers. `Ok(())` means the
/// node accepted the transaction; channel acceptance is asynchronous and a
/// rejection only shows up in node logs and on-chain behavior.
pub async fn post_channel_config(
    config: &BedrockConfig,
    signing_key: &Ed25519Key,
    keys: Vec<Ed25519PublicKey>,
    posting_timeframe: u32,
    posting_timeout: u32,
    configuration_threshold: u16,
    transfer_threshold: u16,
) -> Result<()> {
    ensure!(!keys.is_empty(), "Channel key list must not be empty");
    for (name, threshold) in [
        ("configuration_threshold", configuration_threshold),
        ("transfer_threshold", transfer_threshold),
    ] {
        ensure!(
            threshold >= 1 && usize::from(threshold) <= keys.len(),
            "{name} must be between 1 and the key count ({}), got {threshold}",
            keys.len()
        );
    }
    ensure!(
        posting_timeframe > 0 && posting_timeout >= posting_timeframe,
        "posting_timeframe must be nonzero and posting_timeout at least as long, \
         got {posting_timeframe} and {posting_timeout}"
    );

    let keys = Keys::try_from(keys).map_err(|err| anyhow!("Invalid channel key list: {err}"))?;
    let config_op = ChannelConfigOp {
        channel: config.channel_id,
        keys,
        posting_timeframe: SlotTimeframe::from(posting_timeframe),
        posting_timeout: SlotTimeout::from(posting_timeout),
        configuration_threshold,
        transfer_threshold,
    };

    let node = NodeHttpClient::new(
        CommonHttpClient::new(config.auth.clone().map(Into::into)),
        config.node_url.clone(),
    );

    let funded = fund_ops(
        &node,
        config.funding_key,
        config.priority_fee,
        [Op::ChannelConfig(config_op)],
    )
    .await?;
    let mantle_tx = funded.funded_tx;

    // Sign the funded tx: the appended fee transfer changes the hash.
    let tx_hash = mantle_tx.hash();
    // The admin key is `keys[0]`, hence signature index 0.
    let signature = IndexedSignature::new(
        0,
        signing_key.sign_payload(tx_hash.as_signing_bytes().as_ref()),
    );
    let proof = ChannelMultiSigProof::try_new(signature.into())
        .map_err(|err| anyhow!("Failed to assemble channel multi-sig proof: {err:?}"))?;

    // Proofs follow op order; funding appends the transfer as the last op.
    let mut ops_proofs: OpsProofs = OpProof::ChannelMultiSigProof(proof).into();
    if let Some(transfer_proof) = funded.transfer_proof {
        ops_proofs
            .try_push(transfer_proof)
            .map_err(|err| anyhow!("Too many operation proofs: {err:?}"))?;
    }
    let signed_tx = SignedMantleTx::new(mantle_tx, ops_proofs);

    node.post_transaction(signed_tx)
        .await
        .context("Failed to post channel config transaction")
}
