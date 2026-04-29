use std::{sync::Arc, time::Duration};

use anyhow::{Context as _, Result, anyhow};
use common::block::Block;
pub use logos_blockchain_core::mantle::ops::channel::MsgId;
pub use logos_blockchain_key_management_system_service::keys::Ed25519Key;
pub use logos_blockchain_zone_sdk::sequencer::SequencerCheckpoint;
use logos_blockchain_zone_sdk::{
    CommonHttpClient,
    adapter::NodeHttpClient,
    sequencer::{Event, SequencerConfig as ZoneSdkSequencerConfig, SequencerHandle, ZoneSequencer},
};
use tokio::task::JoinHandle;

use crate::config::BedrockConfig;

/// Sink for `Event::Published` checkpoints emitted by the drive task.
/// Caller is responsible for persistence (e.g. writing to rocksdb).
pub type CheckpointSink = Box<dyn Fn(SequencerCheckpoint) + Send + Sync + 'static>;

#[expect(async_fn_in_trait, reason = "We don't care about Send/Sync here")]
pub trait BlockPublisherTrait: Clone {
    async fn new(
        config: &BedrockConfig,
        bedrock_signing_key: Ed25519Key,
        resubmit_interval: Duration,
        initial_checkpoint: Option<SequencerCheckpoint>,
        on_checkpoint: CheckpointSink,
    ) -> Result<Self>;

    /// Fire-and-forget publish. Zone-sdk drives the actual submission and
    /// retries internally; this just hands the payload off.
    async fn publish_block(&self, block: &Block) -> Result<()>;
}

/// Real block publisher backed by zone-sdk's `ZoneSequencer`.
#[derive(Clone)]
pub struct ZoneSdkPublisher {
    handle: SequencerHandle<NodeHttpClient>,
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
    ) -> Result<Self> {
        let basic_auth = config.auth.clone().map(Into::into);
        let node = NodeHttpClient::new(CommonHttpClient::new(basic_auth), config.node_url.clone());

        let zone_sdk_config = ZoneSdkSequencerConfig {
            resubmit_interval,
            ..ZoneSdkSequencerConfig::default()
        };

        let (mut sequencer, mut handle) = ZoneSequencer::init_with_config(
            config.channel_id,
            bedrock_signing_key,
            node,
            zone_sdk_config,
            initial_checkpoint,
        );

        let drive_task = tokio::spawn(async move {
            loop {
                if let Some(Event::Published { checkpoint, .. }) = sequencer.next_event().await {
                    on_checkpoint(checkpoint);
                }
            }
        });

        handle.wait_ready().await;

        Ok(Self {
            handle,
            _drive_task: Arc::new(DriveTaskGuard(drive_task)),
        })
    }

    async fn publish_block(&self, block: &Block) -> Result<()> {
        let data = borsh::to_vec(block).context("Failed to serialize block")?;
        self.handle
            .publish_message(data)
            .await
            .map_err(|e| anyhow!("zone-sdk publish failed: {e}"))?;
        Ok(())
    }
}
