use std::{path::Path, sync::Arc};

use anyhow::{Context, Result};
use common::block::Block;
use log::info;
pub use logos_blockchain_core::mantle::ops::channel::MsgId;
pub use logos_blockchain_key_management_system_service::keys::Ed25519Key;
use logos_blockchain_zone_sdk::sequencer::{
    PublishResult, SequencerCheckpoint, SequencerConfig as ZoneSdkSequencerConfig, ZoneSequencer,
};
use url::Url;

use crate::config::BedrockConfig;

/// Trait for publishing L2 blocks to the L1 chain.
#[expect(async_fn_in_trait, reason = "We don't care about Send/Sync here")]
pub trait BlockPublisherTrait: Clone {
    /// Initialize the publisher.
    async fn new(
        config: &BedrockConfig,
        bedrock_signing_key: Ed25519Key,
        checkpoint: Option<SequencerCheckpoint>,
    ) -> Result<Self>;

    /// Publish a block. Returns the checkpoint to persist.
    async fn publish_block(&self, block: &Block) -> Result<SequencerCheckpoint>;
}

/// Real block publisher backed by zone-sdk's ZoneSequencer.
#[derive(Clone)]
pub struct ZoneSdkPublisher {
    sequencer: Arc<ZoneSequencer>,
}

impl BlockPublisherTrait for ZoneSdkPublisher {
    async fn new(
        config: &BedrockConfig,
        bedrock_signing_key: Ed25519Key,
        checkpoint: Option<SequencerCheckpoint>,
    ) -> Result<Self> {
        let auth = config.auth.clone().map(Into::into);

        let sequencer = ZoneSequencer::init_with_config(
            config.channel_id,
            bedrock_signing_key,
            Url::from(config.node_url.clone()),
            auth,
            ZoneSdkSequencerConfig::default(),
            checkpoint,
        );

        Ok(Self {
            sequencer: Arc::new(sequencer),
        })
    }

    async fn publish_block(&self, block: &Block) -> Result<SequencerCheckpoint> {
        let data = borsh::to_vec(block).context("Failed to serialize block")?;
        let PublishResult { checkpoint, .. } = self
            .sequencer
            .publish(data)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        Ok(checkpoint)
    }
}

const CHECKPOINT_FILE_NAME: &str = "zone_sdk_checkpoint.json";

/// Load a persisted checkpoint from the sequencer home directory.
pub fn load_checkpoint(home: &Path) -> Result<Option<SequencerCheckpoint>> {
    let path = home.join(CHECKPOINT_FILE_NAME);
    if path.exists() {
        let data = std::fs::read(&path).context("Failed to read checkpoint file")?;
        let checkpoint: SequencerCheckpoint =
            serde_json::from_slice(&data).context("Failed to deserialize checkpoint")?;
        info!("Loaded zone-sdk checkpoint from {}", path.display());
        Ok(Some(checkpoint))
    } else {
        Ok(None)
    }
}

/// Persist a checkpoint to the sequencer home directory.
pub fn save_checkpoint(home: &Path, checkpoint: &SequencerCheckpoint) -> Result<()> {
    let path = home.join(CHECKPOINT_FILE_NAME);
    let data = serde_json::to_vec(checkpoint).context("Failed to serialize checkpoint")?;
    std::fs::write(&path, data).context("Failed to write checkpoint file")?;
    Ok(())
}
