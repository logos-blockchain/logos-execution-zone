use std::time::Duration;

use anyhow::Result;
use common::block::Block;
use logos_blockchain_key_management_system_service::keys::Ed25519Key;
use url::Url;

use crate::{
    block_publisher::{BlockPublisherTrait, CheckpointSink, SequencerCheckpoint},
    config::BedrockConfig,
    indexer_client::IndexerClientTrait,
};

pub type SequencerCoreWithMockClients = crate::SequencerCore<MockBlockPublisher, MockIndexerClient>;

#[derive(Clone)]
pub struct MockBlockPublisher;

impl BlockPublisherTrait for MockBlockPublisher {
    async fn new(
        _config: &BedrockConfig,
        _bedrock_signing_key: Ed25519Key,
        _resubmit_interval: Duration,
        _initial_checkpoint: Option<SequencerCheckpoint>,
        _on_checkpoint: CheckpointSink,
    ) -> Result<Self> {
        Ok(Self)
    }

    async fn publish_block(&self, _block: &Block) -> Result<()> {
        Ok(())
    }
}

#[derive(Copy, Clone)]
pub struct MockIndexerClient;

impl IndexerClientTrait for MockIndexerClient {
    async fn new(_indexer_url: &Url) -> Result<Self> {
        Ok(Self)
    }
}
