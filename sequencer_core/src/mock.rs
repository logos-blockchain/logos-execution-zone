use std::time::Duration;

use anyhow::Result;
use common::block::Block;
use logos_blockchain_key_management_system_service::keys::Ed25519Key;
use logos_blockchain_zone_sdk::sequencer::SequencerCheckpoint;
use url::Url;

use crate::{
    block_publisher::BlockPublisherTrait, config::BedrockConfig, indexer_client::IndexerClientTrait,
};

pub type SequencerCoreWithMockClients = crate::SequencerCore<MockBlockPublisher, MockIndexerClient>;

#[derive(Clone)]
pub struct MockBlockPublisher;

impl BlockPublisherTrait for MockBlockPublisher {
    async fn new(
        _config: &BedrockConfig,
        _bedrock_signing_key: Ed25519Key,
        _checkpoint: Option<SequencerCheckpoint>,
        _resubmit_interval: Duration,
    ) -> Result<Self> {
        Ok(Self)
    }

    async fn publish_block(&self, _block: &Block) -> Result<SequencerCheckpoint> {
        use logos_blockchain_core::{header::HeaderId, mantle::ops::channel::MsgId};

        Ok(SequencerCheckpoint {
            last_msg_id: MsgId::from([0; 32]),
            pending_txs: vec![],
            lib: HeaderId::from([0; 32]),
            lib_slot: 0.into(),
        })
    }
}

#[derive(Copy, Clone)]
pub struct MockIndexerClient;

impl IndexerClientTrait for MockIndexerClient {
    async fn new(_indexer_url: &Url) -> Result<Self> {
        Ok(Self)
    }
}
