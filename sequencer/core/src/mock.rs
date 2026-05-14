use anyhow::{Result, anyhow};
use bedrock_client::SignedMantleTx;
use logos_blockchain_core::mantle::ops::channel::ChannelId;
use logos_blockchain_key_management_system_service::keys::Ed25519Key;
use url::Url;

use crate::{
    block_settlement_client::BlockSettlementClientTrait, config::BedrockConfig,
    indexer_client::IndexerClientTrait,
};

pub type SequencerCoreWithMockClients =
    crate::SequencerCore<MockBlockSettlementClient, MockIndexerClient>;

#[derive(Clone)]
pub struct MockBlockSettlementClient {
    bedrock_channel_id: ChannelId,
    bedrock_signing_key: Ed25519Key,
}

impl BlockSettlementClientTrait for MockBlockSettlementClient {
    fn new(config: &BedrockConfig, signing_key: Ed25519Key) -> Result<Self> {
        Ok(Self {
            bedrock_channel_id: config.channel_id,
            bedrock_signing_key: signing_key,
        })
    }

    fn bedrock_channel_id(&self) -> ChannelId {
        self.bedrock_channel_id
    }

    fn bedrock_signing_key(&self) -> &Ed25519Key {
        &self.bedrock_signing_key
    }

    async fn submit_inscribe_tx_to_bedrock(&self, _tx: SignedMantleTx) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct MockBlockSettlementClientWithError {
    bedrock_channel_id: ChannelId,
    bedrock_signing_key: Ed25519Key,
}

impl BlockSettlementClientTrait for MockBlockSettlementClientWithError {
    fn new(config: &BedrockConfig, signing_key: Ed25519Key) -> Result<Self> {
        Ok(Self {
            bedrock_channel_id: config.channel_id,
            bedrock_signing_key: signing_key,
        })
    }

    fn bedrock_channel_id(&self) -> ChannelId {
        self.bedrock_channel_id
    }

    fn bedrock_signing_key(&self) -> &Ed25519Key {
        &self.bedrock_signing_key
    }

    async fn submit_inscribe_tx_to_bedrock(&self, _tx: SignedMantleTx) -> Result<()> {
        Err(anyhow!("Mock error"))
    }
}

#[derive(Copy, Clone)]
pub struct MockIndexerClient;

impl IndexerClientTrait for MockIndexerClient {
    async fn new(_indexer_url: &Url) -> Result<Self> {
        Ok(Self)
    }
}
