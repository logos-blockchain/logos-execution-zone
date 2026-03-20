use std::{
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Result;
use bedrock_client::BackoffConfig;
use bytesize::ByteSize;
use common::config::BasicAuth;
use humantime_serde;
use logos_blockchain_core::mantle::ops::channel::ChannelId;
use serde::{Deserialize, Serialize};
use testnet_initial_state::{PrivateAccountPublicInitialData, PublicAccountPublicInitialData};
use url::Url;

// TODO: Provide default values
#[derive(Clone, Serialize, Deserialize)]
pub struct SequencerConfig {
    /// Home dir of sequencer storage.
    pub home: PathBuf,
    /// Genesis id.
    pub genesis_id: u64,
    /// If `True`, then adds random sequence of bytes to genesis block.
    pub is_genesis_random: bool,
    /// Maximum number of transactions in block.
    pub max_num_tx_in_block: usize,
    /// Maximum block size (includes header and transactions).
    #[serde(default = "default_max_block_size")]
    pub max_block_size: ByteSize,
    /// Mempool maximum size.
    pub mempool_max_size: usize,
    /// Interval in which blocks produced.
    #[serde(with = "humantime_serde")]
    pub block_create_timeout: Duration,
    /// Interval in which pending blocks are retried.
    #[serde(with = "humantime_serde")]
    pub retry_pending_blocks_timeout: Duration,
    /// Sequencer own signing key.
    pub signing_key: [u8; 32],
    /// Bedrock configuration options.
    pub bedrock_config: BedrockConfig,
    /// Indexer RPC URL.
    pub indexer_rpc_url: Url,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_public_accounts: Option<Vec<PublicAccountPublicInitialData>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_private_accounts: Option<Vec<PrivateAccountPublicInitialData>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BedrockConfig {
    /// Fibonacci backoff retry strategy configuration.
    #[serde(default)]
    pub backoff: BackoffConfig,
    /// Bedrock channel ID.
    pub channel_id: ChannelId,
    /// Bedrock Url.
    pub node_url: Url,
    /// Bedrock auth.
    pub auth: Option<BasicAuth>,
}

impl SequencerConfig {
    pub fn from_path(config_home: &Path) -> Result<Self> {
        let file = File::open(config_home)?;
        let reader = BufReader::new(file);

        Ok(serde_json::from_reader(reader)?)
    }
}

const fn default_max_block_size() -> ByteSize {
    ByteSize::mib(1)
}
