use std::{
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Result;
use bedrock_client::BackoffConfig;
use bytesize::ByteSize;
use common::{
    block::{AccountInitialData, CommitmentsInitialData},
    config::BasicAuth,
};
use humantime_serde;
use logos_blockchain_core::mantle::ops::channel::ChannelId;
use serde::{Deserialize, Serialize};
use url::Url;

// TODO: Provide default values
#[derive(Clone, Serialize, Deserialize)]
pub struct SequencerConfig {
    /// Home dir of sequencer storage.
    pub home: PathBuf,
    /// Override rust log (env var logging level).
    pub override_rust_log: Option<String>,
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
    /// Port to listen.
    pub port: u16,
    /// List of initial accounts data.
    pub initial_accounts: Vec<AccountInitialData>,
    /// List of initial commitments.
    pub initial_commitments: Vec<CommitmentsInitialData>,
    /// Sequencer own signing key.
    pub signing_key: [u8; 32],
    /// Bedrock configuration options.
    pub bedrock_config: BedrockConfig,
    /// Indexer RPC URL.
    pub indexer_rpc_url: Url,
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
