use std::{
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context as _, Result};
pub use bedrock_client::BackoffConfig;
use common::config::BasicAuth;
use humantime_serde;
pub use logos_blockchain_core::mantle::ops::channel::ChannelId;
use serde::{Deserialize, Serialize};
use testnet_initial_state::{PrivateAccountPublicInitialData, PublicAccountPublicInitialData};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// For individual RPC requests we use Fibonacci backoff retry strategy.
    pub backoff: BackoffConfig,
    pub addr: Url,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<BasicAuth>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexerConfig {
    /// Home dir of sequencer storage.
    pub home: PathBuf,
    /// Sequencers signing key.
    pub signing_key: [u8; 32],
    #[serde(with = "humantime_serde")]
    pub consensus_info_polling_interval: Duration,
    pub bedrock_client_config: ClientConfig,
    pub channel_id: ChannelId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_public_accounts: Option<Vec<PublicAccountPublicInitialData>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_private_accounts: Option<Vec<PrivateAccountPublicInitialData>>,
}

impl IndexerConfig {
    pub fn from_path(config_path: &Path) -> Result<Self> {
        let file = File::open(config_path).with_context(|| {
            format!("Failed to open indexer config at {}", config_path.display())
        })?;
        let reader = BufReader::new(file);

        serde_json::from_reader(reader).with_context(|| {
            format!(
                "Failed to parse indexer config at {}",
                config_path.display()
            )
        })
    }
}
