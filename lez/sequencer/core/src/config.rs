use std::{
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Result;
use bytesize::ByteSize;
use common::config::BasicAuth;
pub use cross_zone_inbox_core::{CrossZoneConfig, CrossZonePeer};
use humantime_serde;
use lee::{AccountId, Balance};
use logos_blockchain_core::mantle::ops::channel::ChannelId;
use logos_blockchain_key_management_system_service::keys::ZkPublicKey;
use serde::{Deserialize, Serialize};
use url::Url;

/// A transaction to be applied at genesis to supply initial balances.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenesisAction {
    SupplyAccount {
        account_id: AccountId,
        balance: Balance,
    },
    SupplyBridgeAccount {
        balance: Balance,
    },
    /// Seeds a bridge-lock holder's initial bridgeable balance into genesis state.
    SupplyBridgeLockHolding {
        holder: AccountId,
        amount: Balance,
    },
}

// TODO: Provide default values
#[derive(Clone, Serialize, Deserialize)]
pub struct SequencerConfig {
    /// Home dir of sequencer storage.
    pub home: PathBuf,
    /// Maximum number of user transactions in a block (excludes the mandatory clock transaction).
    pub max_num_tx_in_block: usize,
    /// Maximum block size (includes header, user transactions, and the mandatory clock
    /// transaction).
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
    /// Genesis configuration.
    #[serde(default)]
    pub genesis: Vec<GenesisAction>,
    /// Cross-zone messaging configuration. `None` disables the watcher.
    #[serde(default)]
    pub cross_zone: Option<CrossZoneConfig>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BedrockConfig {
    /// Bedrock channel ID.
    pub channel_id: ChannelId,
    /// Bedrock Url.
    pub node_url: Url,
    /// Bedrock auth.
    pub auth: Option<BasicAuth>,
    pub funding_key: ZkPublicKey,
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
