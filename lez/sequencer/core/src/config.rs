use std::{
    fs::File,
    io::BufReader,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Result;
use bytesize::ByteSize;
use common::config::BasicAuth;
pub use cross_zone_inbox_core::{CrossZoneConfig, CrossZonePeer, CrossZoneRoute};
use fee_core::params::MAX_GAS_STOR;
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
    ///
    /// An *operational* envelope, local to this sequencer: how large a block it is willing to
    /// serialize and inscribe. It is not the consensus bound. That is `MAX_GAS_STOR`
    /// (`1_000_000` bytes of charged transaction payload), which every node enforces in the block
    /// transition and which no configuration can raise or lower.
    ///
    /// Set below [`SequencerConfig::min_max_block_size`] it silently under-cuts consensus
    /// capacity: blocks stop filling at the local limit while the protocol would still accept
    /// more. [`SequencerConfig::check_block_size_envelope`] reports that at startup.
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
    /// Address the Prometheus metrics exporter binds to.
    #[serde(default = "default_metrics_address")]
    pub metrics_address: Option<SocketAddr>,
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
    #[serde(default = "default_priority_fee")]
    pub priority_fee: u64,
}

impl SequencerConfig {
    /// What a block spends on top of the transaction bytes the consensus storage cap counts: the
    /// header (block id, both hashes, timestamp, producer key and signature), the mandatory clock
    /// transaction, and borsh's length prefixes. Those are hundreds of bytes in practice; 16 KiB is
    /// a deliberately wide margin, chosen so the 1 MiB default clears it comfortably.
    pub const BLOCK_FRAMING_ALLOWANCE: ByteSize = ByteSize::kib(16);
    /// Address [`Self::metrics_address`] falls back to when the config omits it.
    pub const DEFAULT_METRICS_ADDRESS: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9000);

    /// The smallest [`Self::max_block_size`] that still lets a block carry a full consensus
    /// storage cap's worth of transactions: `MAX_GAS_STOR` plus [`Self::BLOCK_FRAMING_ALLOWANCE`].
    #[must_use]
    pub const fn min_max_block_size() -> ByteSize {
        ByteSize::b(MAX_GAS_STOR.saturating_add(Self::BLOCK_FRAMING_ALLOWANCE.as_u64()))
    }

    /// Checks the operational block-size envelope against consensus capacity.
    ///
    /// # Errors
    ///
    /// A rendered, actionable message when [`Self::max_block_size`] cuts blocks short of what the
    /// protocol would accept. Not fatal — a smaller local limit produces smaller blocks, never
    /// invalid ones — so callers log it rather than refuse to start.
    pub fn check_block_size_envelope(&self) -> Result<(), String> {
        let minimum = Self::min_max_block_size();
        if self.max_block_size >= minimum {
            return Ok(());
        }
        Err(format!(
            "max_block_size is {} ({} bytes), below the {} ({} bytes) a block needs to carry a full \
             MAX_GAS_STOR ({MAX_GAS_STOR} bytes) of transactions plus {} of block framing. Blocks \
             will stop filling before they reach the consensus storage cap; raise max_block_size to \
             at least \"{minimum}\" to use the whole cap, or keep it if smaller blocks are intended.",
            self.max_block_size,
            self.max_block_size.as_u64(),
            minimum,
            minimum.as_u64(),
            Self::BLOCK_FRAMING_ALLOWANCE,
        ))
    }

    pub fn from_path(config_home: &Path) -> Result<Self> {
        let file = File::open(config_home)?;
        let reader = BufReader::new(file);

        Ok(serde_json::from_reader(reader)?)
    }
}

const fn default_max_block_size() -> ByteSize {
    ByteSize::mib(1)
}

#[expect(clippy::unnecessary_wraps, reason = "Required by serde")]
const fn default_metrics_address() -> Option<SocketAddr> {
    Some(SequencerConfig::DEFAULT_METRICS_ADDRESS)
}

#[must_use]
pub const fn default_priority_fee() -> u64 {
    logos_blockchain_zone_sdk::sequencer::FundingConfig::DEFAULT_PRIORITY_FEE
}
