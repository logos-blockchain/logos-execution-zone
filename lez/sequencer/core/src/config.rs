use std::{
    fs::File,
    io::BufReader,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Result, ensure};
use common::config::BasicAuth;
pub use cross_zone_inbox_core::{CrossZoneConfig, CrossZonePeer, CrossZoneRoute};
use humantime_serde;
use lee::{AccountId, PublicKey, Signature};
use logos_blockchain_core::mantle::ops::channel::ChannelId;
pub use sequencer_stake_core::ChannelParams;
use serde::{Deserialize, Serialize};
use url::Url;

/// Bytes reserved out of `max_block_size` for the block header plus the forced
/// fee and clock tail transactions; RPC and gossip cap a single transaction at
/// `max_block_size - BLOCK_OVERHEAD`.
pub const BLOCK_OVERHEAD: u64 = 2_048;

/// The largest usable `max_block_size`: an L2 block is published to Bedrock as
/// a single inscription, which the L1 caps at this many bytes.
#[expect(
    clippy::as_conversions,
    reason = "usize::try_from is not const & usize fits u64 on every supported target"
)]
pub const MAX_PUBLISHABLE_BLOCK_SIZE: u64 =
    logos_blockchain_core::mantle::ops::channel::inscribe::MAX_BYTES as u64;

/// A transaction to be applied at genesis to supply initial balances.
///
/// Amounts are `u64`, not [`lee::Balance`], because every one is funded through
/// the bridge's `Deposit`, whose amount is `u64`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenesisAction {
    SupplyAccount {
        account_id: AccountId,
        balance: u64,
    },
    /// Funds a holder's holding PDA at genesis with one replayable genesis
    /// credit; the balance-only PDA needs no claim.
    SupplyBridgeLockHolding {
        holder: AccountId,
        amount: u64,
    },
    /// Stakes `sequencer_key` at genesis.
    StakeSequencer {
        sequencer_key: sequencer_stake_core::SequencerKey,
        ownership_public_key: PublicKey,
        stake_signature: Signature,
    },
}

/// Sequencer p2p gossip configuration. Absent (`None`) disables gossip
/// entirely: no sockets, no background tasks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipConfig {
    /// Multiaddr to listen on.
    #[serde(default = "default_gossip_listen_addr")]
    pub listen_addr: libp2p::Multiaddr,
    /// Peer multiaddrs to dial at startup, optionally with `/p2p/<peer_id>`.
    #[serde(default)]
    pub bootstrap_peers: Vec<libp2p::Multiaddr>,
}

// TODO: Provide default values
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SequencerConfig {
    /// Home dir of sequencer storage. Holds `channel_signing_key`, and
    /// `sequencer_stake_signing_key` when a solo sequencer creates the channel.
    pub home: PathBuf,
    /// Maximum number of user transactions in a block (excludes the mandatory clock transaction).
    pub max_num_tx_in_block: usize,
    /// Mempool maximum size.
    pub mempool_max_size: usize,
    /// Interval in which blocks produced.
    #[serde(with = "humantime_serde")]
    pub block_create_timeout: Duration,
    /// Interval in which pending blocks are retried.
    #[serde(with = "humantime_serde")]
    pub retry_pending_blocks_timeout: Duration,
    /// Bedrock configuration options.
    pub bedrock_config: BedrockConfig,
    /// What creating the channel writes into genesis; only read when the channel does not exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genesis: Option<GenesisConfig>,
    /// Presence selects the genesis program set, must match the indexer's, and
    /// cannot change on an existing chain. A source-only zone declares
    /// `"cross_zone": {}`.
    #[serde(default)]
    pub cross_zone: Option<CrossZoneConfig>,
    /// Address the Prometheus metrics exporter binds to.
    #[serde(default = "default_metrics_address")]
    pub metrics_address: Option<SocketAddr>,
    /// Sequencer p2p gossip configuration. `None` disables gossip.
    #[serde(default)]
    pub gossip: Option<GossipConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BedrockConfig {
    /// Bedrock channel ID.
    pub channel_id: ChannelId,
    /// Bedrock Url.
    pub node_url: Url,
    /// Bedrock auth.
    pub auth: Option<BasicAuth>,
    #[serde(default = "default_priority_fee_percent")]
    pub priority_fee_percent: u64,
}

/// The values a new channel is created with.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisConfig {
    /// Fixed for the chain's life; every other node reads them from the chain.
    pub channel_params: ChannelParams,
    #[serde(default)]
    pub actions: Vec<GenesisAction>,
}

impl SequencerConfig {
    /// Address [`Self::metrics_address`] falls back to when the config omits it.
    pub const DEFAULT_METRICS_ADDRESS: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9000);

    pub fn from_path(config_home: &Path) -> Result<Self> {
        let file = File::open(config_home)?;
        let reader = BufReader::new(file);
        let config: Self = serde_json::from_reader(reader)?;
        if let Some(genesis) = &config.genesis {
            check_channel_params(&genesis.channel_params, config.block_create_timeout)?;
        }
        Ok(config)
    }

    /// Where this sequencer's database lives, suffixed with the channel id like
    /// the indexer's, so several sequencers can share a home directory. Only the
    /// database is per-channel; `channel_signing_key` stays unsuffixed, so
    /// sequencers sharing a home share one channel signing key.
    #[must_use]
    pub fn db_path(&self) -> PathBuf {
        self.home
            .join(format!("rocksdb-{}", self.bedrock_config.channel_id))
    }
}

/// Checks channel params against what this node and Bedrock can work with.
pub fn check_channel_params(params: &ChannelParams, block_create_timeout: Duration) -> Result<()> {
    ensure!(
        keeps_turn(params, block_create_timeout),
        "block_create_timeout ({block_create_timeout:?}) must be under posting_timeout ({}s)",
        params.posting_timeout
    );
    check_max_block_size(params)
}

/// Whether blocks every `block_create_timeout` hold a turn: one passes on after
/// `posting_timeout` idle slots (1 slot = 1s).
#[must_use]
pub fn keeps_turn(params: &ChannelParams, block_create_timeout: Duration) -> bool {
    block_create_timeout < Duration::from_secs(u64::from(params.posting_timeout))
}

/// Checks `max_block_size` against what a block must hold and what Bedrock can carry.
pub fn check_max_block_size(params: &ChannelParams) -> Result<()> {
    ensure!(
        (sequencer_stake_core::MIN_MAX_BLOCK_SIZE..=MAX_PUBLISHABLE_BLOCK_SIZE)
            .contains(&params.max_block_size),
        "max_block_size {} must be between {} and Bedrock's inscription limit of \
         {MAX_PUBLISHABLE_BLOCK_SIZE} bytes",
        params.max_block_size,
        sequencer_stake_core::MIN_MAX_BLOCK_SIZE
    );
    Ok(())
}

fn default_gossip_listen_addr() -> libp2p::Multiaddr {
    "/ip4/0.0.0.0/udp/0/quic-v1"
        .parse()
        .expect("hardcoded default gossip listen addr is a valid multiaddr")
}

#[expect(clippy::unnecessary_wraps, reason = "Required by serde")]
const fn default_metrics_address() -> Option<SocketAddr> {
    Some(SequencerConfig::DEFAULT_METRICS_ADDRESS)
}

/// Percentage of the mandatory fee reserved on every funded Bedrock
/// transaction, covering a gas price rise before it is mined.
#[must_use]
pub const fn default_priority_fee_percent() -> u64 {
    12
}

/// Production defaults for the values genesis fixes.
#[must_use]
pub const fn default_channel_params() -> ChannelParams {
    ChannelParams {
        minimum_sequencer_stake: system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE,
        posting_timeframe: system_accounts::DEFAULT_SEQUENCER_POSTING_TIMEFRAME,
        posting_timeout: system_accounts::DEFAULT_SEQUENCER_POSTING_TIMEOUT,
        exit_delay: system_accounts::DEFAULT_SEQUENCER_EXIT_DELAY,
        max_block_size: system_accounts::DEFAULT_MAX_BLOCK_SIZE,
    }
}
