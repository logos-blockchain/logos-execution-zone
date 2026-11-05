use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZero,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context as _, Result, ensure};
pub use bridge_core::DepositRecipient;
use common::config::BasicAuth;
pub use cross_zone_inbox_core::{CrossZoneConfig, CrossZonePeer, CrossZoneRoute};
use humantime_serde;
use logos_blockchain_core::mantle::ops::channel::ChannelId;
use logos_blockchain_key_management_system_service::keys::ZkPublicKey;
pub use sequencer_genesis::GenesisAction;
use sequencer_genesis::GenesisSpec;
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

/// The largest Bedrock transaction: the L1 caps a block's transactions at this
/// many bytes.
#[expect(
    clippy::as_conversions,
    reason = "usize::try_from is not const & usize fits u64 on every supported target"
)]
pub const MAX_BEDROCK_TX_SIZE: u64 =
    logos_blockchain_core::block::MAX_BLOCK_TRANSACTIONS_SIZE as u64;

/// Smallest nonzero `stale_refund_slots`, since a shorter window orphans blocks before L1 can
/// mine them.
const MIN_STALE_REFUND_SLOTS: u64 = 50;

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
    #[serde(default = "default_metrics_listen_address")]
    pub metrics_listen_address: Option<SocketAddr>,
    /// Sequencer p2p gossip configuration. `None` disables gossip.
    #[serde(default)]
    pub gossip: Option<GossipConfig>,
    /// Overrides `<home>/channel_signing_key`.
    /// This is a "per-node" setting, and should not be read from a shared config.
    #[serde(skip)]
    pub channel_signing_key_file: Option<PathBuf>,
    /// Overrides `<home>/bedrock_funding_public_key`.
    /// This is a "per-node" setting, and should not be read from a shared config.
    #[serde(skip)]
    pub funding_public_key: Option<ZkPublicKey>,
    /// Without a `genesis`, waits for the channel's creator instead of failing when the channel
    /// does not exist yet.
    /// This is a "per-node" setting, and should not be read from a shared config.
    #[serde(skip)]
    pub wait_for_channel: bool,
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
    #[serde(default = "default_stale_refund_slots")]
    pub stale_refund_slots: u64,
    #[serde(default = "default_backfill_batch_slots")]
    pub backfill_batch_slots: NonZero<u64>,
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
    /// Address [`Self::metrics_listen_address`] falls back to when the config omits it.
    pub const DEFAULT_METRICS_LISTEN_ADDRESS: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9000);

    pub fn from_path(path: &Path) -> Result<Self> {
        Self::from_json(&std::fs::read_to_string(path)?)
    }

    pub fn from_json(json: &str) -> Result<Self> {
        let config: Self = serde_json::from_str(json)?;
        if let Some(genesis) = &config.genesis {
            check_channel_params(&genesis.channel_params, config.block_create_timeout)?;
        }
        let stale_refund_slots = config.bedrock_config.stale_refund_slots;
        ensure!(
            stale_refund_slots == 0 || stale_refund_slots >= MIN_STALE_REFUND_SLOTS,
            "stale_refund_slots ({stale_refund_slots}) must be 0 or at least \
             {MIN_STALE_REFUND_SLOTS}"
        );
        Ok(config)
    }

    /// The genesis this config describes, or a placeholder with the default channel params when
    /// [`Self::genesis`] is absent.
    ///
    /// When [`Self::genesis`] stakes no sequencer, `bootstrap_sequencer_key` is staked by the key
    /// in `<home>/sequencer_stake_signing_key`, created on first use.
    pub fn genesis_spec(
        &self,
        bootstrap_sequencer_key: Option<sequencer_stake_core::SequencerKey>,
    ) -> Result<GenesisSpec> {
        let mut spec = GenesisSpec {
            channel_id: *self.bedrock_config.channel_id.as_ref(),
            channel_params: default_channel_params(),
            cross_zone: self.cross_zone.clone(),
            actions: Vec::new(),
        };
        let Some(genesis) = &self.genesis else {
            return Ok(spec);
        };

        spec.channel_params = genesis.channel_params;
        spec.actions.clone_from(&genesis.actions);
        if let Some(sequencer_key) = bootstrap_sequencer_key
            && !sequencer_genesis::stakes_any_sequencer(&spec.actions)
        {
            let ownership_key = crate::load_or_create_stake_signing_key(
                &self.home.join("sequencer_stake_signing_key"),
            )
            .context("Failed to load or create the stake signing key")?;
            spec.actions.push(sequencer_genesis::self_stake(
                sequencer_key,
                &ownership_key,
                genesis.channel_params.minimum_sequencer_stake,
            ));
        }

        Ok(spec)
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

    #[must_use]
    pub fn channel_signing_key_path(&self) -> PathBuf {
        self.channel_signing_key_file
            .clone()
            .unwrap_or_else(|| self.home.join(crate::CHANNEL_SIGNING_KEY_FILE))
    }

    pub fn load_funding_public_key(&self) -> Result<ZkPublicKey> {
        self.funding_public_key
            .map_or_else(|| crate::load_funding_public_key(&self.home), Ok)
    }
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_gossip_listen_addr(),
            bootstrap_peers: Vec::new(),
        }
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
const fn default_metrics_listen_address() -> Option<SocketAddr> {
    Some(SequencerConfig::DEFAULT_METRICS_LISTEN_ADDRESS)
}

/// Percentage of the mandatory fee reserved on every funded Bedrock
/// transaction, covering a gas price rise before it is mined.
#[must_use]
pub const fn default_priority_fee_percent() -> u64 {
    12
}

/// LIB slots an unmined own inscription waits before zone-sdk orphans it, or re-funds it if
/// zone-sdk funded it (5 minutes at 1s slots); zero disables both.
#[must_use]
pub const fn default_stale_refund_slots() -> u64 {
    300
}

#[must_use]
pub const fn default_backfill_batch_slots() -> NonZero<u64> {
    chain_state::zone_indexer::DEFAULT_BACKFILL_BATCH_SLOTS
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
