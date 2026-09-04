use std::{
    fs::File,
    io::BufReader,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context as _, Result, ensure};
use bytesize::ByteSize;
use common::config::BasicAuth;
pub use cross_zone_inbox_core::{CrossZoneConfig, CrossZonePeer, CrossZoneRoute};
use humantime_serde;
use lee::{AccountId, Balance, PublicKey, Signature};
use logos_blockchain_core::mantle::ops::channel::ChannelId;
use logos_blockchain_key_management_system_service::keys::ZkPublicKey;
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
    /// Funds a holder's holding PDA at genesis with one replayable faucet
    /// credit; the balance-only PDA needs no claim.
    SupplyBridgeLockHolding {
        holder: AccountId,
        amount: Balance,
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
pub struct SequencerConfig {
    /// Home dir of sequencer storage. Holds `bedrock_signing_key`, and
    /// `sequencer_stake_signing_key` when a solo sequencer creates the channel.
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
    /// The key this sequencer signs its blocks with.
    ///
    /// Absent when the node is given one separately (`--signing-key`), which is
    /// what lets a set of sequencers share a single config file — it is all
    /// that otherwise differs between them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key: Option<[u8; 32]>,
    /// Bedrock configuration options.
    pub bedrock_config: BedrockConfig,
    /// Genesis configuration.
    #[serde(default)]
    pub genesis: Vec<GenesisAction>,
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
pub struct BedrockConfig {
    /// Bedrock channel ID.
    pub channel_id: ChannelId,
    /// Bedrock Url.
    pub node_url: Url,
    /// Bedrock auth.
    pub auth: Option<BasicAuth>,
    pub funding_key: ZkPublicKey,
    #[serde(default = "default_priority_fee_percent")]
    pub priority_fee_percent: u64,
    /// What it takes to write on this channel, fixed at genesis: the stake a
    /// key needs to be accredited, and the turn timing round robin runs on.
    /// Every node on the channel must agree on them.
    pub channel_params: ChannelParams,
}

impl SequencerConfig {
    /// Address [`Self::metrics_address`] falls back to when the config omits it.
    pub const DEFAULT_METRICS_ADDRESS: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9000);

    pub fn from_path(config_home: &Path) -> Result<Self> {
        let file = File::open(config_home)?;
        let reader = BufReader::new(file);
        let config: Self = serde_json::from_reader(reader)?;

        // A turn passes on after `posting_timeout` idle slots (1 slot = 1s), so a slower block
        // interval drops our turn between our own blocks.
        let posting_timeout = Duration::from_secs(u64::from(
            config.bedrock_config.channel_params.posting_timeout,
        ));
        ensure!(
            config.block_create_timeout < posting_timeout,
            "block_create_timeout ({:?}) must be under posting_timeout ({posting_timeout:?})",
            config.block_create_timeout
        );

        Ok(config)
    }

    /// The key [`Self::signing_key`] names, ready to sign blocks with.
    pub fn block_signing_key(&self) -> Result<lee::PrivateKey> {
        let bytes = self.signing_key.context(
            "No block signing key: set `signing_key` in the config, or pass --signing-key",
        )?;
        lee::PrivateKey::try_new(bytes).context("Block signing key is not a valid private key")
    }

    /// Where this sequencer's database lives, suffixed with the channel id like
    /// the indexer's, so several sequencers can share a home directory. Only the
    /// database is per-channel; `bedrock_signing_key` stays unsuffixed, so
    /// sequencers sharing a home share one Bedrock identity.
    #[must_use]
    pub fn db_path(&self) -> PathBuf {
        self.home
            .join(format!("rocksdb-{}", self.bedrock_config.channel_id))
    }
}

const fn default_max_block_size() -> ByteSize {
    ByteSize::mib(1)
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
    }
}
