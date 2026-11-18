use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZero,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context as _, Result, ensure};
pub use bridge_core::DepositRecipient;
use common::{config::BasicAuth, transaction::LeeTransactionWith};
pub use cross_zone::{CrossZoneConfig, CrossZonePeer, CrossZoneRoute};
use humantime_serde;
use lee::privacy_preserving_transaction::circuit::ProofDigest;
use logos_blockchain_zone_sdk::{
    core::mantle::ops::channel::ChannelId, key_management_system_service::keys::ZkPublicKey,
};
pub use sequencer_genesis::GenesisAction;
use sequencer_genesis::GenesisSpec;
pub use sequencer_stake_core::ChannelParams;
use serde::{Deserialize, Serialize};
use url::Url;

/// Bytes reserved out of `max_block_size` for the block header plus the forced
/// fee and clock tail transactions; RPC and gossip cap a single transaction's
/// digest form at `max_block_size - BLOCK_OVERHEAD`.
pub const BLOCK_OVERHEAD: u64 = 2_048;

/// The largest usable `max_block_size`, 7/8 of 2 MiB.
///
/// An L2 block is published to Bedrock as a single inscription, which an era
/// caps at its `max_op_data_size`. Bedrock sets its limits per era, so this is
/// the smallest one in the era schedule of the `logos-blockchain-node` default
/// deployment.
pub const MAX_PUBLISHABLE_BLOCK_SIZE: u64 = 0x001C_0000;

/// The largest transaction RPC and gossip admit in full form, proofs included. Blocks carry
/// proof digests, so this bounds transport only; it is what the largest block could hold.
pub const MAX_TRANSACTION_SIZE: u64 = MAX_PUBLISHABLE_BLOCK_SIZE.saturating_sub(BLOCK_OVERHEAD);
const _: () = assert!(
    sequencer_stake_core::MAX_MAX_BLOCK_SIZE == MAX_PUBLISHABLE_BLOCK_SIZE,
    "the sequencer_stake program must bound max_block_size at Bedrock's inscription limit"
);

/// The largest Bedrock transaction, 2 MiB.
///
/// An era caps a block's transactions at its `max_transactions_size` bytes; this
/// is the smallest one in the era schedule of the `logos-blockchain-node`
/// default deployment.
pub const MAX_BEDROCK_TX_SIZE: u64 = 0x0020_0000;

/// What a turn keeps, after a candidate's private cutoff, for its public remainder to be built
/// and submitted before the posting timeout runs out.
pub const PUBLIC_FALLBACK_MARGIN: Duration = Duration::from_secs(2);

/// Bytes of transaction proofs a node keeps in memory.
pub const PROOF_STORE_CAPACITY: usize = 256 * 1024 * 1024;

/// Smallest nonzero `stale_refund_slots`, since a shorter window orphans blocks before L1 can
/// mine them.
const MIN_STALE_REFUND_SLOTS: u64 = 50;

/// Why RPC and gossip refuse a transaction for its size.
#[derive(Debug, thiserror::Error)]
pub enum TransactionTooLarge {
    #[error("transaction too large: {size} > {max}")]
    Full { size: u64, max: u64 },
    #[error("transaction too large for a block: {size} > {max}")]
    Inscribed { size: u64, max: u64 },
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
    /// `"cross_zone": {"lock_target_zones": []}`.
    #[serde(default)]
    pub cross_zone: Option<CrossZoneConfig>,
    /// Address the Prometheus metrics exporter binds to.
    #[serde(default = "default_metrics_listen_address")]
    pub metrics_listen_address: Option<SocketAddr>,
    /// Sequencer p2p gossip configuration. `None` disables gossip.
    #[serde(default)]
    pub gossip: Option<GossipConfig>,
    /// The Logos Storage node this sequencer distributes proofs through.
    #[serde(default)]
    pub logos_storage: LogosStorageConfig,
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

/// The Logos Storage node a sequencer runs beside.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogosStorageConfig {
    /// Base URL of the node's REST API.
    #[serde(default = "default_logos_storage_api_url")]
    pub api_url: Url,
    /// How long a proof stays served after its last holder lets go.
    #[serde(with = "humantime_serde", default = "default_serving_window")]
    pub serving_window: Duration,
    /// Bytes of the node's quota kept for the proofs of live blocks, which optional admission
    /// leaves free.
    #[serde(default = "default_live_reserve_bytes")]
    pub live_reserve_bytes: u64,
    /// How often a held proof is uploaded again, which renews its expiry; under the node's
    /// block TTL.
    #[serde(with = "humantime_serde", default = "default_renewal_interval")]
    pub renewal_interval: Duration,
    /// Proof downloads in flight at once.
    #[serde(default = "default_max_downloads")]
    pub max_downloads: usize,
    /// Proof downloads one peer's announcements keep in flight at once.
    #[serde(default = "default_max_downloads_per_peer")]
    pub max_downloads_per_peer: usize,
}

impl Default for LogosStorageConfig {
    fn default() -> Self {
        Self {
            api_url: default_logos_storage_api_url(),
            serving_window: default_serving_window(),
            live_reserve_bytes: default_live_reserve_bytes(),
            renewal_interval: default_renewal_interval(),
            max_downloads: default_max_downloads(),
            max_downloads_per_peer: default_max_downloads_per_peer(),
        }
    }
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
    /// The chain's initial params; every other node reads them from the chain.
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

/// Refuses `len` encoded bytes over [`MAX_TRANSACTION_SIZE`], before anything decodes them.
pub fn check_transaction_size(len: usize) -> Result<(), TransactionTooLarge> {
    let size = u64::try_from(len).unwrap_or(u64::MAX);
    if size > MAX_TRANSACTION_SIZE {
        return Err(TransactionTooLarge::Full {
            size,
            max: MAX_TRANSACTION_SIZE,
        });
    }
    Ok(())
}

/// Refuses the digest form `tx` when it, with its locator, does not fit a block of
/// `max_block_size`.
pub fn check_inscribed_size(
    tx: &LeeTransactionWith<ProofDigest>,
    max_block_size: u64,
) -> Result<(), TransactionTooLarge> {
    let size = tx.charged_bytes().unwrap_or(u64::MAX);
    let max = max_block_size.saturating_sub(BLOCK_OVERHEAD);
    if size > max {
        return Err(TransactionTooLarge::Inscribed { size, max });
    }
    Ok(())
}

fn default_gossip_listen_addr() -> libp2p::Multiaddr {
    "/ip4/0.0.0.0/udp/0/quic-v1"
        .parse()
        .expect("hardcoded default gossip listen addr is a valid multiaddr")
}

fn default_logos_storage_api_url() -> Url {
    "http://127.0.0.1:8080/"
        .parse()
        .expect("hardcoded default Logos Storage API URL is a valid URL")
}

const fn default_serving_window() -> Duration {
    Duration::from_hours(1)
}

const fn default_live_reserve_bytes() -> u64 {
    0x4000_0000
}

const fn default_renewal_interval() -> Duration {
    Duration::from_hours(24)
}

const fn default_max_downloads() -> usize {
    16
}

const fn default_max_downloads_per_peer() -> usize {
    2
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

/// Production defaults for the values genesis sets.
#[must_use]
pub const fn default_channel_params() -> ChannelParams {
    ChannelParams {
        minimum_sequencer_stake: system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE,
        posting_timeframe: system_accounts::DEFAULT_SEQUENCER_POSTING_TIMEFRAME,
        posting_timeout: system_accounts::DEFAULT_SEQUENCER_POSTING_TIMEOUT,
        skip_window: system_accounts::DEFAULT_SKIP_WINDOW,
        max_block_size: system_accounts::DEFAULT_MAX_BLOCK_SIZE,
        finality_depth: system_accounts::DEFAULT_FINALITY_DEPTH,
    }
}

#[cfg(test)]
mod tests {
    use common::transaction::LeeTransaction;
    use lee::{
        PrivacyPreservingTransaction,
        privacy_preserving_transaction::{Message, WitnessSet, circuit::Proof},
    };

    use super::*;

    fn private_transaction(proof: Vec<u8>) -> LeeTransaction {
        LeeTransaction::PrivacyPreserving(PrivacyPreservingTransaction::new(
            Message::default(),
            WitnessSet::from_raw_parts(vec![], Proof::from_inner(proof)),
        ))
    }

    #[test]
    fn a_private_transaction_too_big_for_a_block_only_in_its_full_form_is_accepted() {
        let max_block_size: u64 = 1 << 20;
        let tx = private_transaction(vec![7; 1 << 20]);
        let full_size = borsh::to_vec(&tx).unwrap().len();
        let max_inscribed_size = max_block_size.checked_sub(BLOCK_OVERHEAD).unwrap();
        assert!(u64::try_from(full_size).unwrap() > max_inscribed_size);

        assert!(check_transaction_size(full_size).is_ok());
        assert!(check_inscribed_size(&tx.digested(), max_block_size).is_ok());
    }

    #[test]
    fn a_private_transaction_fits_a_block_up_to_its_locator() {
        let tx = private_transaction(vec![7; 64]).digested();
        let charged = tx.charged_bytes().unwrap();
        let fitting = charged + BLOCK_OVERHEAD;

        assert!(check_inscribed_size(&tx, fitting).is_ok());
        assert!(matches!(
            check_inscribed_size(&tx, fitting - 1),
            Err(TransactionTooLarge::Inscribed { size, .. }) if size == charged
        ));
    }
}
