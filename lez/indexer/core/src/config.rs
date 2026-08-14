use std::{fs::File, io::BufReader, path::Path, time::Duration};

use anyhow::{Context as _, Result};
use common::{HashType, config::BasicAuth};
use cross_zone_inbox_core::CrossZoneConfig;
use humantime_serde;
use lee::AccountId;
pub use logos_blockchain_core::mantle::ops::channel::ChannelId;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub addr: Url,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<BasicAuth>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexerConfig {
    #[serde(with = "humantime_serde")]
    pub consensus_info_polling_interval: Duration,
    pub bedrock_config: ClientConfig,
    pub channel_id: ChannelId,
    /// Cross-zone configuration. `None` disables the indexer's cross-zone handling.
    #[serde(default)]
    pub cross_zone: Option<CrossZoneConfig>,
    /// Hex hashes of local blocks accepted without cross-zone verification: a
    /// listed block skips verification entirely, so listing a hash clears a
    /// dead-peer retry loop as well as a forged verdict. This accepts the
    /// sequencer's word for the listed blocks only; every other block stays
    /// verified. Acceptance can permanently consume the real message's
    /// delivery slot if the sequencer forged under true source coordinates,
    /// and the unverified marks are memory only, so an unlisted replay of the
    /// same dispatch after a restart halts again.
    #[serde(default)]
    pub cross_zone_accept_unverified: Vec<HashType>,
    /// Bridge-lock holdings to seed into genesis, mirroring the sequencer's
    /// `SupplyBridgeLockHolding` actions. They are not produced by any
    /// transaction, so the indexer must seed them to match the sequencer's state.
    #[serde(default)]
    pub bridge_lock_holdings: Vec<BridgeLockHolding>,
    /// Whether to wipe the indexer store and re-index from scratch when the startup
    /// chain-identity check finds the channel serving a different block than the one
    /// stored at the same id.
    ///
    /// Defaults to `false`: on mismatch the indexer refuses to start.
    #[serde(default)]
    pub allow_chain_reset: bool,
}

/// A genesis-funded bridge-lock holder balance, configured identically on the
/// sequencer (via `SupplyBridgeLockHolding`) and the indexer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeLockHolding {
    pub holder: AccountId,
    pub amount: u128,
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
