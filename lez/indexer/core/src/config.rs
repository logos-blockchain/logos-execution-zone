use std::{fs::File, io::BufReader, path::Path, time::Duration};

use anyhow::{Context as _, Result};
use common::config::BasicAuth;
use humantime_serde;
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
    /// Whether to wipe the indexer store and re-index from scratch when a genesis mismatch occurs
    /// (i.e. the L1/sequencer was reset but the old store was reused).
    ///
    /// Defaults to `false`: on mismatch the indexer refuses to start.
    #[serde(default)]
    pub allow_chain_reset: bool,
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

#[cfg(test)]
mod tests {
    use super::IndexerConfig;

    const MINIMAL_CONFIG: &str = r#"{
        "consensus_info_polling_interval": "1s",
        "bedrock_config": { "addr": "http://localhost:18080" },
        "channel_id": "0101010101010101010101010101010101010101010101010101010101010101"
    }"#;

    #[test]
    fn allow_chain_reset_defaults_to_false() {
        let config: IndexerConfig = serde_json::from_str(MINIMAL_CONFIG).unwrap();
        assert!(!config.allow_chain_reset);
    }

    #[test]
    fn allow_chain_reset_parses_true() {
        let json = r#"{
            "consensus_info_polling_interval": "1s",
            "bedrock_config": { "addr": "http://localhost:18080" },
            "channel_id": "0101010101010101010101010101010101010101010101010101010101010101",
            "allow_chain_reset": true
        }"#;
        let config: IndexerConfig = serde_json::from_str(json).unwrap();
        assert!(config.allow_chain_reset);
    }
}
