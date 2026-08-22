use std::{
    collections::HashMap, fmt::Display, fs::File, io::BufReader, num::NonZeroU32, path::Path,
    str::FromStr, time::Duration,
};

use anyhow::{Context as _, Result, ensure};
use common::{HashType, config::BasicAuth};
use cross_zone_inbox_core::CrossZoneConfig;
use humantime_serde;
use lee::AccountId;
pub use logos_blockchain_core::mantle::ops::channel::ChannelId;
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use url::Url;

use crate::event_filter::{EventFilter, SelectorFilter};

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
    /// Peer-block bodies the cross-zone verifier keeps behind each peer's
    /// verified tip. Omitted means 1024. `u32::MAX` is effectively unbounded:
    /// the escape hatch for a deployment whose dispatches routinely reach
    /// further back than any fixed window, paid for in unbounded memory. Zero
    /// is unrepresentable and rejected at config parse.
    #[serde(default = "default_peer_block_cache_window")]
    pub peer_block_cache_window: NonZeroU32,
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
    /// Which emitted events this indexer persists.
    #[serde(default)]
    pub event_filter: EventFilterConfig,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventFilterConfig {
    /// Archival configuration persists all events.
    Archival,
    /// Specifies which events to persist based on selector and id.
    Sources(Vec<EventSourceConfig>),
}

impl Default for EventFilterConfig {
    fn default() -> Self {
        Self::Sources(Vec::new())
    }
}

/// Struct storing information on event-filtering.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventSourceConfig {
    /// The ID of the program emitting an event.
    pub program_id: ProgramId,
    /// The optional selectors that are being monitored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selectors: Option<Vec<Selector>>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, SerializeDisplay, DeserializeFromStr)]
pub struct ProgramId(pub lee_core::program::ProgramId);

impl Display for ProgramId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        AccountId::from(self.0).fmt(f)
    }
}

impl FromStr for ProgramId {
    type Err = <AccountId as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse::<AccountId>()?.into()))
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, SerializeDisplay, DeserializeFromStr)]
pub struct Selector(pub [u8; 8]);

impl Display for Selector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl FromStr for Selector {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0_u8; 8];
        hex::decode_to_slice(s, &mut bytes)?;
        Ok(Self(bytes))
    }
}

impl EventFilterConfig {
    pub fn to_filter(&self) -> Result<EventFilter> {
        let declared = match self {
            Self::Archival => return Ok(EventFilter::Archival),
            Self::Sources(sources) => sources,
        };
        let mut sources = HashMap::new();
        for source in declared {
            let selectors = match &source.selectors {
                None => SelectorFilter::All,
                Some(selectors) => {
                    ensure!(
                        !selectors.is_empty(),
                        "event_filter declares program {} with no selectors",
                        source.program_id
                    );
                    SelectorFilter::Only(selectors.iter().map(|selector| selector.0).collect())
                }
            };
            ensure!(
                sources.insert(source.program_id.0, selectors).is_none(),
                "event_filter declares program {} twice",
                source.program_id
            );
        }
        Ok(EventFilter::Sources(sources))
    }
}

/// The window applied when the config omits `peer_block_cache_window`.
pub(crate) const fn default_peer_block_cache_window() -> NonZeroU32 {
    NonZeroU32::new(1024).expect("1024 is nonzero")
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    const PROGRAM_ONES_BASE58: &str = "4uQeVjgVccFGKht1dTy7bqxH3WehditPsgHyN1FSvRM";
    const PROGRAM_TWOS_BASE58: &str = "8opHzUMzEDVXeQm2FvwECguZ62JQGSmnkMawj1Vtqqh";

    fn parse(json: &str) -> EventFilterConfig {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn selector_display_and_parse_are_pinned_to_hex() {
        let selector = Selector([1; 8]);
        assert_eq!(selector.to_string(), "0101010101010101");
        assert_eq!("0101010101010101".parse::<Selector>().unwrap(), selector);
    }

    #[test]
    fn omitted_filter_keeps_nothing() {
        assert_eq!(
            EventFilterConfig::default().to_filter().unwrap(),
            EventFilter::default()
        );
    }

    #[test]
    fn archival_config_maps_to_archival() {
        assert_eq!(
            parse(r#""archival""#).to_filter().unwrap(),
            EventFilter::Archival
        );
    }

    #[test]
    fn declared_sources_map_to_selector_filters() {
        let config = parse(&format!(
            r#"{{ "sources": [
                {{ "program_id": "{PROGRAM_ONES_BASE58}" }},
                {{ "program_id": "{PROGRAM_TWOS_BASE58}", "selectors": ["0303030303030303"] }}
            ] }}"#
        ));

        let expected = EventFilter::Sources(HashMap::from([
            ([1; 8], SelectorFilter::All),
            ([2; 8], SelectorFilter::Only(HashSet::from([[3; 8]]))),
        ]));
        assert_eq!(config.to_filter().unwrap(), expected);
    }

    #[test]
    fn duplicate_program_declaration_is_rejected() {
        let config = parse(&format!(
            r#"{{ "sources": [
                {{ "program_id": "{PROGRAM_ONES_BASE58}" }},
                {{ "program_id": "{PROGRAM_ONES_BASE58}", "selectors": ["0303030303030303"] }}
            ] }}"#
        ));
        assert!(config.to_filter().is_err());
    }

    #[test]
    fn empty_selector_list_is_rejected() {
        let config = parse(&format!(
            r#"{{ "sources": [
                {{ "program_id": "{PROGRAM_ONES_BASE58}", "selectors": [] }}
            ] }}"#
        ));
        let err = config.to_filter().unwrap_err().to_string();
        assert!(err.contains("no selectors"));
    }

    #[test]
    fn unknown_source_field_is_rejected() {
        let json = format!(
            r#"{{ "sources": [
                {{ "program_id": "{PROGRAM_ONES_BASE58}", "selector": ["0303030303030303"] }}
            ] }}"#
        );
        assert!(serde_json::from_str::<EventFilterConfig>(&json).is_err());
    }
}
