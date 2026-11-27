//! What `sequencer_service start` runs with, shared with embedders such as `core_ffi` so they
//! take the same options, env vars included.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use anyhow::{Context as _, Result, ensure};
use clap::builder::BoolishValueParser;
use libp2p::{Multiaddr, multiaddr::Protocol};
use sequencer_core::{Ed25519PublicKey, config::GossipConfig};
use serde::Deserialize;
use tracing::info;

use crate::SequencerConfig;

/// The config a home holds, written by `setup`.
pub const CONFIG_FILE: &str = "sequencer_config.json";

/// Where the RPC listens unless told otherwise.
pub const DEFAULT_RPC_LISTEN_ADDRESS: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3040);

/// Each option also reads `SEQUENCER_<OPTION>`. A flag wins over its env var, and both win over
/// the config.
///
/// Embedders pass the options besides the home as JSON fields of the same names, see
/// [`StartArgs::from_json`].
#[derive(Debug, clap::Args, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartArgs {
    /// Holds the database, and by default the config and keys.
    #[clap(env = "SEQUENCER_HOME")]
    pub home: PathBuf,
    /// Defaults to `<home>/sequencer_config.json`.
    #[clap(long, env = "SEQUENCER_CONFIG")]
    pub config: Option<PathBuf>,
    /// Keeps the genesis of `--config`, so the channel is created if it does not
    /// exist. Without it, a node pointed at the wrong channel fails instead of creating that one.
    /// A home's own config keeps whatever `setup` decided.
    #[clap(long, env = "SEQUENCER_CREATE_CHANNEL", value_parser = BoolishValueParser::new())]
    #[serde(default)]
    pub create_channel: bool,
    /// Waits for the channel to be created, instead of failing, when it does not exist yet and
    /// this node has no genesis to create it with.
    #[clap(long, env = "SEQUENCER_WAIT_FOR_CHANNEL", value_parser = BoolishValueParser::new())]
    #[serde(default)]
    pub wait_for_channel: bool,
    /// Defaults to `<home>/channel_signing_key`.
    #[clap(long, env = "SEQUENCER_CHANNEL_SIGNING_KEY_FILE")]
    pub channel_signing_key_file: Option<PathBuf>,
    /// In hex. Defaults to the one in `<home>/bedrock_funding_public_key`.
    #[clap(long, env = "SEQUENCER_FUNDING_PUBLIC_KEY")]
    pub funding_public_key: Option<String>,
    /// Overrides the config's `bedrock_config.node_url`.
    #[clap(long, env = "SEQUENCER_BEDROCK_NODE_URL")]
    pub bedrock_node_url: Option<String>,
    /// In hex. Overrides the config's `bedrock_config.channel_id`.
    #[clap(long, env = "SEQUENCER_CHANNEL_ID")]
    pub channel_id: Option<String>,
    /// The RPC has no caller auth, so only widen it behind a firewall.
    #[clap(
        long,
        env = "SEQUENCER_RPC_LISTEN_ADDRESS",
        default_value_t = DEFAULT_RPC_LISTEN_ADDRESS
    )]
    #[serde(default = "default_rpc_listen_address")]
    pub rpc_listen_address: SocketAddr,
    /// Overrides the config's `metrics_listen_address`.
    #[clap(long, env = "SEQUENCER_METRICS_LISTEN_ADDRESS")]
    pub metrics_listen_address: Option<SocketAddr>,
    /// Gossip's QUIC (UDP) address. Turns gossip on if the config leaves it off.
    #[clap(long, env = "SEQUENCER_GOSSIP_LISTEN_ADDR")]
    pub gossip_listen_addr: Option<SocketAddr>,
    /// `host:port` or a multiaddr; repeat, or comma-separate in the env var, for several.
    /// Replaces the config's `bootstrap_peers`, and turns gossip on.
    #[clap(long, env = "SEQUENCER_GOSSIP_BOOTSTRAP_PEER", value_delimiter = ',')]
    #[serde(default, rename = "gossip_bootstrap_peers")]
    pub gossip_bootstrap_peer: Vec<String>,
}

impl StartArgs {
    /// `start`'s options for `home`, the others from `overrides`: a JSON object of the options'
    /// names (`gossip_bootstrap_peers` an array), each left out taking its default. Empty for no
    /// overrides. Unlike `start`, no option falls back to a `SEQUENCER_*` env var.
    pub fn from_json(home: PathBuf, overrides: &str) -> Result<Self> {
        let mut fields: serde_json::Map<String, serde_json::Value> = if overrides.trim().is_empty()
        {
            serde_json::Map::new()
        } else {
            serde_json::from_str(overrides).context("Start overrides must be a JSON object")?
        };
        ensure!(
            !fields.contains_key("home"),
            "The home is given on its own, not among the start overrides"
        );
        fields.insert(
            "home".to_owned(),
            serde_json::to_value(home).context("Home is not UTF-8")?,
        );
        serde_json::from_value(fields.into()).context("Invalid start overrides")
    }

    /// The config file with these args applied over it.
    pub fn load_config(&self) -> Result<SequencerConfig> {
        let args = self;
        let explicit_config = args.config.is_some();
        ensure!(
            explicit_config || !args.create_channel,
            "--create-channel needs --config; a home's own config keeps what `setup` decided"
        );
        let config_path = args
            .config
            .clone()
            .unwrap_or_else(|| args.home.join(CONFIG_FILE));
        ensure!(
            config_path.exists(),
            "{} does not exist; run `setup` first",
            config_path.display()
        );
        let mut config = SequencerConfig::from_path(&config_path)
            .with_context(|| format!("Failed to read {}", config_path.display()))?;
        if explicit_config && !args.create_channel && config.genesis.is_some() {
            info!("Ignoring the config's genesis, as --create-channel is not set");
            config.genesis = None;
        }

        config.home.clone_from(&args.home);
        config.wait_for_channel = args.wait_for_channel;
        config
            .channel_signing_key_file
            .clone_from(&args.channel_signing_key_file);
        if let Some(key) = &args.funding_public_key {
            config.funding_public_key = Some(
                sequencer_core::parse_funding_public_key(key)
                    .context("Invalid --funding-public-key")?,
            );
        }
        if let Some(url) = &args.bedrock_node_url {
            config.bedrock_config.node_url = url.parse().context("Invalid --bedrock-node-url")?;
        }
        if let Some(channel_id) = &args.channel_id {
            let bytes: [u8; 32] = hex::decode(channel_id.trim_start_matches("0x"))
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .context("Invalid --channel-id: expected 32 bytes in hex")?;
            config.bedrock_config.channel_id = bytes.into();
        }
        if args.metrics_listen_address.is_some() {
            config.metrics_listen_address = args.metrics_listen_address;
        }
        if args.gossip_listen_addr.is_some() || !args.gossip_bootstrap_peer.is_empty() {
            let gossip = config.gossip.get_or_insert_with(GossipConfig::default);
            if let Some(address) = args.gossip_listen_addr {
                gossip.listen_addr = quic_multiaddr(address);
            }
            if !args.gossip_bootstrap_peer.is_empty() {
                gossip.bootstrap_peers = args
                    .gossip_bootstrap_peer
                    .iter()
                    .map(|peer| {
                        parse_gossip_peer(peer)
                            .with_context(|| format!("Invalid --gossip-bootstrap-peer {peer}"))
                    })
                    .collect::<Result<_>>()?;
            }
        }

        let key_path = config.channel_signing_key_path();
        ensure!(
            key_path.exists(),
            "{} does not exist; run `setup` first",
            key_path.display()
        );
        config.load_funding_public_key()?;
        Ok(config)
    }
}

const fn default_rpc_listen_address() -> SocketAddr {
    DEFAULT_RPC_LISTEN_ADDRESS
}

fn quic_multiaddr(address: SocketAddr) -> Multiaddr {
    let ip = match address.ip() {
        IpAddr::V4(ip) => Protocol::Ip4(ip),
        IpAddr::V6(ip) => Protocol::Ip6(ip),
    };
    Multiaddr::empty()
        .with(ip)
        .with(Protocol::Udp(address.port()))
        .with(Protocol::QuicV1)
}

/// Parses `host:port` as a QUIC address, or takes a full multiaddr as is.
fn parse_gossip_peer(peer: &str) -> Result<Multiaddr> {
    if peer.starts_with('/') {
        return peer.parse().context("not a multiaddr");
    }
    if let Ok(address) = peer.parse::<SocketAddr>() {
        return Ok(quic_multiaddr(address));
    }
    let (host, port) = peer
        .rsplit_once(':')
        .context("expected `host:port` or a multiaddr")?;
    Ok(Multiaddr::empty()
        .with(Protocol::Dns(host.into()))
        .with(Protocol::Udp(port.parse().context("not a port")?))
        .with(Protocol::QuicV1))
}

/// The channel signing public key: what tells sequencers apart in metrics and
/// traces.
pub fn channel_public_key(config: &SequencerConfig) -> Result<Ed25519PublicKey> {
    let channel_signing_key =
        sequencer_core::load_or_create_signing_key(&config.channel_signing_key_path())?;
    Ok(channel_signing_key.public_key())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gossip_peers_parse() {
        let parse = |peer| parse_gossip_peer(peer).unwrap().to_string();
        assert_eq!(parse("10.0.0.1:4040"), "/ip4/10.0.0.1/udp/4040/quic-v1");
        assert_eq!(
            parse("sequencer_service_0:4040"),
            "/dns/sequencer_service_0/udp/4040/quic-v1"
        );
        assert_eq!(
            parse("/ip4/10.0.0.1/udp/4040/quic-v1"),
            "/ip4/10.0.0.1/udp/4040/quic-v1"
        );
        assert!(parse_gossip_peer("sequencer_service_0").is_err());
    }
}
