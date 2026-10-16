use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use anyhow::{Context as _, Result, ensure};
use clap::{Parser, Subcommand};
use libp2p::{Multiaddr, multiaddr::Protocol};
use log::error;
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};
use sequencer_core::config::GossipConfig;
use sequencer_service::SequencerConfig;
use sequencer_stake_core::SequencerKey;
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::sync::CancellationToken;
use wallet::cli::CliAccountMention;

mod operator;

#[derive(Debug, Parser)]
#[clap(version)]
struct Args {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Creates a home with its config and Bedrock funding public key.
    Setup {
        home: PathBuf,
        /// Config to copy into the home.
        #[clap(long)]
        config: PathBuf,
        /// Public key, in hex, of a funded key in the Bedrock node's wallet; it pays the
        /// node's inscriptions.
        #[clap(long)]
        funding_public_key: String,
        /// Keeps the config's `genesis`, so `start` creates the channel if it does not exist.
        #[clap(long)]
        create_channel: bool,
    },
    /// Runs the sequencer out of a home, following the channel.
    Start(StartArgs),
    /// Stakes a channel signing key, through the wallet's sequencer.
    Stake {
        /// Channel signing public key to stake, in hex; `setup` prints it.
        #[clap(long, value_parser = operator::parse_sequencer_key)]
        sequencer_key: SequencerKey,
        /// Wallet account paying the stake, as `Public/<id>` or a label.
        #[clap(long)]
        from: CliAccountMention,
        /// Defaults to the minimum stake.
        #[clap(long)]
        amount: Option<u128>,
        /// Defaults to `$LEE_WALLET_HOME_DIR`, else `~/.lee/wallet`.
        #[clap(long)]
        wallet_home: Option<PathBuf>,
    },
    /// Requests the release of a channel signing key's stake, through the wallet's sequencer.
    Unstake {
        /// Channel signing public key whose stake to release, in hex.
        #[clap(long, value_parser = operator::parse_sequencer_key)]
        sequencer_key: SequencerKey,
        /// Account receiving the release, as `Public/<id>` or a label.
        #[clap(long)]
        destination: CliAccountMention,
        /// Defaults to the whole stake.
        #[clap(long)]
        amount: Option<u128>,
        /// Defaults to `$LEE_WALLET_HOME_DIR`, else `~/.lee/wallet`.
        #[clap(long)]
        wallet_home: Option<PathBuf>,
    },
}

/// Each option also reads `SEQUENCER_<OPTION>`. A flag wins over its env var, and both win over
/// the config.
#[derive(Debug, clap::Args)]
struct StartArgs {
    /// Holds the database, and by default the config and keys.
    #[clap(env = "SEQUENCER_HOME")]
    home: PathBuf,
    /// Defaults to `<home>/sequencer_config.json`.
    #[clap(long, env = "SEQUENCER_CONFIG")]
    config: Option<PathBuf>,
    /// Defaults to `<home>/channel_signing_key`.
    #[clap(long, env = "SEQUENCER_CHANNEL_SIGNING_KEY_FILE")]
    channel_signing_key_file: Option<PathBuf>,
    /// In hex. Defaults to the one in `<home>/bedrock_funding_public_key`.
    #[clap(long, env = "SEQUENCER_FUNDING_PUBLIC_KEY")]
    funding_public_key: Option<String>,
    /// Overrides the config's `bedrock_config.node_url`.
    #[clap(long, env = "SEQUENCER_BEDROCK_URL")]
    bedrock_url: Option<String>,
    /// In hex. Overrides the config's `bedrock_config.channel_id`.
    #[clap(long, env = "SEQUENCER_CHANNEL_ID")]
    channel_id: Option<String>,
    /// The RPC has no caller auth, so only widen it behind a firewall.
    #[clap(
        long,
        env = "SEQUENCER_RPC_LISTEN_ADDRESS",
        default_value = "127.0.0.1:3040"
    )]
    rpc_listen_address: SocketAddr,
    /// Overrides the config's `metrics_address`.
    #[clap(long, env = "SEQUENCER_METRICS_LISTEN_ADDRESS")]
    metrics_listen_address: Option<SocketAddr>,
    /// Gossip's QUIC (UDP) address. Turns gossip on if the config leaves it off.
    #[clap(long, env = "SEQUENCER_GOSSIP_LISTEN_ADDRESS")]
    gossip_listen_address: Option<SocketAddr>,
    /// `host:port` or a multiaddr; repeat, or comma-separate in the env var, for several.
    /// Replaces the config's `bootstrap_peers`, and turns gossip on.
    #[clap(long, env = "SEQUENCER_GOSSIP_BOOTSTRAP_PEER", value_delimiter = ',')]
    gossip_bootstrap_peer: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    match Args::parse().command {
        Command::Setup {
            home,
            config,
            funding_public_key,
            create_channel,
        } => operator::setup(&home, &config, &funding_public_key, create_channel),
        Command::Start(args) => start(args).await,
        Command::Stake {
            sequencer_key,
            from,
            amount,
            wallet_home,
        } => operator::stake(wallet_home, sequencer_key, from, amount).await,
        Command::Unstake {
            sequencer_key,
            destination,
            amount,
            wallet_home,
        } => operator::unstake(wallet_home, sequencer_key, destination, amount).await,
    }
}

#[expect(
    clippy::integer_division_remainder_used,
    reason = "Generated by select! macro, can't be easily rewritten to avoid this lint"
)]
async fn start(args: StartArgs) -> Result<()> {
    let cancellation_token = listen_for_shutdown_signal();

    let config = load_config(&args)?;
    log_config(&config)?;

    if let Some(address) = config.metrics_address {
        install_prometheus_recorder(address)?;
    }
    let sequencer_handle = sequencer_service::run(config, args.rpc_listen_address).await?;

    tokio::select! {
        () = cancellation_token.cancelled() => {
            log::info!("Shutting down sequencer...");
        }
        Err(err) = sequencer_handle.failed() => {
            error!("Sequencer failed unexpectedly: {err}");
        }
    }

    // Stop the watchers, the publisher's drive task, the block loop and the RPC
    // server, and wait for each. Dropping the handle only asks; the store stays
    // open for an unbounded stretch after that, so a restart can find its own
    // home directory locked, and a watcher can be killed between recording a
    // delivery and handing it over.
    sequencer_handle.shutdown().await;

    log::info!("Sequencer shutdown complete");

    Ok(())
}

/// The config file with `args` applied over it.
fn load_config(args: &StartArgs) -> Result<SequencerConfig> {
    let config_path = args
        .config
        .clone()
        .unwrap_or_else(|| args.home.join(operator::CONFIG_FILE));
    ensure!(
        config_path.exists(),
        "{} does not exist; run `setup` first",
        config_path.display()
    );
    let mut config = SequencerConfig::from_path(&config_path)
        .with_context(|| format!("Failed to read {}", config_path.display()))?;

    config.home.clone_from(&args.home);
    config
        .channel_signing_key_file
        .clone_from(&args.channel_signing_key_file);
    if let Some(key) = &args.funding_public_key {
        config.funding_public_key = Some(
            sequencer_core::parse_funding_public_key(key)
                .context("Invalid --funding-public-key")?,
        );
    }
    if let Some(url) = &args.bedrock_url {
        config.bedrock_config.node_url = url.parse().context("Invalid --bedrock-url")?;
    }
    if let Some(channel_id) = &args.channel_id {
        let bytes: [u8; 32] = hex::decode(channel_id.trim_start_matches("0x"))
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .context("Invalid --channel-id: expected 32 bytes in hex")?;
        config.bedrock_config.channel_id = bytes.into();
    }
    if args.metrics_listen_address.is_some() {
        config.metrics_address = args.metrics_listen_address;
    }
    if args.gossip_listen_address.is_some() || !args.gossip_bootstrap_peer.is_empty() {
        let gossip = config.gossip.get_or_insert_with(GossipConfig::default);
        if let Some(address) = args.gossip_listen_address {
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

/// Logs what `start` runs with, secrets masked.
fn log_config(config: &SequencerConfig) -> Result<()> {
    let mut shown = config.clone();
    if let Some(password) = shown
        .bedrock_config
        .auth
        .as_mut()
        .and_then(|auth| auth.password.as_mut())
    {
        "<redacted>".clone_into(password);
    }
    log::info!(
        "Config: {}, channel signing key file: {}, funding public key: {}",
        serde_json::to_string(&shown)?,
        config.channel_signing_key_path().display(),
        serde_json::to_string(&config.load_funding_public_key()?)?,
    );
    Ok(())
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

/// Installs the recorder on `metrics_address`.
fn install_prometheus_recorder(metrics_address: SocketAddr) -> Result<()> {
    /// Ladder for `*_seconds` histograms, densest across the 1–100 ms band where
    /// block production and transaction application actually land.
    const LATENCY_BUCKETS: &[f64] = &[
        0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ];

    /// Fallback ladder for histograms that count things rather than measure time.
    const COUNT_BUCKETS: &[f64] = &[1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0];

    PrometheusBuilder::new()
        .with_http_listener(metrics_address)
        .with_recommended_naming(true)
        .set_buckets(COUNT_BUCKETS)
        .context("Failed to set default histogram buckets")?
        .set_buckets_for_metric(Matcher::Suffix("_seconds".to_owned()), LATENCY_BUCKETS)
        .context("Failed to set latency histogram buckets")?
        .install()
        .context("Failed to install Prometheus recorder")
}

/// Cancelled on Ctrl-C or `SIGTERM`.
///
/// `SIGTERM` is what a container runtime sends first, so without it every
/// orchestrated stop is the ungraceful path.
#[expect(
    clippy::integer_division_remainder_used,
    reason = "Generated by select! macro, can't be easily rewritten to avoid this lint"
)]
fn listen_for_shutdown_signal() -> CancellationToken {
    let cancellation_token = CancellationToken::new();
    let cancellation_token_clone = cancellation_token.clone();

    tokio::spawn(async move {
        let mut terminate = match signal(SignalKind::terminate()) {
            Ok(terminate) => terminate,
            Err(err) => {
                error!("Failed to listen for SIGTERM: {err}");
                return;
            }
        };

        tokio::select! {
            result = tokio::signal::ctrl_c() => match result {
                Ok(()) => log::info!("Received Ctrl-C signal"),
                Err(err) => {
                    error!("Failed to listen for Ctrl-C signal: {err}");
                    return;
                }
            },
            _ = terminate.recv() => log::info!("Received SIGTERM"),
        }

        cancellation_token_clone.cancel();
    });

    cancellation_token
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    use super::*;

    #[test]
    fn start_env_vars_follow_flag_names() {
        let command = Args::command();
        let start = command.find_subcommand("start").expect("`start` exists");
        for arg in start.get_arguments() {
            let id = arg.get_id().as_str();
            let name = arg.get_long().unwrap_or(id);
            let expected = format!("SEQUENCER_{}", name.replace('-', "_").to_uppercase());
            assert_eq!(
                arg.get_env().and_then(|env| env.to_str()),
                Some(expected.as_str()),
                "`{id}`"
            );
        }
    }

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
