use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, OnceLock},
    time::Duration,
};

use anyhow::{Context as _, Result, ensure};
use clap::{Parser, Subcommand, builder::BoolishValueParser};
use lee::Balance;
use libp2p::{Multiaddr, multiaddr::Protocol};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use sequencer_core::{Ed25519PublicKey, config::GossipConfig};
use sequencer_service::SequencerConfig;
use sequencer_stake_core::SequencerKey;
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use tracing_subscriber::{
    filter::{FilterExt as _, FilterFn},
    layer::{Filter, SubscriberExt as _},
    util::SubscriberInitExt as _,
};
use wallet::cli::CliAccountMention;

mod actor_metrics;
mod operator;
mod ops;
mod traces;

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
        /// Config to copy into the home, e.g. one of `lez/sequencer/service/networks/`.
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
        amount: Option<Balance>,
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
        amount: Option<Balance>,
        /// Defaults to `$LEE_WALLET_HOME_DIR`, else `~/.lee/wallet`.
        #[clap(long)]
        wallet_home: Option<PathBuf>,
    },
    /// Votes, as a staked key's owner, for new channel params, through the wallet's sequencer.
    ///
    /// Params left out keep the values in force. The params change once two thirds of the
    /// accredited keys vote for the same values.
    VoteParams {
        /// Accredited channel signing public key voting, in hex.
        #[clap(long, value_parser = operator::parse_sequencer_key)]
        sequencer_key: SequencerKey,
        #[clap(flatten)]
        changes: operator::ParamsArgs,
        /// Defaults to `$LEE_WALLET_HOME_DIR`, else `~/.lee/wallet`.
        #[clap(long)]
        wallet_home: Option<PathBuf>,
    },
    /// Withdraws, as a staked key's owner, its vote on channel params, through the wallet's
    /// sequencer.
    WithdrawParamsVote {
        /// Channel signing public key whose vote to withdraw, in hex.
        #[clap(long, value_parser = operator::parse_sequencer_key)]
        sequencer_key: SequencerKey,
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
    /// Keeps the genesis of `--config`, so the channel is created if it does not
    /// exist. Without it, a node pointed at the wrong channel fails instead of creating that one.
    /// A home's own config keeps whatever `setup` decided.
    #[clap(long, env = "SEQUENCER_CREATE_CHANNEL", value_parser = BoolishValueParser::new())]
    create_channel: bool,
    /// Waits for the channel to be created, instead of failing, when it does not exist yet and
    /// this node has no genesis to create it with.
    #[clap(long, env = "SEQUENCER_WAIT_FOR_CHANNEL", value_parser = BoolishValueParser::new())]
    wait_for_channel: bool,
    /// Defaults to `<home>/channel_signing_key`.
    #[clap(long, env = "SEQUENCER_CHANNEL_SIGNING_KEY_FILE")]
    channel_signing_key_file: Option<PathBuf>,
    /// In hex. Defaults to the one in `<home>/bedrock_funding_public_key`.
    #[clap(long, env = "SEQUENCER_FUNDING_PUBLIC_KEY")]
    funding_public_key: Option<String>,
    /// Overrides the config's `bedrock_config.node_url`.
    #[clap(long, env = "SEQUENCER_BEDROCK_NODE_URL")]
    bedrock_node_url: Option<String>,
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
    /// Overrides the config's `metrics_listen_address`.
    #[clap(long, env = "SEQUENCER_METRICS_LISTEN_ADDRESS")]
    metrics_listen_address: Option<SocketAddr>,
    /// Gossip's QUIC (UDP) address. Turns gossip on if the config leaves it off.
    #[clap(long, env = "SEQUENCER_GOSSIP_LISTEN_ADDR")]
    gossip_listen_addr: Option<SocketAddr>,
    /// `host:port` or a multiaddr; repeat, or comma-separate in the env var, for several.
    /// Replaces the config's `bootstrap_peers`, and turns gossip on.
    #[clap(long, env = "SEQUENCER_GOSSIP_BOOTSTRAP_PEER", value_delimiter = ',')]
    gossip_bootstrap_peer: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let traces = traces::Traces::from_env()?;
    tracing_subscriber::registry()
        .with(logging::layer(log_filter()))
        .with(actor_metrics::layer())
        .with(
            traces
                .as_ref()
                .map(|traces| traces.layer(logging::EnvFilter::from_default_env())),
        )
        .try_init()
        .context("Failed to install the tracing subscriber")?;
    let args = Args::parse();

    match args.command {
        Command::Setup {
            home,
            config,
            funding_public_key,
            create_channel,
        } => {
            let template = std::fs::read_to_string(&config)
                .with_context(|| format!("Failed to read {}", config.display()))?;
            operator::setup(&home, &template, &funding_public_key, create_channel)
        }
        Command::Start(args) => start(args, traces.as_ref()).await,
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
        Command::VoteParams {
            sequencer_key,
            changes,
            wallet_home,
        } => operator::vote_params(wallet_home, sequencer_key, changes).await,
        Command::WithdrawParamsVote {
            sequencer_key,
            wallet_home,
        } => operator::withdraw_params_vote(wallet_home, sequencer_key).await,
    }
}

/// `RUST_LOG`, plus kameo's spans around each actor and message handler when
/// logging JSON, so every line an actor logs names it, whatever `RUST_LOG`
/// says of kameo. Plain text goes without, as each line would start with the
/// actor's full type name.
fn log_filter<S>() -> impl Filter<S> {
    let actor_spans = logging::Format::from_env() == logging::Format::Json;
    logging::EnvFilter::from_default_env().or(FilterFn::new(move |metadata| {
        actor_spans && metadata.is_span() && metadata.target().starts_with("kameo::")
    }))
}

#[expect(
    clippy::integer_division_remainder_used,
    reason = "Generated by select! macro, can't be easily rewritten to avoid this lint"
)]
async fn start(args: StartArgs, traces: Option<&traces::Traces>) -> Result<()> {
    let cancellation_token = listen_for_shutdown_signal();

    let config = load_config(&args)?;
    log_config(&config)?;
    let public_key = channel_public_key(&config)?;
    if let Some(traces) = traces {
        traces.set_sequencer(&public_key);
    }

    // Served from the start, so probes and metrics answer while startup waits on Bedrock.
    let sequencer_cell = Arc::new(OnceLock::new());
    let ops_shutdown = CancellationToken::new();
    let ops_server = match config.metrics_listen_address {
        Some(address) => Some(tokio::spawn(ops::serve(
            ops::bind(address).await?,
            install_prometheus_recorder(&public_key)?,
            Arc::clone(&sequencer_cell),
            ops_shutdown.clone(),
        ))),
        None => None,
    };
    // Startup can wait on Bedrock for long, e.g. `--wait-for-channel`, so a stop must cut it short.
    let sequencer_handle = tokio::select! {
        handle = sequencer_service::run(config, args.rpc_listen_address) => Arc::new(handle?),
        () = cancellation_token.cancelled() => {
            info!("Stopped before the sequencer finished starting");
            return Ok(());
        }
    };
    sequencer_cell.get_or_init(|| Arc::clone(&sequencer_handle));

    tokio::select! {
        () = cancellation_token.cancelled() => {
            info!("Shutting down sequencer");
        }
        Err(err) = sequencer_handle.failed() => {
            error!(error = %err, "Sequencer failed unexpectedly");
        }
    }

    // Stop the watchers, the publisher's drive task, the block loop and the RPC
    // server, and wait for each. Dropping the handle only asks; the store stays
    // open for an unbounded stretch after that, so a restart can find its own
    // home directory locked, and a watcher can be killed between recording a
    // delivery and handing it over.
    ops_shutdown.cancel();
    if let Some(ops_server) = ops_server {
        match ops_server.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => error!(error = format_args!("{err:#}"), "Ops server failed"),
            Err(err) => error!(error = %err, "Ops server panicked"),
        }
    }
    drop(sequencer_cell);
    Arc::into_inner(sequencer_handle)
        .expect("the ops server, the only other holder, has stopped")
        .shutdown()
        .await;

    info!("Sequencer shutdown complete");

    Ok(())
}

/// The config file with `args` applied over it.
fn load_config(args: &StartArgs) -> Result<SequencerConfig> {
    let explicit_config = args.config.is_some();
    ensure!(
        explicit_config || !args.create_channel,
        "--create-channel needs --config; a home's own config keeps what `setup` decided"
    );
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
    // Serializes as a hex string, which would otherwise show in quotes.
    let funding_public_key = serde_json::to_value(config.load_funding_public_key()?)?;
    let funding_public_key = funding_public_key
        .as_str()
        .map_or_else(|| funding_public_key.to_string(), str::to_owned);
    info!(
        config = %serde_json::to_string(&shown)?,
        channel_signing_key_file = %config.channel_signing_key_path().display(),
        %funding_public_key,
        "Starting with config"
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

/// The channel signing public key: what tells sequencers apart in metrics and
/// traces.
fn channel_public_key(config: &SequencerConfig) -> Result<Ed25519PublicKey> {
    let channel_signing_key =
        sequencer_core::load_or_create_signing_key(&config.channel_signing_key_path())?;
    Ok(channel_signing_key.public_key())
}

/// Installs the recorder, whose metrics the ops server renders. Every series is
/// labelled with `public_key`, in hex, so sequencers stay apart wherever they
/// are scraped.
fn install_prometheus_recorder(public_key: &Ed25519PublicKey) -> Result<PrometheusHandle> {
    let handle = prometheus_builder(hex::encode(public_key.as_bytes()))?
        .install_recorder()
        .context("Failed to install Prometheus recorder")?;
    // Without the exporter's own listener, draining histograms is ours to schedule.
    let upkeep = handle.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            upkeep.run_upkeep();
        }
    });
    Ok(handle)
}

/// The exporter's naming, buckets and `public_key` label.
fn prometheus_builder(public_key: String) -> Result<PrometheusBuilder> {
    /// Ladder for `*_seconds` histograms, densest across the 1-100 ms band where
    /// block production and transaction application actually land.
    const LATENCY_BUCKETS: &[f64] = &[
        0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ];

    /// Fallback ladder for histograms that count things rather than measure time.
    const COUNT_BUCKETS: &[f64] = &[1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0];

    PrometheusBuilder::new()
        .with_recommended_naming(true)
        .add_global_label(
            sequencer_service_metrics::names::SEQUENCER_LABEL,
            public_key,
        )
        .set_buckets(COUNT_BUCKETS)
        .context("Failed to set default histogram buckets")?
        .set_buckets_for_metric(Matcher::Suffix("_seconds".to_owned()), LATENCY_BUCKETS)
        .context("Failed to set latency histogram buckets")
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
                error!(error = %err, "Failed to listen for SIGTERM");
                return;
            }
        };

        tokio::select! {
            result = tokio::signal::ctrl_c() => match result {
                Ok(()) => info!("Received Ctrl-C signal"),
                Err(err) => {
                    error!(error = %err, "Failed to listen for Ctrl-C signal");
                    return;
                }
            },
            _ = terminate.recv() => info!("Received SIGTERM"),
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

    #[test]
    fn network_configs_parse() {
        for config in [
            include_str!("../networks/local.json"),
            include_str!("../networks/devnet.json"),
            include_str!("../networks/testnet.json"),
        ] {
            SequencerConfig::from_json(config).unwrap();
        }
    }

    /// Kameo, not us, names these series: a rename in a kameo upgrade must fail
    /// here rather than blank the actors dashboard.
    #[tokio::test]
    async fn kameo_renders_the_actor_series_the_dashboard_reads() {
        use kameo::{
            actor::Spawn as _,
            message::{Context, Message},
        };
        use sequencer_service_metrics::names::{
            ACTOR_NAME_LABEL, KAMEO_LIFECYCLE_RECEIVED_TOTAL, KAMEO_LINK_DIED_RECEIVED_TOTAL,
            KAMEO_MESSAGES_RECEIVED_TOTAL, KAMEO_MESSAGES_SENT_TOTAL,
        };

        #[derive(kameo::Actor)]
        struct Echo;

        struct Ping;

        impl Message<Ping> for Echo {
            type Reply = ();

            async fn handle(&mut self, _: Ping, _: &mut Context<Self, Self::Reply>) {}
        }

        let recorder = prometheus_builder("test".to_owned())
            .unwrap()
            .build_recorder();
        // Kameo binds its counters to the recorder when the mailbox is created.
        let mailbox = metrics::with_local_recorder(&recorder, || kameo::mailbox::bounded(8));
        let echo = Echo::spawn_with_mailbox(Echo, mailbox);
        echo.ask(Ping).await.unwrap();

        let rendered = recorder.handle().render();
        let actor_name = format!(r#"{ACTOR_NAME_LABEL}="{}""#, <Echo as kameo::Actor>::name());
        for (metric, value) in [
            (KAMEO_MESSAGES_SENT_TOTAL, 1),
            (KAMEO_MESSAGES_RECEIVED_TOTAL, 1),
            // Startup finished.
            (KAMEO_LIFECYCLE_RECEIVED_TOTAL, 1),
            (KAMEO_LINK_DIED_RECEIVED_TOTAL, 0),
        ] {
            let found = rendered.lines().any(|line| {
                line.starts_with(&format!("{metric}{{"))
                    && line.contains(&actor_name)
                    && line.ends_with(&format!(" {value}"))
            });
            assert!(found, "no `{metric}` = {value} for Echo in:\n{rendered}");
        }
    }
}
