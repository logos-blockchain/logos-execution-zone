use std::{path::PathBuf, sync::Arc};

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};
use lee::Balance;
#[cfg(test)]
use sequencer_service::ops::prometheus_builder;
use sequencer_service::{SequencerConfig, StartArgs, channel_public_key, ops::OpsServer};
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

    let config = args.load_config()?;
    log_config(&config)?;
    let public_key = channel_public_key(&config)?;
    if let Some(traces) = traces {
        traces.set_sequencer(&public_key);
    }

    // Served from the start, so probes and metrics answer while startup waits on Bedrock.
    let ops_server = OpsServer::start(config.metrics_listen_address, &public_key).await?;
    // Startup can wait on Bedrock for long, e.g. `--wait-for-channel`, so a stop must cut it short.
    let sequencer_handle = tokio::select! {
        handle = sequencer_service::run(config, args.rpc_listen_address) => Arc::new(handle?),
        () = cancellation_token.cancelled() => {
            info!("Stopped before the sequencer finished starting");
            return Ok(());
        }
    };
    if let Some(ops_server) = &ops_server {
        ops_server.set_sequencer(&sequencer_handle);
    }

    tokio::select! {
        () = cancellation_token.cancelled() => {
            info!("Shutting down sequencer");
        }
        Err(err) = sequencer_handle.failed() => {
            error!(error = %err, "Sequencer failed unexpectedly");
        }
    }

    // Stop the publisher's drive task, the block loop and the RPC server, and
    // wait for each. Dropping the handle only asks; the store stays open for an
    // unbounded stretch after that, so a restart can find its own home directory
    // locked.
    if let Some(ops_server) = ops_server {
        ops_server.stop().await;
    }
    // The ops server only holds a `Weak`, so this is the last strong reference.
    if let Some(handle) = Arc::into_inner(sequencer_handle) {
        handle.shutdown().await;
    } else {
        error!("Sequencer handle still shared, dropping it without waiting for shutdown");
    }

    info!("Sequencer shutdown complete");

    Ok(())
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
