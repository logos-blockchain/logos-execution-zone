//! End-to-end LEZ scenario bench.
//!
//! Spins up the full stack via `test_fixtures::TestContext` (docker-compose
//! Bedrock + in-process sequencer + indexer + wallet) once for the whole run,
//! then drives the wallet through each requested scenario against that single
//! shared stack. Times each step and records borsh-serialized block + tx sizes
//! per scenario.
//!
//! Prerequisite: a working local Docker daemon. The Bedrock service is brought
//! up via the same `bedrock/docker-compose.yml` the integration tests use, so
//! no host-side binary or env vars are required.
//!
//! Run examples:
//!   `RISC0_DEV_MODE=1 cargo run --release -p integration_bench -- --scenario all`.
//!   `cargo run --release -p integration_bench -- --scenario amm`.
//!
//! `RISC0_DEV_MODE=1` skips proving and produces latency-only numbers in
//! ~minutes; omitting it produces realistic proving-inclusive numbers but
//! the run takes much longer.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::shadow_unrelated,
    clippy::wildcard_enum_match_arm,
    reason = "Bench tool: stderr/stdout output is the deliverable; small Duration / iterator-sum \
              arithmetic is safe at bench scale; bench scenarios bail loudly on any unexpected \
              return variant, which is preferable to maintaining an exhaustive list in five files; \
              the step() closure helper canonically rebinds `ctx` inside the closure body."
)]

use std::{path::PathBuf, time::Duration};

use anyhow::{Context as _, Result};
use clap::{Parser, ValueEnum};
use harness::ScenarioOutput;
use serde::Serialize;
use test_fixtures::TestContext;

mod harness;
mod scenarios;

#[derive(Copy, Clone, Debug, ValueEnum)]
enum ScenarioName {
    Token,
    Amm,
    Fanout,
    Private,
    Parallel,
    All,
}

#[derive(Parser, Debug)]
#[command(about = "End-to-end LEZ scenario bench")]
struct Cli {
    /// Which scenario(s) to run.
    #[arg(long, value_enum, default_value_t = ScenarioName::All)]
    scenario: ScenarioName,

    /// Optional JSON output path. Defaults to `<workspace>/target/integration_bench.json`.
    #[arg(long)]
    json_out: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct BenchRunReport {
    risc0_dev_mode: bool,
    /// Time to bring up the shared `TestContext` (docker-compose Bedrock +
    /// sequencer + indexer + wallet). Paid once per run regardless of how many
    /// scenarios are exercised.
    shared_setup_s: f64,
    scenarios: Vec<ScenarioOutput>,
    total_wall_s: f64,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    // test_fixtures initializes env_logger via a LazyLock, so we leave logger
    // setup to it. Set RUST_LOG=info before running to see logs.

    let cli = Cli::parse();
    let risc0_dev_mode = std::env::var("RISC0_DEV_MODE").is_ok_and(|v| !v.is_empty() && v != "0");

    eprintln!(
        "integration_bench: scenario={:?}, RISC0_DEV_MODE={}",
        cli.scenario,
        if risc0_dev_mode { "1" } else { "unset/0" }
    );

    let to_run: Vec<ScenarioName> = match cli.scenario {
        ScenarioName::All => vec![
            ScenarioName::Token,
            ScenarioName::Amm,
            ScenarioName::Fanout,
            ScenarioName::Private,
            ScenarioName::Parallel,
        ],
        other => vec![other],
    };

    let overall_started = std::time::Instant::now();

    // One shared stack for the entire run: docker-compose Bedrock + sequencer +
    // indexer + wallet. Scenarios share chain state, which matches how the node
    // runs in production (long-lived, accumulating).
    let setup_started = std::time::Instant::now();
    let mut ctx = TestContext::new()
        .await
        .context("failed to setup TestContext")?;
    let shared_setup = setup_started.elapsed();
    eprintln!("setup: {:.2}s", shared_setup.as_secs_f64());

    let mut all_outputs = Vec::with_capacity(to_run.len());

    for name in to_run {
        eprintln!("\n=== running scenario: {name:?} ===");
        let disk_before = ctx.disk_sizes();
        let mut output = run_scenario(name, &mut ctx).await?;
        output.disk_before = Some(disk_before);
        output.disk_after = Some(ctx.disk_sizes());
        output.bedrock_finality = Some(measure_bedrock_finality(&ctx).await?);
        harness::print_table(&output);
        all_outputs.push(output);
    }

    let total_wall_s = overall_started.elapsed().as_secs_f64();
    eprintln!("\nTotal wall time: {total_wall_s:.1}s");

    let report = BenchRunReport {
        risc0_dev_mode,
        shared_setup_s: shared_setup.as_secs_f64(),
        scenarios: all_outputs,
        total_wall_s,
    };

    let out_path = if let Some(p) = cli.json_out {
        p
    } else {
        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .canonicalize()?;
        let suffix = if risc0_dev_mode { "dev" } else { "prove" };
        workspace_root
            .join("target")
            .join(format!("integration_bench_{suffix}.json"))
    };
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&out_path, serde_json::to_string_pretty(&report)?)?;
    eprintln!("\nJSON written to {}", out_path.display());

    Ok(())
}

async fn run_scenario(name: ScenarioName, ctx: &mut TestContext) -> Result<ScenarioOutput> {
    match name {
        ScenarioName::Token => scenarios::token::run(ctx).await,
        ScenarioName::Amm => scenarios::amm::run(ctx).await,
        ScenarioName::Fanout => scenarios::fanout::run(ctx).await,
        ScenarioName::Private => scenarios::private::run(ctx).await,
        ScenarioName::Parallel => scenarios::parallel::run(ctx).await,
        ScenarioName::All => unreachable!("dispatched above"),
    }
}

/// Poll the indexer's L1-finalised block id until it catches up with the
/// sequencer's last block id. This is effectively the sequencer→Bedrock posting
/// plus Bedrock finalisation plus indexer ingest latency.
async fn measure_bedrock_finality(ctx: &TestContext) -> Result<Duration> {
    use indexer_service_rpc::RpcClient as _;
    use jsonrpsee::ws_client::WsClientBuilder;
    use sequencer_service_rpc::RpcClient as _;

    let indexer_url = format!("ws://{}", ctx.indexer_addr());
    let indexer_ws = WsClientBuilder::default()
        .build(&indexer_url)
        .await
        .context("connect indexer WS")?;
    let sequencer_tip = ctx.sequencer_client().get_last_block_id().await?;

    let timeout = Duration::from_mins(1);
    let started = std::time::Instant::now();
    let poll = async {
        loop {
            match indexer_ws.get_last_finalized_block_id().await {
                Ok(Some(b)) if b >= sequencer_tip => return,
                Ok(_) => {}
                Err(err) => eprintln!("indexer last_synced poll error: {err:#}"),
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    };
    if tokio::time::timeout(timeout, poll).await.is_err() {
        eprintln!("indexer did not catch up to {sequencer_tip} within {timeout:?}");
    }
    Ok(started.elapsed())
}
