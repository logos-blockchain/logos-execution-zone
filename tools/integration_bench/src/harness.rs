//! Step / scenario timing primitives shared across scenarios.

#![allow(
    clippy::ref_option,
    reason = "serde::serialize_with requires fn(&Option<T>, S) -> Result<...>"
)]

use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use common::transaction::NSSATransaction;
use sequencer_service_rpc::RpcClient as _;
use serde::{Serialize, Serializer};
use test_fixtures::{DiskSizes, TestContext};
use wallet::cli::SubcommandReturnValue;

const TX_INCLUSION_POLL_INTERVAL: Duration = Duration::from_millis(250);
const TX_INCLUSION_TIMEOUT: Duration = Duration::from_secs(120);

/// Borsh-serialized sizes for one zone block fetched after a step. `block_bytes`
/// is the full Block (header + body + bedrock metadata) and is the closest
/// proxy we have to the L1 payload posted per block. `tx_bytes` is each contained
/// transaction split by variant, which is what the fee model's `S_tx` slot covers.
#[derive(Debug, Serialize, Clone, Default)]
pub struct BlockSize {
    pub block_id: u64,
    pub block_bytes: usize,
    pub public_tx_bytes: Vec<usize>,
    pub ppe_tx_bytes: Vec<usize>,
    pub deploy_tx_bytes: Vec<usize>,
}

#[derive(Debug, Serialize, Clone)]
pub struct StepResult {
    pub label: String,
    #[serde(serialize_with = "ser_duration_secs", rename = "submit_s")]
    pub submit: Duration,
    #[serde(serialize_with = "ser_opt_duration_secs", rename = "inclusion_s")]
    pub inclusion: Option<Duration>,
    #[serde(serialize_with = "ser_opt_duration_secs", rename = "wallet_sync_s")]
    pub wallet_sync: Option<Duration>,
    #[serde(serialize_with = "ser_duration_secs", rename = "total_s")]
    pub total: Duration,
    pub tx_hash: Option<String>,
    /// Borsh sizes for every zone block produced during this step.
    /// Empty for steps that don't advance the chain (e.g. `RegisterAccount`).
    pub blocks: Vec<BlockSize>,
}

#[derive(Debug, Serialize, Default)]
pub struct ScenarioOutput {
    pub name: String,
    pub steps: Vec<StepResult>,
    #[serde(serialize_with = "ser_duration_secs", rename = "total_s")]
    pub total: Duration,
    /// Disk sizes (sequencer / indexer / wallet tempdirs) sampled at scenario start.
    pub disk_before: Option<DiskSizes>,
    /// Disk sizes sampled at scenario end.
    pub disk_after: Option<DiskSizes>,
    /// Bedrock-finality latency: time from final-step inclusion to the indexer
    /// reporting the sequencer tip as L1-finalised. Effectively measures the
    /// sequencer→Bedrock posting + Bedrock finalisation + indexer L1 ingest path.
    /// A value at the timeout (60s) means finalisation did not happen within the bench window.
    #[serde(
        serialize_with = "ser_opt_duration_secs",
        rename = "bedrock_finality_s"
    )]
    pub bedrock_finality: Option<Duration>,
}

impl ScenarioOutput {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    pub fn push(&mut self, step: StepResult) {
        self.total = self.total.saturating_add(step.total);
        self.steps.push(step);
    }

    /// Run a single timed step against `ctx`: capture pre-block, run `submit`,
    /// finalize timings, push a `StepResult` onto `self.steps`. Returns the
    /// `SubcommandReturnValue` from `submit` so the caller can match on it.
    pub async fn step(
        &mut self,
        ctx: &mut TestContext,
        label: impl Into<String>,
        submit: impl AsyncFnOnce(&mut TestContext) -> Result<SubcommandReturnValue>,
    ) -> Result<SubcommandReturnValue> {
        let pre_block = begin_step(ctx).await?;
        let started = Instant::now();
        let ret = submit(ctx).await?;
        let step = finalize_step(label, started, pre_block, &ret, ctx).await?;
        self.push(step);
        Ok(ret)
    }
}

/// Begin a timed step. Capture this *before* submitting the wallet operation
/// so we can later subtract it from the post-submit block height to detect
/// when the chain has advanced past the tx's block.
async fn begin_step(ctx: &TestContext) -> Result<u64> {
    Ok(ctx.sequencer_client().get_last_block_id().await?)
}

/// Finish a timed wallet step. Records submit (the time between `started`
/// being captured and `ret` being received) and, if `ret` is a
/// [`SubcommandReturnValue::PrivacyPreservingTransfer`], polls the sequencer
/// for inclusion and records the inclusion latency. Returns a [`StepResult`].
async fn finalize_step(
    label: impl Into<String>,
    started: Instant,
    pre_block_id: u64,
    ret: &SubcommandReturnValue,
    ctx: &mut TestContext,
) -> Result<StepResult> {
    let label = label.into();
    let submit = started.elapsed();

    let mut tx_hash_str = None;
    let mut inclusion = None;
    let mut wallet_sync = None;
    let mut blocks: Vec<BlockSize> = Vec::new();

    // For non-account-create steps (anything that produces a tx_hash, or even
    // `Empty` for public Token Send), wait for the chain to advance past the
    // submission block so state is applied before the next step. We use
    // get_last_block_id as the canonical "block has been produced and
    // recorded" signal.
    let should_wait_for_chain = !matches!(ret, SubcommandReturnValue::RegisterAccount { .. });
    if should_wait_for_chain {
        if let SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash } = ret {
            tx_hash_str = Some(format!("{tx_hash}"));
        }
        let started_inclusion = Instant::now();
        wait_for_chain_advance(ctx, pre_block_id, 2).await?;
        inclusion = Some(started_inclusion.elapsed());

        let started_sync = Instant::now();
        sync_wallet_to_tip(ctx).await?;
        wallet_sync = Some(started_sync.elapsed());

        // Capture block-byte and per-tx-byte sizes for every block produced
        // during this step. We intentionally capture all blocks, including
        // empty clock-only ticks: the empty-block baseline lets the fee model
        // back out the per-tx contribution.
        let tip = ctx.sequencer_client().get_last_block_id().await?;
        for block_id in (pre_block_id.saturating_add(1))..=tip {
            if let Some(block) = ctx.sequencer_client().get_block(block_id).await? {
                let block_bytes = borsh::to_vec(&block).map_or(0, |v| v.len());
                let mut sz = BlockSize {
                    block_id,
                    block_bytes,
                    public_tx_bytes: Vec::new(),
                    ppe_tx_bytes: Vec::new(),
                    deploy_tx_bytes: Vec::new(),
                };
                for tx in &block.body.transactions {
                    let n = borsh::to_vec(tx).map_or(0, |v| v.len());
                    match tx {
                        NSSATransaction::Public(_) => sz.public_tx_bytes.push(n),
                        NSSATransaction::PrivacyPreserving(_) => sz.ppe_tx_bytes.push(n),
                        NSSATransaction::ProgramDeployment(_) => sz.deploy_tx_bytes.push(n),
                    }
                }
                blocks.push(sz);
            }
        }
    }

    Ok(StepResult {
        label,
        submit,
        inclusion,
        wallet_sync,
        total: started.elapsed(),
        tx_hash: tx_hash_str,
        blocks,
    })
}

/// Wait for `get_last_block_id` to advance by at least `min_blocks` from `from_block_id`.
pub async fn wait_for_chain_advance(
    ctx: &TestContext,
    from_block_id: u64,
    min_blocks: u64,
) -> Result<()> {
    let target = from_block_id.saturating_add(min_blocks);
    let poll = async {
        loop {
            match ctx.sequencer_client().get_last_block_id().await {
                Ok(current) if current >= target => return,
                Ok(_) => {}
                Err(err) => eprintln!("get_last_block_id error (continuing poll): {err:#}"),
            }
            tokio::time::sleep(TX_INCLUSION_POLL_INTERVAL).await;
        }
    };
    match tokio::time::timeout(TX_INCLUSION_TIMEOUT, poll).await {
        Ok(()) => Ok(()),
        Err(_) => bail!(
            "chain did not advance from {from_block_id} to at least {target} within {TX_INCLUSION_TIMEOUT:?}"
        ),
    }
}

async fn sync_wallet_to_tip(ctx: &mut TestContext) -> Result<()> {
    let last_block = ctx.sequencer_client().get_last_block_id().await?;
    ctx.wallet_mut().sync_to_block(last_block).await?;
    Ok(())
}

pub fn print_table(output: &ScenarioOutput) {
    let label_width = output
        .steps
        .iter()
        .map(|s| s.label.len())
        .max()
        .unwrap_or(0)
        .max("step".len());

    println!(
        "\nScenario: {} (total {:.2}s)",
        output.name,
        output.total.as_secs_f64(),
    );
    println!(
        "{:<lw$}  {:>10}  {:>12}  {:>10}  {:>10}",
        "step",
        "submit_s",
        "inclusion_s",
        "sync_s",
        "total_s",
        lw = label_width,
    );
    println!("{}", "-".repeat(label_width.saturating_add(50)));
    for s in &output.steps {
        let inclusion = s
            .inclusion
            .map_or_else(|| "-".to_owned(), |v| format!("{:.3}", v.as_secs_f64()));
        let sync = s
            .wallet_sync
            .map_or_else(|| "-".to_owned(), |v| format!("{:.3}", v.as_secs_f64()));
        println!(
            "{:<lw$}  {:>10.3}  {:>12}  {:>10}  {:>10.3}",
            s.label,
            s.submit.as_secs_f64(),
            inclusion,
            sync,
            s.total.as_secs_f64(),
            lw = label_width,
        );
    }

    print_size_summary(output);
}

/// Aggregate borsh sizes per scenario: total/mean/min/max block bytes, and
/// per-tx bytes split by variant. Empty if no blocks were captured.
fn print_size_summary(output: &ScenarioOutput) {
    let blocks: Vec<&BlockSize> = output.steps.iter().flat_map(|s| s.blocks.iter()).collect();
    if blocks.is_empty() {
        return;
    }

    let block_bytes: Vec<usize> = blocks.iter().map(|b| b.block_bytes).collect();
    let total_block_bytes: usize = block_bytes.iter().sum();
    let mean_block = mean_usize(&block_bytes);
    let min_block = block_bytes.iter().copied().min().unwrap_or(0);
    let max_block = block_bytes.iter().copied().max().unwrap_or(0);

    let public: Vec<usize> = blocks
        .iter()
        .flat_map(|b| b.public_tx_bytes.iter().copied())
        .collect();
    let ppe: Vec<usize> = blocks
        .iter()
        .flat_map(|b| b.ppe_tx_bytes.iter().copied())
        .collect();
    let deploy: Vec<usize> = blocks
        .iter()
        .flat_map(|b| b.deploy_tx_bytes.iter().copied())
        .collect();

    println!(
        "\nBlock + tx size summary ({} blocks captured):",
        blocks.len()
    );
    println!(
        "  block_bytes: total={total_block_bytes}, mean={mean_block}, min={min_block}, max={max_block}",
    );
    print_tx_line("public_tx_bytes      ", &public);
    print_tx_line("ppe_tx_bytes         ", &ppe);
    print_tx_line("deploy_tx_bytes      ", &deploy);
}

fn print_tx_line(label: &str, samples: &[usize]) {
    if samples.is_empty() {
        println!("  {label}: (none)");
        return;
    }
    let total: usize = samples.iter().sum();
    let mean = mean_usize(samples);
    let min = samples.iter().copied().min().unwrap_or(0);
    let max = samples.iter().copied().max().unwrap_or(0);
    println!(
        "  {label}: n={}, total={total}, mean={mean}, min={min}, max={max}",
        samples.len()
    );
}

fn mean_usize(xs: &[usize]) -> usize {
    xs.iter().sum::<usize>().checked_div(xs.len()).unwrap_or(0)
}

fn ser_duration_secs<S: Serializer>(d: &Duration, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_f64(d.as_secs_f64())
}

fn ser_opt_duration_secs<S: Serializer>(
    d: &Option<Duration>,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    match d {
        Some(d) => s.serialize_f64(d.as_secs_f64()),
        None => s.serialize_none(),
    }
}
