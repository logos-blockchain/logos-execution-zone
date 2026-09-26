//! Measures Risc0 user cycles per built-in program instruction.
//!
//! Runs each guest ELF through the Risc0 executor (no proving) with realistic inputs
//! drawn from the existing per-program unit tests, then prints a table and writes a
//! JSON dump for regression comparison.
//!
//! A program instruction is two kinds of guest invocation, not one: a planner run that sees
//! only account handles and emits shard effects, and one apply run per effect that sees a
//! single shard's data. Both are measured, one row each, because a caller pays for all of them.
//!
//! Run with `cargo run --release -p cycle_bench`. `RISC0_DEV_MODE` has no effect on
//! executor cycle counts.

#![expect(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_precision_loss,
    clippy::float_arithmetic,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    clippy::missing_const_for_fn,
    clippy::non_ascii_literal,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::suboptimal_flops,
    reason = "Bench tool: matches test-style fixture code"
)]

use std::{collections::HashMap, path::PathBuf, time::Instant};

use amm_core::{PoolDefinition, compute_liquidity_token_pda, compute_pool_pda, compute_vault_pda};
use anyhow::{Result, bail};
use associated_token_account_core::{
    AtaContents, compute_ata_seed, get_associated_token_account_id,
};
use clap::Parser;
use clock_core::{
    CLOCK_01_PROGRAM_ACCOUNT_ID, CLOCK_10_PROGRAM_ACCOUNT_ID, CLOCK_50_PROGRAM_ACCOUNT_ID,
    ClockAccountData,
};
use cycle_bench::{ppe, stats::Stats};
use lee::program::Program;
use lee_core::{
    BlockId, Timestamp,
    account::{AccountId, ProgramShardSelector, ShardData},
    from_frame,
    native_token::encode_balance,
    program::{AccountMeta, ApplyInput, GuestOutput, InstructionData, PlanInput, PlanOutput},
};
use risc0_zkvm::{ExecutorEnv, default_executor, default_prover};
use serde::Serialize;
use token_core::{TokenDefinition, TokenDescriptor, TokenHolding, TokenKind};

/// The AMM pool fixture's reserves: lp supply is `sqrt(1000*500) = 707`.
const AMM_RESERVE_A: u128 = 1_000;
const AMM_RESERVE_B: u128 = 500;

#[derive(Parser, Debug)]
#[command(about = "Per-program executor and (optionally) prover cycle measurements")]
struct Cli {
    /// Also run prover.prove for each case and report wall time + cycles. Slow.
    #[arg(long)]
    prove: bool,

    /// Also run privacy-preserving execution circuit (PPE) composition cases:
    /// (a) single native Transfer through `execute_and_prove`, (b) `chain_caller`
    /// with depth N=1,3,5,9. Requires --features ppe at build time. Very slow.
    #[arg(long)]
    ppe: bool,

    /// Iterations for executor wall-time sampling per case. First iter is
    /// discarded as warmup, remaining N feed the stats.
    #[arg(long, default_value_t = 5)]
    exec_iters: usize,
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Phase {
    Plan,
    Apply,
}

impl Phase {
    const fn label(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Apply => "apply",
        }
    }
}

#[derive(Debug, Serialize)]
struct BenchResult {
    program_name: &'static str,
    instruction: String,
    phase: Phase,
    user_cycles: u64,
    segments: usize,
    exec_stats: Stats,
    /// Compute-only execution time (ms): best-of-N executor wall-time minus the calibrated
    /// host-side fixed per-call overhead. Filled after the calibration fit over all cases.
    net_compute_ms: Option<f64>,
    /// Deterministic model prediction of compute time (ms): `user_cycles * slope` from the
    /// calibration fit. Pure function of the deterministic cycle count and the pinned-hardware
    /// throughput, so it reproduces across re-runs where raw wall-time does not.
    calibrated_ms: Option<f64>,
    /// Stats over prover.prove(env, elf) wall-clock samples. Only populated when --prove is set.
    /// Single-sample (n=1) when --prove is on without explicit repetition, since proving is slow.
    prove_stats: Option<Stats>,
    /// Total cycles (with continuation overhead, paging, po2 padding) from ProveInfo.stats.
    prove_total_cycles: Option<u64>,
    /// User cycles from ProveInfo.stats (should match executor cycles).
    prove_user_cycles: Option<u64>,
    /// Paging cycles from ProveInfo.stats.
    prove_paging_cycles: Option<u64>,
    /// Segments from ProveInfo.stats.
    prove_segments: Option<usize>,
}

/// Linear calibration of executor wall-time against deterministic user cycles,
/// fitted across all standalone cases as `best_ms = intercept_ms + slope_ms_per_cycle *
/// user_cycles`.
///
/// The intercept is the host-side fixed per-call cost (ELF parse, `ExecutorEnv` build) that is
/// outside the cycle count and does not scale with the instruction's work. The slope is the
/// per-cycle execution rate on the pinned box; its reciprocal is the throughput the tokenomics
/// fee model denominates public execution in, and is the public-side counterpart to the flat
/// `G_verify` verify cost. The intercept is an ELF-size-averaged constant, so `net_compute_ms`
/// is a first-order decomposition, not a mechanistic per-program overhead.
#[derive(Debug, Serialize, Clone, Copy)]
struct Calibration {
    /// Cases the fit was computed over.
    n: usize,
    /// Slope: milliseconds of executor wall-time per user cycle.
    slope_ms_per_cycle: f64,
    /// Intercept: host-side fixed per-call overhead in milliseconds.
    intercept_ms: f64,
    /// Reciprocal of the slope: cycles executed per millisecond on the pinned box.
    throughput_cycles_per_ms: f64,
    /// Coefficient of determination of the fit (1.0 = perfect linear fit).
    r2: f64,
}

impl Calibration {
    /// Ordinary least squares of `best_ms` (y) on `user_cycles` (x) across `results`.
    /// The fit uses best-of-N rather than the mean so a single OS scheduling spike in one
    /// case cannot tilt the slope; best-of-N is the per-case noise floor and reproduces
    /// run-to-run, which is what a pinned-hardware throughput constant needs.
    /// Returns `None` when there are fewer than two distinct cycle counts to fit a line.
    fn fit(results: &[BenchResult]) -> Option<Self> {
        let n = results.len();
        if n < 2 {
            return None;
        }
        let xs: Vec<f64> = results.iter().map(|r| r.user_cycles as f64).collect();
        let ys: Vec<f64> = results.iter().map(|r| r.exec_stats.best_ms).collect();
        let nf = n as f64;
        let sum_x: f64 = xs.iter().sum();
        let sum_y: f64 = ys.iter().sum();
        let sum_xy: f64 = xs.iter().zip(&ys).map(|(x, y)| x * y).sum();
        let sum_xx: f64 = xs.iter().map(|x| x * x).sum();
        let denom = nf * sum_xx - sum_x.powi(2);
        if denom.abs() < f64::EPSILON {
            return None;
        }
        let slope = (nf * sum_xy - sum_x * sum_y) / denom;
        let intercept = (sum_y - slope * sum_x) / nf;
        let mean_y = sum_y / nf;
        let ss_tot: f64 = ys.iter().map(|y| (y - mean_y).powi(2)).sum();
        let ss_res: f64 = xs
            .iter()
            .zip(&ys)
            .map(|(x, y)| (y - (intercept + slope * x)).powi(2))
            .sum();
        // ss_tot ≈ 0 means every best_ms is identical; the ratio is 0/0. We report 1.0 (a flat
        // line fits a flat cloud exactly). This is a degenerate guard, not a real-data path: the
        // bench cases span a wide cycle range, so ss_tot is large in practice.
        let r2 = if ss_tot.abs() < f64::EPSILON {
            1.0
        } else {
            1.0 - ss_res / ss_tot
        };
        let throughput_cycles_per_ms = if slope.abs() < f64::EPSILON {
            0.0
        } else {
            1.0 / slope
        };
        Some(Self {
            n,
            slope_ms_per_cycle: slope,
            intercept_ms: intercept,
            throughput_cycles_per_ms,
            r2,
        })
    }

    /// Compute-time prediction for a cycle count: `slope * user_cycles` (overhead excluded).
    fn calibrated_ms(&self, user_cycles: u64) -> f64 {
        self.slope_ms_per_cycle * user_cycles as f64
    }
}

struct Fixture {
    account: AccountMeta,
    data: ShardData,
}

impl Fixture {
    fn new(
        account_id: AccountId,
        is_authorized: bool,
        program_account_id: AccountId,
        data: ShardData,
    ) -> Self {
        Self {
            account: AccountMeta::new(account_id, is_authorized, program_account_id),
            data,
        }
    }

    fn balance(account_id: AccountId, is_authorized: bool, balance: u128) -> Self {
        Self {
            account: AccountMeta::native_balance(account_id, is_authorized),
            data: encode_balance(balance),
        }
    }
}

struct Case {
    program_name: &'static str,
    instruction_label: &'static str,
    program: Program,
    fixtures: Vec<Fixture>,
    instruction_data: InstructionData,
}

impl Case {
    fn new<I: borsh::BorshSerialize>(
        program_name: &'static str,
        instruction_label: &'static str,
        program: Program,
        fixtures: Vec<Fixture>,
        instruction: &I,
    ) -> Result<Self> {
        Ok(Self {
            program_name,
            instruction_label,
            program,
            fixtures,
            instruction_data: borsh::to_vec(instruction)?,
        })
    }

    fn run(self, prove: bool, exec_iters: usize) -> Result<Vec<BenchResult>> {
        let Self {
            program_name,
            instruction_label,
            program,
            fixtures,
            instruction_data,
        } = self;
        let self_account_id = AccountId::from_builtin_program(program.id());

        let mut shards: HashMap<ProgramShardSelector, ShardData> = fixtures
            .iter()
            .map(|f| (ProgramShardSelector::from(&f.account), f.data.clone()))
            .collect();
        let input = PlanInput {
            self_account_id,
            caller_account_id: None,
            accounts: fixtures.into_iter().map(|f| f.account).collect(),
            instruction_data,
        };

        let mut rows = Vec::new();
        let (journal, row) = sample(
            program_name,
            instruction_label,
            Phase::Plan,
            &program,
            prove,
            exec_iters,
            |env| Ok(Program::write_plan_inputs(&input, env)?),
        )?;
        rows.push(row);

        let plan = plan_journal(&journal)?;
        for effect in plan.effects {
            let apply_input = ApplyInput {
                self_account_id,
                selector: effect.selector,
                pre_data: shards.get(&effect.selector).cloned().unwrap_or_default(),
                effect_data: effect.data,
            };
            let (output, apply_row) = sample(
                program_name,
                instruction_label,
                Phase::Apply,
                &program,
                prove,
                exec_iters,
                |env| Ok(Program::write_apply_inputs(&apply_input, env)?),
            )?;
            rows.push(apply_row);

            if let Some(post_data) = apply_journal(&output)?.post_data {
                shards.insert(effect.selector, post_data);
            }
        }

        Ok(rows)
    }
}

/// One warmup pass discarded. The executor has
/// large per-call setup overhead (ELF parsing, env init); reporting both
/// best-of-N and mean ± stdev shows whether jitter is significant.
fn sample(
    program_name: &'static str,
    instruction_label: &'static str,
    phase: Phase,
    program: &Program,
    prove: bool,
    exec_iters: usize,
    write: impl Fn(&mut risc0_zkvm::ExecutorEnvBuilder) -> Result<()>,
) -> Result<(Vec<u8>, BenchResult)> {
    let mut samples: Vec<f64> = Vec::with_capacity(exec_iters);
    let mut last_info = None;
    let total = exec_iters.saturating_add(1).max(2);
    for iter in 0..total {
        let mut env_builder = ExecutorEnv::builder();
        write(&mut env_builder)?;
        let env = env_builder.build()?;

        let started = Instant::now();
        let info = default_executor().execute(env, program.elf())?;
        let elapsed_ms = started.elapsed().as_secs_f64() * 1_000.0;

        if iter > 0 {
            samples.push(elapsed_ms);
        }
        last_info = Some(info);
    }
    let info = last_info.expect("at least one iteration");
    let exec_stats = Stats::from_samples(&samples);

    let mut prove_stats = None;
    let mut prove_total_cycles = None;
    let mut prove_user_cycles = None;
    let mut prove_paging_cycles = None;
    let mut prove_segments = None;
    if prove {
        let mut env_builder = ExecutorEnv::builder();
        write(&mut env_builder)?;
        let env = env_builder.build()?;

        let started = Instant::now();
        let prove_info = default_prover()
            .prove(env, program.elf())
            .map_err(|e| anyhow::anyhow!("prove failed: {e}"))?;
        let prove_ms = started.elapsed().as_secs_f64() * 1_000.0;
        prove_stats = Some(Stats::from_samples(&[prove_ms]));
        prove_total_cycles = Some(prove_info.stats.total_cycles);
        prove_user_cycles = Some(prove_info.stats.user_cycles);
        prove_paging_cycles = Some(prove_info.stats.paging_cycles);
        prove_segments = Some(prove_info.stats.segments);
        eprintln!(
            "  prove({program_name}/{instruction_label}/{}): {prove_ms:.1} ms ({:.1}s), total_cycles={}, segments={}",
            phase.label(),
            prove_ms / 1_000.0,
            prove_info.stats.total_cycles,
            prove_info.stats.segments,
        );
    }

    let result = BenchResult {
        program_name,
        instruction: instruction_label.to_owned(),
        phase,
        user_cycles: info.cycles(),
        segments: info.segments.len(),
        exec_stats,
        net_compute_ms: None,
        calibrated_ms: None,
        prove_stats,
        prove_total_cycles,
        prove_user_cycles,
        prove_paging_cycles,
        prove_segments,
    };
    Ok((info.journal.bytes, result))
}

fn guest_output(journal: &[u8]) -> Result<GuestOutput> {
    let payload = from_frame(journal).ok_or_else(|| anyhow::anyhow!("malformed journal frame"))?;
    Ok(borsh::from_slice(payload)?)
}

fn plan_journal(journal: &[u8]) -> Result<PlanOutput> {
    match guest_output(journal)? {
        GuestOutput::Plan(plan) => Ok(plan),
        GuestOutput::Apply(_) => bail!("a scheduled plan returned an apply journal"),
    }
}

fn apply_journal(journal: &[u8]) -> Result<lee_core::program::ApplyOutput> {
    match guest_output(journal)? {
        GuestOutput::Apply(output) => Ok(output),
        GuestOutput::Plan(_) => bail!("a scheduled apply returned a plan journal"),
    }
}

fn token_holding(
    definition_id: AccountId,
    account_id: AccountId,
    balance: u128,
    is_authorized: bool,
) -> Fixture {
    Fixture::new(
        account_id,
        is_authorized,
        programs::token_account_id(),
        ShardData::from(&TokenHolding::Fungible {
            definition_id,
            balance,
        }),
    )
}

fn token_definition(account_id: AccountId, total_supply: u128, is_authorized: bool) -> Fixture {
    Fixture::new(
        account_id,
        is_authorized,
        programs::token_account_id(),
        ShardData::from(&TokenDefinition::Fungible {
            name: String::from("test"),
            total_supply,
            metadata_id: None,
        }),
    )
}

fn token_definition_id() -> AccountId {
    AccountId::new([15; 32])
}

fn fungible(definition_id: AccountId) -> TokenDescriptor {
    TokenDescriptor {
        definition_id,
        kind: TokenKind::Fungible,
    }
}

fn token_transfer_accounts() -> Vec<Fixture> {
    let def = token_definition_id();
    let sender = token_holding(def, AccountId::new([17; 32]), 100_000, true);
    let recipient = token_holding(def, AccountId::new([42; 32]), 50_000, true);
    vec![sender, recipient]
}

fn token_definition_and_holding_accounts() -> Vec<Fixture> {
    let def_id = token_definition_id();
    let def = token_definition(def_id, 100_000, true);
    let holding = token_holding(def_id, AccountId::new([17; 32]), 1_000, true);
    vec![def, holding]
}

fn clock_account(account_id: AccountId, block_id: BlockId) -> Fixture {
    Fixture::new(
        account_id,
        false,
        programs::clock_account_id(),
        ClockAccountData {
            block_id,
            timestamp: Timestamp::from(0_u64),
        }
        .to_bytes()
        .try_into()
        .expect("ClockAccountData should fit in account data"),
    )
}

fn clock_accounts_tick_at(block_id: BlockId) -> Vec<Fixture> {
    vec![
        clock_account(CLOCK_01_PROGRAM_ACCOUNT_ID, block_id),
        clock_account(CLOCK_10_PROGRAM_ACCOUNT_ID, block_id),
        clock_account(CLOCK_50_PROGRAM_ACCOUNT_ID, block_id),
    ]
}

fn amm_lp_supply() -> u128 {
    (AMM_RESERVE_A * AMM_RESERVE_B).isqrt()
}

fn amm_token_a_def_id() -> AccountId {
    AccountId::new([42; 32])
}
fn amm_token_b_def_id() -> AccountId {
    AccountId::new([43; 32])
}
fn amm_pool_id() -> AccountId {
    compute_pool_pda(
        programs::amm_account_id(),
        amm_token_a_def_id(),
        amm_token_b_def_id(),
        programs::token_account_id(),
    )
}
fn amm_vault_a_id() -> AccountId {
    compute_vault_pda(
        programs::amm_account_id(),
        amm_pool_id(),
        amm_token_a_def_id(),
    )
}
fn amm_vault_b_id() -> AccountId {
    compute_vault_pda(
        programs::amm_account_id(),
        amm_pool_id(),
        amm_token_b_def_id(),
    )
}
fn amm_lp_def_id() -> AccountId {
    compute_liquidity_token_pda(programs::amm_account_id(), amm_pool_id())
}

fn amm_pool_account() -> Fixture {
    Fixture::new(
        amm_pool_id(),
        true,
        programs::amm_account_id(),
        ShardData::from(&PoolDefinition {
            token_program_id: programs::token_account_id(),
            definition_token_a_id: amm_token_a_def_id(),
            definition_token_b_id: amm_token_b_def_id(),
            vault_a_id: amm_vault_a_id(),
            vault_b_id: amm_vault_b_id(),
            liquidity_pool_id: amm_lp_def_id(),
            liquidity_pool_supply: amm_lp_supply(),
            reserve_a: AMM_RESERVE_A,
            reserve_b: AMM_RESERVE_B,
            fees: 0,
            active: true,
        }),
    )
}

fn amm_swap_accounts() -> Vec<Fixture> {
    vec![
        amm_pool_account(),
        token_holding(amm_token_a_def_id(), amm_vault_a_id(), AMM_RESERVE_A, true),
        token_holding(amm_token_b_def_id(), amm_vault_b_id(), AMM_RESERVE_B, true),
        token_holding(amm_token_a_def_id(), AccountId::new([45; 32]), 1_000, true),
        token_holding(amm_token_b_def_id(), AccountId::new([46; 32]), 500, false),
    ]
}

fn amm_add_liquidity_accounts() -> Vec<Fixture> {
    vec![
        amm_pool_account(),
        token_holding(amm_token_a_def_id(), amm_vault_a_id(), AMM_RESERVE_A, true),
        token_holding(amm_token_b_def_id(), amm_vault_b_id(), AMM_RESERVE_B, true),
        token_definition(amm_lp_def_id(), amm_lp_supply(), true),
        token_holding(amm_token_a_def_id(), AccountId::new([45; 32]), 1_000, true),
        token_holding(amm_token_b_def_id(), AccountId::new([46; 32]), 500, true),
        token_holding(amm_lp_def_id(), AccountId::new([47; 32]), 0, true),
    ]
}

fn ata_create_accounts() -> Vec<Fixture> {
    let owner_id = AccountId::new([91; 32]);
    let definition_id = token_definition_id();
    let seed = compute_ata_seed(owner_id, definition_id, programs::token_account_id());
    let ata_id = get_associated_token_account_id(&programs::ata_account_id(), &seed);
    vec![
        Fixture::balance(owner_id, true, 0),
        token_definition(definition_id, 100_000, false),
        Fixture::new(
            ata_id,
            false,
            programs::token_account_id(),
            ShardData::empty(),
        ),
    ]
}

fn mul_div(factor: u128, multiplier: u128, divisor: u128) -> u128 {
    factor * multiplier / divisor
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let prove = cli.prove;
    let exec_iters = cli.exec_iters.max(1);
    if prove {
        eprintln!("cycle_bench: prove mode ON, this will be slow (~minutes per program)");
    }

    // Priced off the pool fixture exactly as `wallet::program_facades::amm` prices a real
    // swap off the pool it observed, because the pool's `apply` recomputes both and refuses
    // anything else.
    let swap_amount_in: u128 = 200;
    let swap_amount_out = mul_div(
        AMM_RESERVE_B,
        swap_amount_in,
        AMM_RESERVE_A + swap_amount_in,
    );

    let max_amount_to_add_token_a: u128 = 400;
    let max_amount_to_add_token_b: u128 = 200;
    let amount_to_add_token_a = mul_div(AMM_RESERVE_A, max_amount_to_add_token_b, AMM_RESERVE_B)
        .min(max_amount_to_add_token_a);
    let amount_to_add_token_b = mul_div(AMM_RESERVE_B, max_amount_to_add_token_a, AMM_RESERVE_A)
        .min(max_amount_to_add_token_b);
    let amount_liquidity = mul_div(amm_lp_supply(), amount_to_add_token_a, AMM_RESERVE_A).min(
        mul_div(amm_lp_supply(), amount_to_add_token_b, AMM_RESERVE_B),
    );

    let cases = [
        Case::new(
            "token",
            "Transfer",
            programs::token(),
            token_transfer_accounts(),
            &token_core::Instruction::Transfer {
                amount_to_transfer: 5_000,
                descriptor: fungible(token_definition_id()),
            },
        )?,
        Case::new(
            "token",
            "Mint",
            programs::token(),
            token_definition_and_holding_accounts(),
            &token_core::Instruction::Mint {
                amount_to_mint: 5_000,
            },
        )?,
        Case::new(
            "token",
            "Burn",
            programs::token(),
            token_definition_and_holding_accounts(),
            &token_core::Instruction::Burn {
                amount_to_burn: 500,
                kind: TokenKind::Fungible,
            },
        )?,
        Case::new(
            "clock",
            "Tick (block_id+1, no multiples)",
            programs::clock(),
            clock_accounts_tick_at(0),
            &clock_core::Instruction {
                timestamp: Timestamp::from(1_700_000_000_u64),
                block_id: 1,
            },
        )?,
        Case::new(
            "amm",
            "Swap",
            programs::amm(),
            amm_swap_accounts(),
            &amm_core::Instruction::Swap {
                token_program_id: programs::token_account_id(),
                definition_id_in: amm_token_a_def_id(),
                definition_id_out: amm_token_b_def_id(),
                amount_in: swap_amount_in,
                amount_out: swap_amount_out,
            },
        )?,
        Case::new(
            "amm",
            "AddLiquidity",
            programs::amm(),
            amm_add_liquidity_accounts(),
            &amm_core::Instruction::AddLiquidity {
                max_amount_to_add_token_a,
                max_amount_to_add_token_b,
                token_program_id: programs::token_account_id(),
                definition_token_a_id: amm_token_a_def_id(),
                definition_token_b_id: amm_token_b_def_id(),
                amount_to_add_token_a,
                amount_to_add_token_b,
                amount_liquidity,
            },
        )?,
        Case::new(
            "ata",
            "Create",
            programs::ata(),
            ata_create_accounts(),
            &associated_token_account_core::Instruction::Create {
                token_program_id: programs::token_account_id(),
                kind: TokenKind::Fungible,
                contents: AtaContents::Empty,
            },
        )?,
    ];

    let mut results: Vec<BenchResult> = cases
        .into_iter()
        .map(|c| c.run(prove, exec_iters))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();

    let calibration = Calibration::fit(&results);
    if let Some(cal) = calibration {
        for r in &mut results {
            r.calibrated_ms = Some(cal.calibrated_ms(r.user_cycles));
            r.net_compute_ms = Some(r.exec_stats.best_ms - cal.intercept_ms);
        }
    }

    print_table(&results, prove);
    if let Some(cal) = calibration {
        print_calibration(&cal);
    }

    #[cfg(feature = "ppe")]
    let ppe_results = if cli.ppe { ppe::run_all() } else { Vec::new() };
    #[cfg(not(feature = "ppe"))]
    let ppe_results: Vec<ppe::PpeBenchResult> = {
        if cli.ppe {
            eprintln!("cycle_bench: --ppe requires --features ppe at build time. Ignoring.");
        }
        Vec::new()
    };
    if !ppe_results.is_empty() {
        ppe::print_table(&ppe_results);
    }

    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()?;
    let out_path = workspace_root.join("target").join("cycle_bench.json");
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let combined = serde_json::json!({
        "standalone": results,
        "calibration": calibration,
        "ppe": ppe_results,
    });
    std::fs::write(&out_path, serde_json::to_string_pretty(&combined)?)?;
    println!("\nJSON written to {}", out_path.display());

    Ok(())
}

fn print_calibration(cal: &Calibration) {
    println!("\npublic-execution ms calibration (pinned hardware):");
    println!(
        "  fit: best_ms = {:.4} + {:.3e} * user_cycles  (n={}, R²={:.4})",
        cal.intercept_ms, cal.slope_ms_per_cycle, cal.n, cal.r2,
    );
    println!(
        "  throughput:    {:.0} cycles/ms",
        cal.throughput_cycles_per_ms,
    );
    println!(
        "  fixed overhead: {:.3} ms host-side per call (ELF parse + env build, off-cycle)",
        cal.intercept_ms,
    );
    println!("  calib_ms = user_cycles / throughput  (compute only, overhead excluded)");
    println!("  net_ms   = best exec_ms - fixed overhead  (measured compute, overhead stripped)");
}

fn print_table(results: &[BenchResult], prove: bool) {
    let pw = results
        .iter()
        .map(|r| r.program_name.len())
        .max()
        .unwrap_or(0)
        .max("program".len());
    let iw = results
        .iter()
        .map(|r| r.instruction.len())
        .max()
        .unwrap_or(0)
        .max("instruction".len());
    let fw = "phase".len();
    let cw = 12_usize;
    let sw = 8_usize;
    let exec_w = results
        .iter()
        .map(|r| r.exec_stats.to_string().len())
        .max()
        .unwrap_or(0)
        .max("exec_ms (best / mean ± stdev)".len());

    let dw = 10_usize;
    println!(
        "{:<pw$}  {:<iw$}  {:<fw$}  {:>cw$}  {:>sw$}  {:<exec_w$}  {:>dw$}  {:>dw$}",
        "program",
        "instruction",
        "phase",
        "user_cycles",
        "segments",
        "exec_ms (best / mean ± stdev)",
        "calib_ms",
        "net_ms",
    );
    println!(
        "{}",
        "-".repeat(pw + iw + fw + cw + sw + exec_w + 2 * dw + 14)
    );
    for r in results {
        let calib = r
            .calibrated_ms
            .map_or_else(|| "-".to_owned(), |v| format!("{v:.2}"));
        let net = r
            .net_compute_ms
            .map_or_else(|| "-".to_owned(), |v| format!("{v:.2}"));
        println!(
            "{:<pw$}  {:<iw$}  {:<fw$}  {:>cw$}  {:>sw$}  {:<exec_w$}  {:>dw$}  {:>dw$}",
            r.program_name,
            r.instruction,
            r.phase.label(),
            r.user_cycles,
            r.segments,
            r.exec_stats,
            calib,
            net,
        );
    }

    if prove {
        println!("\nprove():");
        let pcw = 14_usize;
        let pwallw = 24_usize;
        let psw = 10_usize;
        println!(
            "{:<pw$}  {:<iw$}  {:<fw$}  {:>pcw$}  {:>pwallw$}  {:>psw$}",
            "program", "instruction", "phase", "prove_total_c", "prove_ms (s)", "prove_segs",
        );
        println!("{}", "-".repeat(pw + iw + fw + pcw + pwallw + psw + 10));
        for r in results {
            let total = r
                .prove_total_cycles
                .map_or_else(|| "-".to_owned(), |c| c.to_string());
            let pms = r.prove_stats.map_or_else(
                || "-".to_owned(),
                |s| format!("{:.1} ({:.1}s)", s.best_ms, s.best_ms / 1_000.0),
            );
            let psegs = r
                .prove_segments
                .map_or_else(|| "-".to_owned(), |s| s.to_string());
            println!(
                "{:<pw$}  {:<iw$}  {:<fw$}  {:>pcw$}  {:>pwallw$}  {:>psw$}",
                r.program_name,
                r.instruction,
                r.phase.label(),
                total,
                pms,
                psegs,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use cycle_bench::stats::Stats;

    use super::{BenchResult, Calibration, Phase};

    /// Minimal `BenchResult` carrying only the fields the calibration fit reads:
    /// `user_cycles` (x) and `exec_stats.best_ms` (y).
    fn point(user_cycles: u64, best_ms: f64) -> BenchResult {
        BenchResult {
            program_name: "test",
            instruction: "test".to_owned(),
            phase: Phase::Plan,
            user_cycles,
            segments: 1,
            exec_stats: Stats::from_samples(&[best_ms]),
            net_compute_ms: None,
            calibrated_ms: None,
            prove_stats: None,
            prove_total_cycles: None,
            prove_user_cycles: None,
            prove_paging_cycles: None,
            prove_segments: None,
        }
    }

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    #[test]
    fn fit_recovers_a_known_line() {
        // best_ms = 10 + 0.001 * user_cycles  ->  slope 1e-3, intercept 10, throughput 1000.
        let results = [point(1000, 11.0), point(2000, 12.0), point(3000, 13.0)];
        let cal = Calibration::fit(&results).expect("fit over three points");

        assert!(
            close(cal.slope_ms_per_cycle, 0.001),
            "slope {}",
            cal.slope_ms_per_cycle
        );
        assert!(
            close(cal.intercept_ms, 10.0),
            "intercept {}",
            cal.intercept_ms
        );
        assert!(
            close(cal.throughput_cycles_per_ms, 1000.0),
            "throughput {}",
            cal.throughput_cycles_per_ms,
        );
        assert!(close(cal.r2, 1.0), "r2 {}", cal.r2);
        assert_eq!(cal.n, 3);
        // calibrated_ms is the overhead-excluded compute prediction: slope * cycles.
        assert!(
            close(cal.calibrated_ms(2000), 2.0),
            "calib {}",
            cal.calibrated_ms(2000)
        );
    }

    #[test]
    fn fit_needs_at_least_two_points() {
        assert!(Calibration::fit(&[]).is_none());
        assert!(Calibration::fit(&[point(1000, 11.0)]).is_none());
    }

    #[test]
    fn fit_with_identical_cycle_counts_returns_none() {
        // Zero spread in x leaves the slope undetermined; the fit must decline rather than divide
        // by zero.
        let results = [point(1000, 11.0), point(1000, 12.0)];
        assert!(Calibration::fit(&results).is_none());
    }
}
