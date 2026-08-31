//! Measures Risc0 user cycles per built-in program instruction.
//!
//! Runs each guest ELF through the Risc0 executor (no proving) with realistic inputs
//! drawn from the existing per-program unit tests, then prints a table and writes a
//! JSON dump for regression comparison.
//!
//! Run with `cargo run --release -p cycle_bench`. `RISC0_DEV_MODE` has no effect on
//! executor cycle counts.

#![expect(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_precision_loss,
    clippy::float_arithmetic,
    clippy::missing_const_for_fn,
    clippy::non_ascii_literal,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::suboptimal_flops,
    reason = "Bench tool: matches test-style fixture code"
)]

use std::{path::PathBuf, time::Instant};

use amm_core::{PoolDefinition, compute_liquidity_token_pda, compute_pool_pda, compute_vault_pda};
use anyhow::Result;
use associated_token_account_core::{compute_ata_seed, get_associated_token_account_id};
use clap::Parser;
use clock_core::{
    CLOCK_01_PROGRAM_ACCOUNT_ID, CLOCK_10_PROGRAM_ACCOUNT_ID, CLOCK_50_PROGRAM_ACCOUNT_ID,
    ClockAccountData,
};
use cycle_bench::{ppe, stats::Stats};
use lee::program::Program;
use lee_core::{
    Timestamp,
    account::{Account, AccountId, AccountWithMetadata, Data},
    program::{InstructionData, ProgramId},
};
use risc0_zkvm::{ExecutorEnv, default_executor, default_prover};
use serde::Serialize;
use token_core::{TokenDefinition, TokenHolding};

#[derive(Parser, Debug)]
#[command(about = "Per-program executor and (optionally) prover cycle measurements")]
struct Cli {
    /// Also run prover.prove for each case and report wall time + cycles. Slow.
    #[arg(long)]
    prove: bool,

    /// Also run privacy-preserving execution circuit (PPE) composition cases:
    /// (a) single `auth_transfer` Transfer through `execute_and_prove`, (b) `chain_caller`
    /// with depth N=1,3,5,9. Requires --features ppe at build time. Very slow.
    #[arg(long)]
    ppe: bool,

    /// Iterations for executor wall-time sampling per case. First iter is
    /// discarded as warmup, remaining N feed the stats.
    #[arg(long, default_value_t = 5)]
    exec_iters: usize,
}

#[derive(Debug, Serialize)]
struct BenchResult {
    program_name: &'static str,
    instruction: &'static str,
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

struct Case {
    program_name: &'static str,
    instruction_label: &'static str,
    program: Program,
    pre_states: Vec<AccountWithMetadata>,
    instruction_data: InstructionData,
}

impl Case {
    fn new<I: borsh::BorshSerialize>(
        program_name: &'static str,
        instruction_label: &'static str,
        program: Program,
        pre_states: Vec<AccountWithMetadata>,
        instruction: &I,
    ) -> Result<Self> {
        Ok(Self {
            program_name,
            instruction_label,
            program,
            pre_states,
            instruction_data: borsh::to_vec(instruction)?,
        })
    }

    fn run(self, prove: bool, exec_iters: usize) -> Result<BenchResult> {
        let Self {
            program_name,
            instruction_label,
            program,
            pre_states,
            instruction_data,
        } = self;
        let caller_program_id: Option<ProgramId> = None;

        // One warmup pass discarded, then `exec_iters` samples. The executor has
        // large per-call setup overhead (ELF parsing, env init); reporting both
        // best-of-N and mean ± stdev shows whether jitter is significant.
        let mut samples: Vec<f64> = Vec::with_capacity(exec_iters);
        let mut last_info = None;
        let total = exec_iters.saturating_add(1).max(2);
        for iter in 0..total {
            let mut env_builder = ExecutorEnv::builder();
            program.write_inputs(
                caller_program_id,
                &pre_states,
                &instruction_data,
                &mut env_builder,
            )?;
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
            program.write_inputs(
                caller_program_id,
                &pre_states,
                &instruction_data,
                &mut env_builder,
            )?;
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
                "  prove({program_name}/{instruction_label}): {prove_ms:.1} ms ({:.1}s), total_cycles={}, segments={}",
                prove_ms / 1_000.0,
                prove_info.stats.total_cycles,
                prove_info.stats.segments,
            );
        }

        Ok(BenchResult {
            program_name,
            instruction: instruction_label,
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
        })
    }
}

fn authenticated_transfer_transfer() -> Vec<AccountWithMetadata> {
    let sender = AccountWithMetadata {
        account: Account {
            balance: 1_000_000,
            ..Account::default()
        },
        is_authorized: true,
        account_id: AccountId::new([1; 32]),
    };
    let recipient = AccountWithMetadata {
        account: Account::default(),
        is_authorized: false,
        account_id: AccountId::new([2; 32]),
    };
    vec![sender, recipient]
}

fn token_holding(
    definition_id: AccountId,
    account_id: AccountId,
    balance: u128,
    is_authorized: bool,
) -> AccountWithMetadata {
    AccountWithMetadata {
        account: Account {
            program_owner: programs::token().id().into(),
            balance: 0,
            data: Data::from(&TokenHolding::Fungible {
                definition_id,
                balance,
            }),
            nonce: 0_u128.into(),
        },
        is_authorized,
        account_id,
    }
}

fn token_definition(
    account_id: AccountId,
    total_supply: u128,
    is_authorized: bool,
) -> AccountWithMetadata {
    AccountWithMetadata {
        account: Account {
            program_owner: programs::token().id().into(),
            balance: 0,
            data: Data::from(&TokenDefinition::Fungible {
                name: String::from("test"),
                total_supply,
                metadata_id: None,
            }),
            nonce: 0_u128.into(),
        },
        is_authorized,
        account_id,
    }
}

fn token_transfer_pre_states() -> Vec<AccountWithMetadata> {
    let def = AccountId::new([15; 32]);
    let sender = token_holding(def, AccountId::new([17; 32]), 100_000, true);
    let recipient = token_holding(def, AccountId::new([42; 32]), 50_000, true);
    vec![sender, recipient]
}

fn token_mint_pre_states() -> Vec<AccountWithMetadata> {
    let def_id = AccountId::new([15; 32]);
    let def = token_definition(def_id, 100_000, true);
    let holding = token_holding(def_id, AccountId::new([17; 32]), 1_000, true);
    vec![def, holding]
}

fn token_burn_pre_states() -> Vec<AccountWithMetadata> {
    let def_id = AccountId::new([15; 32]);
    let def = token_definition(def_id, 100_000, true);
    let holding = token_holding(def_id, AccountId::new([17; 32]), 1_000, true);
    vec![def, holding]
}

fn clock_account(account_id: AccountId, block_id: u64) -> AccountWithMetadata {
    AccountWithMetadata {
        account: Account {
            program_owner: programs::clock().id().into(),
            balance: 0,
            data: ClockAccountData {
                block_id,
                timestamp: Timestamp::from(0_u64),
            }
            .to_bytes()
            .try_into()
            .expect("ClockAccountData should fit in account data"),
            nonce: 0_u128.into(),
        },
        is_authorized: false,
        account_id,
    }
}

fn clock_pre_states_tick_at(block_id: u64) -> Vec<AccountWithMetadata> {
    vec![
        clock_account(CLOCK_01_PROGRAM_ACCOUNT_ID, block_id),
        clock_account(CLOCK_10_PROGRAM_ACCOUNT_ID, block_id),
        clock_account(CLOCK_50_PROGRAM_ACCOUNT_ID, block_id),
    ]
}

fn amm_token_a_def_id() -> AccountId {
    AccountId::new([42; 32])
}
fn amm_token_b_def_id() -> AccountId {
    AccountId::new([43; 32])
}
fn amm_pool_id() -> AccountId {
    compute_pool_pda(
        programs::amm().id(),
        amm_token_a_def_id(),
        amm_token_b_def_id(),
    )
}
fn amm_vault_a_id() -> AccountId {
    compute_vault_pda(programs::amm().id(), amm_pool_id(), amm_token_a_def_id())
}
fn amm_vault_b_id() -> AccountId {
    compute_vault_pda(programs::amm().id(), amm_pool_id(), amm_token_b_def_id())
}
fn amm_lp_def_id() -> AccountId {
    compute_liquidity_token_pda(programs::amm().id(), amm_pool_id())
}

/// Pool seeded with reserves `1_000` / `500`, lp supply `sqrt(1000*500) = 707`.
fn amm_pool_account() -> AccountWithMetadata {
    let reserve_a: u128 = 1_000;
    let reserve_b: u128 = 500;
    let lp_supply = (reserve_a * reserve_b).isqrt();
    AccountWithMetadata {
        account: Account {
            program_owner: programs::amm().id().into(),
            balance: 0,
            data: Data::from(&PoolDefinition {
                definition_token_a_id: amm_token_a_def_id(),
                definition_token_b_id: amm_token_b_def_id(),
                vault_a_id: amm_vault_a_id(),
                vault_b_id: amm_vault_b_id(),
                liquidity_pool_id: amm_lp_def_id(),
                liquidity_pool_supply: lp_supply,
                reserve_a,
                reserve_b,
                fees: 0,
                active: true,
            }),
            nonce: 0_u128.into(),
        },
        is_authorized: true,
        account_id: amm_pool_id(),
    }
}

fn amm_swap_pre_states() -> Vec<AccountWithMetadata> {
    let pool = amm_pool_account();
    let vault_a = token_holding(amm_token_a_def_id(), amm_vault_a_id(), 1_000, true);
    let vault_b = token_holding(amm_token_b_def_id(), amm_vault_b_id(), 500, true);
    let user_a = token_holding(amm_token_a_def_id(), AccountId::new([45; 32]), 1_000, true);
    let user_b = token_holding(amm_token_b_def_id(), AccountId::new([46; 32]), 500, false);
    vec![pool, vault_a, vault_b, user_a, user_b]
}

fn amm_add_liquidity_pre_states() -> Vec<AccountWithMetadata> {
    let pool = amm_pool_account();
    let vault_a = token_holding(amm_token_a_def_id(), amm_vault_a_id(), 1_000, true);
    let vault_b = token_holding(amm_token_b_def_id(), amm_vault_b_id(), 500, true);
    let lp_supply = (1_000_u128 * 500_u128).isqrt();
    let lp_def = token_definition(amm_lp_def_id(), lp_supply, true);
    let user_a = token_holding(amm_token_a_def_id(), AccountId::new([45; 32]), 1_000, true);
    let user_b = token_holding(amm_token_b_def_id(), AccountId::new([46; 32]), 500, true);
    let user_lp = token_holding(amm_lp_def_id(), AccountId::new([47; 32]), 0, true);
    vec![pool, vault_a, vault_b, lp_def, user_a, user_b, user_lp]
}

fn ata_create_pre_states() -> Vec<AccountWithMetadata> {
    let owner_id = AccountId::new([91; 32]);
    let definition_id = AccountId::new([15; 32]);
    let owner = AccountWithMetadata {
        account: Account::default(),
        is_authorized: true,
        account_id: owner_id,
    };
    let token_def = token_definition(definition_id, 100_000, false);
    let seed = compute_ata_seed(owner_id, definition_id);
    let ata_id = get_associated_token_account_id(&programs::ata().id(), &seed);
    let ata_account = AccountWithMetadata {
        account: Account::default(),
        is_authorized: false,
        account_id: ata_id,
    };
    vec![owner, token_def, ata_account]
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let prove = cli.prove;
    let exec_iters = cli.exec_iters.max(1);
    if prove {
        eprintln!("cycle_bench: prove mode ON, this will be slow (~minutes per program)");
    }

    let cases = [
        Case::new(
            "authenticated_transfer",
            "Transfer",
            programs::authenticated_transfer(),
            authenticated_transfer_transfer(),
            &authenticated_transfer_core::Instruction::Transfer { amount: 5_000 },
        )?,
        Case::new(
            "token",
            "Transfer",
            programs::token(),
            token_transfer_pre_states(),
            &token_core::Instruction::Transfer {
                amount_to_transfer: 5_000,
            },
        )?,
        Case::new(
            "token",
            "Mint",
            programs::token(),
            token_mint_pre_states(),
            &token_core::Instruction::Mint {
                amount_to_mint: 5_000,
            },
        )?,
        Case::new(
            "token",
            "Burn",
            programs::token(),
            token_burn_pre_states(),
            &token_core::Instruction::Burn {
                amount_to_burn: 500,
            },
        )?,
        Case::new(
            "clock",
            "Tick (block_id+1, no multiples)",
            programs::clock(),
            clock_pre_states_tick_at(0),
            &Timestamp::from(1_700_000_000_u64),
        )?,
        Case::new(
            "amm",
            "SwapExactInput",
            programs::amm(),
            amm_swap_pre_states(),
            &amm_core::Instruction::SwapExactInput {
                swap_amount_in: 200,
                min_amount_out: 1,
                token_definition_id_in: amm_token_a_def_id(),
            },
        )?,
        Case::new(
            "amm",
            "AddLiquidity",
            programs::amm(),
            amm_add_liquidity_pre_states(),
            &amm_core::Instruction::AddLiquidity {
                min_amount_liquidity: 1,
                max_amount_to_add_token_a: 400,
                max_amount_to_add_token_b: 200,
            },
        )?,
        Case::new(
            "ata",
            "Create",
            programs::ata(),
            ata_create_pre_states(),
            &associated_token_account_core::Instruction::Create {
                ata_program_id: programs::ata().id(),
            },
        )?,
    ];

    let mut results: Vec<BenchResult> = cases
        .into_iter()
        .map(|c| c.run(prove, exec_iters))
        .collect::<Result<Vec<_>>>()?;

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
        "{:<pw$}  {:<iw$}  {:>cw$}  {:>sw$}  {:<exec_w$}  {:>dw$}  {:>dw$}",
        "program",
        "instruction",
        "user_cycles",
        "segments",
        "exec_ms (best / mean ± stdev)",
        "calib_ms",
        "net_ms",
    );
    println!("{}", "-".repeat(pw + iw + cw + sw + exec_w + 2 * dw + 12));
    for r in results {
        let calib = r
            .calibrated_ms
            .map_or_else(|| "-".to_owned(), |v| format!("{v:.2}"));
        let net = r
            .net_compute_ms
            .map_or_else(|| "-".to_owned(), |v| format!("{v:.2}"));
        println!(
            "{:<pw$}  {:<iw$}  {:>cw$}  {:>sw$}  {:<exec_w$}  {:>dw$}  {:>dw$}",
            r.program_name, r.instruction, r.user_cycles, r.segments, r.exec_stats, calib, net,
        );
    }

    if prove {
        println!("\nprove():");
        let pcw = 14_usize;
        let pwallw = 24_usize;
        let psw = 10_usize;
        println!(
            "{:<pw$}  {:<iw$}  {:>pcw$}  {:>pwallw$}  {:>psw$}",
            "program", "instruction", "prove_total_c", "prove_ms (s)", "prove_segs",
        );
        println!("{}", "-".repeat(pw + iw + pcw + pwallw + psw + 8));
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
                "{:<pw$}  {:<iw$}  {:>pcw$}  {:>pwallw$}  {:>psw$}",
                r.program_name, r.instruction, total, pms, psegs,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use cycle_bench::stats::Stats;

    use super::{BenchResult, Calibration};

    /// Minimal `BenchResult` carrying only the fields the calibration fit reads:
    /// `user_cycles` (x) and `exec_stats.best_ms` (y).
    fn point(user_cycles: u64, best_ms: f64) -> BenchResult {
        BenchResult {
            program_name: "test",
            instruction: "test",
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
