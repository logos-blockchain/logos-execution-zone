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
    clippy::print_literal,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::ref_patterns,
    reason = "Bench tool: matches test-style fixture code"
)]

use std::{path::PathBuf, time::Instant};

use amm_core::{PoolDefinition, compute_liquidity_token_pda, compute_pool_pda, compute_vault_pda};
use anyhow::Result;
use ata_core::{compute_ata_seed, get_associated_token_account_id};
use clap::Parser;
use clock_core::{
    CLOCK_01_PROGRAM_ACCOUNT_ID, CLOCK_10_PROGRAM_ACCOUNT_ID, CLOCK_50_PROGRAM_ACCOUNT_ID,
    ClockAccountData,
};
use nssa::program_methods::{
    AMM_ELF, AMM_ID, ASSOCIATED_TOKEN_ACCOUNT_ELF, ASSOCIATED_TOKEN_ACCOUNT_ID,
    AUTHENTICATED_TRANSFER_ELF, AUTHENTICATED_TRANSFER_ID, CLOCK_ELF, CLOCK_ID, TOKEN_ELF,
    TOKEN_ID,
};
use nssa_core::{
    Timestamp,
    account::{Account, AccountId, AccountWithMetadata, Data},
    program::{InstructionData, ProgramId},
};
use risc0_zkvm::{ExecutorEnv, default_executor, default_prover};
use serde::Serialize;
use stats::Stats;
use token_core::{TokenDefinition, TokenHolding};

mod ppe;
mod stats;

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

    /// After running --ppe-style proving once for auth_transfer-in-PPE, time
    /// `receipt.verify(PRIVACY_PRESERVING_CIRCUIT_ID)` over many iterations.
    /// Produces `G_verify` for the fee model. Requires --features ppe.
    #[arg(long)]
    verify: bool,

    /// Iterations for --verify. Default matches the fee-model handoff target.
    #[arg(long, default_value_t = 1000)]
    verify_iters: usize,

    /// Iterations for executor wall-time sampling per case. First iter is
    /// discarded as warmup, remaining N feed the stats.
    #[arg(long, default_value_t = 5)]
    exec_iters: usize,
}

#[derive(Debug, Serialize)]
struct BenchResult {
    program: &'static str,
    instruction: &'static str,
    user_cycles: u64,
    segments: usize,
    exec_stats: Stats,
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

struct Case {
    program: &'static str,
    instruction_label: &'static str,
    elf: &'static [u8],
    self_program_id: ProgramId,
    pre_states: Vec<AccountWithMetadata>,
    instruction_words: InstructionData,
}

impl Case {
    fn new<I: Serialize>(
        program: &'static str,
        instruction_label: &'static str,
        elf: &'static [u8],
        self_program_id: ProgramId,
        pre_states: Vec<AccountWithMetadata>,
        instruction: &I,
    ) -> Result<Self> {
        Ok(Self {
            program,
            instruction_label,
            elf,
            self_program_id,
            pre_states,
            instruction_words: risc0_zkvm::serde::to_vec(instruction)?,
        })
    }

    fn run(self, prove: bool, exec_iters: usize) -> Result<BenchResult> {
        let Self {
            program,
            instruction_label,
            elf,
            self_program_id,
            pre_states,
            instruction_words,
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
            env_builder
                .write(&self_program_id)?
                .write(&caller_program_id)?
                .write(&pre_states)?
                .write(&instruction_words)?;
            let env = env_builder.build()?;

            let started = Instant::now();
            let info = default_executor().execute(env, elf)?;
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
            env_builder
                .write(&self_program_id)?
                .write(&caller_program_id)?
                .write(&pre_states)?
                .write(&instruction_words)?;
            let env = env_builder.build()?;

            let started = Instant::now();
            let prove_info = default_prover()
                .prove(env, elf)
                .map_err(|e| anyhow::anyhow!("prove failed: {e}"))?;
            let prove_ms = started.elapsed().as_secs_f64() * 1_000.0;
            prove_stats = Some(Stats::from_samples(&[prove_ms]));
            prove_total_cycles = Some(prove_info.stats.total_cycles);
            prove_user_cycles = Some(prove_info.stats.user_cycles);
            prove_paging_cycles = Some(prove_info.stats.paging_cycles);
            prove_segments = Some(prove_info.stats.segments);
            eprintln!(
                "  prove({program}/{instruction_label}): {prove_ms:.1} ms ({:.1}s), total_cycles={}, segments={}",
                prove_ms / 1_000.0,
                prove_info.stats.total_cycles,
                prove_info.stats.segments,
            );
        }

        Ok(BenchResult {
            program,
            instruction: instruction_label,
            user_cycles: info.cycles(),
            segments: info.segments.len(),
            exec_stats,
            prove_stats,
            prove_total_cycles,
            prove_user_cycles,
            prove_paging_cycles,
            prove_segments,
        })
    }
}

fn authenticated_transfer_init() -> Vec<AccountWithMetadata> {
    vec![AccountWithMetadata {
        account: Account::default(),
        is_authorized: true,
        account_id: AccountId::new([1; 32]),
    }]
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
            program_owner: TOKEN_ID,
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
            program_owner: TOKEN_ID,
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
            program_owner: CLOCK_ID,
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
    compute_pool_pda(AMM_ID, amm_token_a_def_id(), amm_token_b_def_id())
}
fn amm_vault_a_id() -> AccountId {
    compute_vault_pda(AMM_ID, amm_pool_id(), amm_token_a_def_id())
}
fn amm_vault_b_id() -> AccountId {
    compute_vault_pda(AMM_ID, amm_pool_id(), amm_token_b_def_id())
}
fn amm_lp_def_id() -> AccountId {
    compute_liquidity_token_pda(AMM_ID, amm_pool_id())
}

/// Pool seeded with reserves `1_000` / `500`, lp supply `sqrt(1000*500) = 707`.
fn amm_pool_account() -> AccountWithMetadata {
    let reserve_a: u128 = 1_000;
    let reserve_b: u128 = 500;
    let lp_supply = (reserve_a * reserve_b).isqrt();
    AccountWithMetadata {
        account: Account {
            program_owner: AMM_ID,
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
    let ata_id = get_associated_token_account_id(&ASSOCIATED_TOKEN_ACCOUNT_ID, &seed);
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
            AUTHENTICATED_TRANSFER_ELF,
            AUTHENTICATED_TRANSFER_ID,
            authenticated_transfer_transfer(),
            &5_000_u128,
        )?,
        Case::new(
            "authenticated_transfer",
            "Initialize",
            AUTHENTICATED_TRANSFER_ELF,
            AUTHENTICATED_TRANSFER_ID,
            authenticated_transfer_init(),
            &0_u128,
        )?,
        Case::new(
            "token",
            "Transfer",
            TOKEN_ELF,
            TOKEN_ID,
            token_transfer_pre_states(),
            &token_core::Instruction::Transfer {
                amount_to_transfer: 5_000,
            },
        )?,
        Case::new(
            "token",
            "Mint",
            TOKEN_ELF,
            TOKEN_ID,
            token_mint_pre_states(),
            &token_core::Instruction::Mint {
                amount_to_mint: 5_000,
            },
        )?,
        Case::new(
            "token",
            "Burn",
            TOKEN_ELF,
            TOKEN_ID,
            token_burn_pre_states(),
            &token_core::Instruction::Burn {
                amount_to_burn: 500,
            },
        )?,
        Case::new(
            "clock",
            "Tick (block_id+1, no multiples)",
            CLOCK_ELF,
            CLOCK_ID,
            clock_pre_states_tick_at(0),
            &Timestamp::from(1_700_000_000_u64),
        )?,
        Case::new(
            "amm",
            "SwapExactInput",
            AMM_ELF,
            AMM_ID,
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
            AMM_ELF,
            AMM_ID,
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
            ASSOCIATED_TOKEN_ACCOUNT_ELF,
            ASSOCIATED_TOKEN_ACCOUNT_ID,
            ata_create_pre_states(),
            &ata_core::Instruction::Create {
                ata_program_id: ASSOCIATED_TOKEN_ACCOUNT_ID,
            },
        )?,
    ];

    let results: Vec<BenchResult> = cases
        .into_iter()
        .map(|c| c.run(prove, exec_iters))
        .collect::<Result<Vec<_>>>()?;

    print_table(&results, prove);

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

    #[cfg(feature = "ppe")]
    let verify_result = if cli.verify {
        Some(ppe::run_verify(cli.verify_iters)?)
    } else {
        None
    };
    #[cfg(not(feature = "ppe"))]
    let verify_result: Option<ppe::VerifyBenchResult> = {
        if cli.verify {
            eprintln!("cycle_bench: --verify requires --features ppe at build time. Ignoring.");
        }
        None
    };
    if let Some(ref vr) = verify_result {
        ppe::print_verify(vr);
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
        "ppe": ppe_results,
        "verify": verify_result,
    });
    std::fs::write(&out_path, serde_json::to_string_pretty(&combined)?)?;
    println!("\nJSON written to {}", out_path.display());

    Ok(())
}

fn print_table(results: &[BenchResult], prove: bool) {
    let pw = results
        .iter()
        .map(|r| r.program.len())
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

    println!(
        "{:<pw$}  {:<iw$}  {:>cw$}  {:>sw$}  {:<exec_w$}",
        "program", "instruction", "user_cycles", "segments", "exec_ms (best / mean ± stdev)",
    );
    println!("{}", "-".repeat(pw + iw + cw + sw + exec_w + 8));
    for r in results {
        println!(
            "{:<pw$}  {:<iw$}  {:>cw$}  {:>sw$}  {:<exec_w$}",
            r.program, r.instruction, r.user_cycles, r.segments, r.exec_stats,
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
                r.program, r.instruction, total, pms, psegs,
            );
        }
    }
}
