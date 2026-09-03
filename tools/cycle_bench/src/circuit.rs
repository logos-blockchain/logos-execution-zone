//! Privacy-preserving circuit executor cases for `cycle_bench`.
//!
//! Each case executes one program through the executor, then executes the circuit over that
//! program's journal with an unresolved assumption standing in for the program receipt.
//! Reports circuit user cycles; no proving.

#![expect(
    clippy::non_ascii_literal,
    reason = "The stats column header matches the sibling tables"
)]

use std::time::Instant;

use lee::{PRIVACY_PRESERVING_CIRCUIT_ELF, program::Program};
use lee_core::{
    AuthorizationSecretKey, DUMMY_COMMITMENT_HASH, InputAccountIdentity, NullifierPublicKey,
    NullifierSecretKey, NullifierWitness, PrivacyPreservingCircuitInput, PrivateWitness,
    WitnessKind,
    account::{Account, AccountId, AccountWithMetadata},
    encryption::ViewingPublicKey,
    from_frame,
    program::ProgramOutput,
    to_frame,
};
use risc0_zkvm::{
    Assumption, Digest, ExecutorEnv, ReceiptClaim, default_executor, sha::Digestible as _,
};
use serde::Serialize;

use crate::stats::Stats;

#[derive(Debug, Serialize)]
pub struct CircuitBenchResult {
    pub label: &'static str,
    pub program_cycles: u64,
    pub circuit_cycles: u64,
    pub circuit_segments: usize,
    pub exec_stats: Stats,
}

pub fn run_all(exec_iters: usize) -> anyhow::Result<Vec<CircuitBenchResult>> {
    Ok(vec![
        run_public_account(exec_iters)?,
        run_private_account_init(exec_iters)?,
    ])
}

pub fn print_table(results: &[CircuitBenchResult]) {
    println!("\nprivacy circuit (executor):");

    let lw = results
        .iter()
        .map(|r| r.label.len())
        .max()
        .unwrap_or(0)
        .max("label".len());
    let cw = 14_usize;
    let sw = 8_usize;
    let exec_w = results
        .iter()
        .map(|r| r.exec_stats.to_string().len())
        .max()
        .unwrap_or(0)
        .max("exec_ms (best / mean ± stdev)".len());

    println!(
        "{:<lw$}  {:>cw$}  {:>cw$}  {:>sw$}  {:<exec_w$}",
        "label", "program_cycles", "circuit_cycles", "segments", "exec_ms (best / mean ± stdev)",
    );
    println!("{}", "-".repeat(lw + 2 * cw + sw + exec_w + 8));
    for r in results {
        println!(
            "{:<lw$}  {:>cw$}  {:>cw$}  {:>sw$}  {:<exec_w$}",
            r.label, r.program_cycles, r.circuit_cycles, r.circuit_segments, r.exec_stats,
        );
    }
}

fn run_public_account(exec_iters: usize) -> anyhow::Result<CircuitBenchResult> {
    let pre_states = vec![AccountWithMetadata::new(
        Account::default(),
        true,
        AccountId::new([1; 32]),
    )];

    run_case(
        "noop / 1 public account",
        &test_programs::noop(),
        &pre_states,
        vec![InputAccountIdentity::Public],
        exec_iters,
    )
}

fn run_private_account_init(exec_iters: usize) -> anyhow::Result<CircuitBenchResult> {
    let ask = AuthorizationSecretKey([13; 32]);
    let nsk = NullifierSecretKey::from(&ask);
    let npk = NullifierPublicKey::from(&nsk);
    let vpk = ViewingPublicKey::from_seed(&[31; 32], &[32; 32]);
    let identifier = 0;
    let account_id = AccountId::for_regular_private_account(&npk, &vpk, identifier);

    let pre_states = vec![AccountWithMetadata::new(
        Account::default(),
        true,
        account_id,
    )];
    let account_identities = vec![InputAccountIdentity::Private(PrivateWitness {
        vpk,
        random_seed: [0; 32],
        identifier,
        kind: WitnessKind::Regular { ask: Some(ask) },
        nullifier: NullifierWitness::Init {
            npk,
            commitment_root: DUMMY_COMMITMENT_HASH,
        },
    })];

    run_case(
        "noop / 1 private account init",
        &test_programs::noop(),
        &pre_states,
        account_identities,
        exec_iters,
    )
}

fn run_case(
    label: &'static str,
    program: &Program,
    pre_states: &[AccountWithMetadata],
    account_identities: Vec<InputAccountIdentity>,
    exec_iters: usize,
) -> anyhow::Result<CircuitBenchResult> {
    let instruction = borsh::to_vec(&())?;

    let mut program_env_builder = ExecutorEnv::builder();
    program.write_inputs(None, pre_states, &instruction, &mut program_env_builder)?;
    let program_env = program_env_builder.build()?;
    let program_info = default_executor().execute(program_env, program.elf())?;

    let program_cycles = program_info.cycles();
    let journal_bytes = program_info.journal.bytes;
    let program_output: ProgramOutput = borsh::from_slice(
        from_frame(&journal_bytes)
            .ok_or_else(|| anyhow::anyhow!("malformed program journal frame"))?,
    )?;

    let assumption = Assumption {
        claim: ReceiptClaim::ok(program.id(), journal_bytes).digest(),
        control_root: Digest::ZERO,
    };

    let payload = to_frame(&borsh::to_vec(&PrivacyPreservingCircuitInput {
        program_outputs: vec![program_output],
        account_identities,
        program_id: program.id(),
        dummy_inputs: vec![],
    })?);

    let mut samples: Vec<f64> = Vec::with_capacity(exec_iters);
    let mut last_info = None;
    let total = exec_iters.saturating_add(1).max(2);
    for iter in 0..total {
        let mut env_builder = ExecutorEnv::builder();
        env_builder.add_assumption(assumption.clone());
        env_builder.write_slice(&payload);
        let env = env_builder.build()?;

        let started = Instant::now();
        let info = default_executor().execute(env, PRIVACY_PRESERVING_CIRCUIT_ELF)?;
        let elapsed_ms = started.elapsed().as_secs_f64() * 1_000.0;

        if iter > 0 {
            samples.push(elapsed_ms);
        }
        last_info = Some(info);
    }
    let info = last_info.expect("at least one iteration");

    Ok(CircuitBenchResult {
        label,
        program_cycles,
        circuit_cycles: info.cycles(),
        circuit_segments: info.segments.len(),
        exec_stats: Stats::from_samples(&samples),
    })
}
