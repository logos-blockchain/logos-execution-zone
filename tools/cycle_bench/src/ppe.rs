//! Privacy-preserving execution (PPE) cases for `cycle_bench`.
//!
//! Composition cost is the delta between standalone `prover.prove(env, elf)` for
//! a single program (measured in the main bench) and a full `execute_and_prove`
//! that wraps the same program in the privacy circuit. Chained-call depth sweep
//! uses the `chain_caller` test program (loaded from artifacts/) with N=1, 3, 5, 9.
//!
//! `run_verify` produces `G_verify` for the fee model: it generates one PPE
//! receipt (`auth_transfer` Transfer in PPE) and times `Receipt::verify` over
//! `iters` iterations. The proof bytes captured here are also the on-wire
//! "outer proof" payload (`S_agg` in the fee model).

#![allow(
    dead_code,
    reason = "Stubs are used when the `ppe` feature is disabled."
)]

use anyhow::Result;
use serde::Serialize;

use crate::stats::Stats;

#[cfg(feature = "ppe")]
mod ppe_impl;

#[derive(Debug, Serialize, Clone)]
pub struct PpeBenchResult {
    pub label: String,
    pub chain_depth: usize,
    pub prove_wall_ms: Option<f64>,
    /// borsh-serialized `InnerReceipt` length (`S_agg` in the fee model).
    pub proof_bytes: Option<usize>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct VerifyBenchResult {
    pub label: String,
    pub stats: Stats,
    pub proof_bytes: usize,
    pub journal_bytes: usize,
}

#[cfg(not(feature = "ppe"))]
pub fn run_all() -> Vec<PpeBenchResult> {
    Vec::new()
}

#[cfg(feature = "ppe")]
pub fn run_all() -> Vec<PpeBenchResult> {
    let mut results = Vec::new();

    eprintln!("PPE: running composition cost (auth_transfer Transfer in PPE)");
    results.push(ppe_impl::run_auth_transfer_in_ppe());

    for depth in [1_u32, 3, 5, 9] {
        eprintln!("PPE: running chain_caller depth={depth}");
        results.push(ppe_impl::run_chain_caller(depth));
    }

    results
}

#[cfg(not(feature = "ppe"))]
pub fn run_verify(_iters: usize) -> Result<VerifyBenchResult> {
    anyhow::bail!("--verify requires --features ppe at build time")
}

#[cfg(feature = "ppe")]
pub fn run_verify(iters: usize) -> Result<VerifyBenchResult> {
    ppe_impl::run_verify(iters)
}

pub fn print_table(results: &[PpeBenchResult]) {
    let lw = results
        .iter()
        .map(|r| r.label.len())
        .max()
        .unwrap_or(0)
        .max("label".len());

    println!(
        "\n{:<lw$}  {:>5}  {:>20}  {:>12}  {}",
        "label",
        "depth",
        "prove_ms (s)",
        "proof_bytes",
        "error",
        lw = lw,
    );
    println!("{}", "-".repeat(lw + 60));
    for r in results {
        let p = r.prove_wall_ms.map_or_else(
            || "-".to_owned(),
            |v| format!("{v:.1} ({:.1}s)", v / 1_000.0),
        );
        let b = r
            .proof_bytes
            .map_or_else(|| "-".to_owned(), |n| n.to_string());
        let e = r.error.as_deref().unwrap_or("");
        println!(
            "{:<lw$}  {:>5}  {:>20}  {:>12}  {}",
            r.label,
            r.chain_depth,
            p,
            b,
            e,
            lw = lw,
        );
    }
}

pub fn print_verify(r: &VerifyBenchResult) {
    println!("\nVerify (G_verify):");
    println!("  case          : {}", r.label);
    println!(
        "  proof_bytes   : {} (borsh InnerReceipt, S_agg)",
        r.proof_bytes
    );
    println!("  journal_bytes : {}", r.journal_bytes);
    println!("  verify_ms     : {}", r.stats);
}
