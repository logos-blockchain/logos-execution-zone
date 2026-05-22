//! Privacy-preserving execution (PPE) cases for `cycle_bench`.
//!
//! Composition cost is the delta between standalone `prover.prove(env, elf)` for
//! a single program (measured in the main bench) and a full `execute_and_prove`
//! that wraps the same program in the privacy circuit. Chained-call depth sweep
//! uses the `chain_caller` test program (loaded from artifacts/) with N=1, 3, 5, 9.
//!
//! `Receipt::verify(PRIVACY_PRESERVING_CIRCUIT_ID)` timings (the `G_verify` fee-model
//! parameter) are measured by the `verify` criterion bench under `benches/verify.rs`,
//! which reuses the `prove_auth_transfer_in_ppe` setup helper re-exported below.

#![allow(
    dead_code,
    reason = "Stubs are used when the `ppe` feature is disabled."
)]

use serde::Serialize;

#[cfg(feature = "ppe")]
mod ppe_impl;

#[cfg(feature = "ppe")]
pub use ppe_impl::prove_auth_transfer_in_ppe;

#[derive(Debug, Serialize, Clone)]
pub struct PpeBenchResult {
    pub label: String,
    pub chain_depth: usize,
    pub prove_wall_ms: Option<f64>,
    /// borsh-serialized `InnerReceipt` length (`S_agg` in the fee model).
    pub proof_bytes: Option<usize>,
    pub error: Option<String>,
}

#[cfg(not(feature = "ppe"))]
#[must_use]
pub const fn run_all() -> Vec<PpeBenchResult> {
    Vec::new()
}

#[cfg(feature = "ppe")]
#[must_use]
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
