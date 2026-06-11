//! Aggregator circuit bench module.
//!
//! Measures wall-clock time for batching N privacy-preserving circuit proofs into a
//! single aggregated proof, using both the core and strict aggregator variants.
//!
//! Reported metrics per (N, variant) pair:
//!   - `pp_prove_ms`: time to generate the N pp-circuit proofs (context for total cost)
//!   - `agg_prove_ms`: time to run `aggregate()` — the sequencer's batch proving step
//!   - `agg_proof_bytes`: borsh-serialized `InnerReceipt` of the aggregated proof
//!   - `pp_proof_bytes_per_tx`: same metric for one pp-proof, for size comparison
//!
//! Requires `--features aggregator` and a full build (aggregator ELFs must exist in
//! `artifacts/program_methods/`).

#![allow(
    dead_code,
    reason = "Stubs are used when the `aggregator` feature is disabled."
)]

use serde::Serialize;

#[cfg(feature = "aggregator")]
mod agg_impl;

#[derive(Debug, Serialize, Clone)]
pub struct AggregatorBenchResult {
    pub label: String,
    pub n_txs: usize,
    pub strict: bool,
    /// Total wall-clock time to generate all N pp-circuit proofs (ms).
    pub pp_prove_ms: Option<f64>,
    /// Wall-clock time for the `aggregate()` call alone (ms).
    pub agg_prove_ms: Option<f64>,
    /// borsh-serialized `InnerReceipt` length of the aggregated proof (bytes).
    pub agg_proof_bytes: Option<usize>,
    /// borsh-serialized `InnerReceipt` length of one pp-proof, for comparison (bytes).
    pub pp_proof_bytes_per_tx: Option<usize>,
    pub error: Option<String>,
}

#[cfg(not(feature = "aggregator"))]
#[must_use]
pub const fn run_all() -> Vec<AggregatorBenchResult> {
    Vec::new()
}

#[cfg(feature = "aggregator")]
#[must_use]
pub fn run_all() -> Vec<AggregatorBenchResult> {
    let mut results = Vec::new();
    for n_txs in [1_usize, 3, 5] {
        for strict in [false, true] {
            let variant = if strict { "strict" } else { "core" };
            eprintln!("aggregator: {variant} n={n_txs}");
            results.push(agg_impl::run(n_txs, strict));
        }
    }
    results
}

pub fn print_table(results: &[AggregatorBenchResult]) {
    if results.is_empty() {
        return;
    }
    let lw = results
        .iter()
        .map(|r| r.label.len())
        .max()
        .unwrap_or(0)
        .max("label".len());

    println!(
        "\n{:<lw$}  {:>5}  {:>22}  {:>22}  {:>12}  {:>12}  {}",
        "label",
        "n_txs",
        "pp_prove_ms (s)",
        "agg_prove_ms (s)",
        "agg_bytes",
        "pp_bytes/tx",
        "error",
        lw = lw,
    );
    println!("{}", "-".repeat(lw + 85));
    for r in results {
        let pp = fmt_ms(r.pp_prove_ms);
        let ap = fmt_ms(r.agg_prove_ms);
        let ab = r
            .agg_proof_bytes
            .map_or_else(|| "-".to_owned(), |n| n.to_string());
        let pb = r
            .pp_proof_bytes_per_tx
            .map_or_else(|| "-".to_owned(), |n| n.to_string());
        let e = r.error.as_deref().unwrap_or("");
        println!(
            "{:<lw$}  {:>5}  {:>22}  {:>22}  {:>12}  {:>12}  {}",
            r.label,
            r.n_txs,
            pp,
            ap,
            ab,
            pb,
            e,
            lw = lw,
        );
    }
}

fn fmt_ms(ms: Option<f64>) -> String {
    ms.map_or_else(
        || "-".to_owned(),
        |v| format!("{v:.1} ({:.1}s)", v / 1_000.0),
    )
}
