//! Privacy-preserving execution (PPE) cases for `cycle_bench`.
//!
//! Composition cost is the delta between standalone `prover.prove(env, elf)` for
//! a single program (measured in the main bench) and a full `execute_and_prove`
//! that wraps the same program in the privacy circuit. The send-depth sweep uses a
//! `scripted` test actor that sends N=1, 3, 5, 9 native transfers out of a private account.
//!
//! `Receipt::verify(PRIVACY_PRESERVING_CIRCUIT_ID)` timings (the `G_verify` fee-model
//! parameter) are measured by the `verify` criterion bench under `benches/verify.rs`,
//! which reuses the `prove_native_transfer_in_ppe` setup helper re-exported below.

#![allow(
    dead_code,
    reason = "Stubs are used when the `ppe` feature is disabled."
)]

use serde::Serialize;

#[cfg(feature = "ppe")]
mod ppe_impl;

#[cfg(feature = "ppe")]
pub use ppe_impl::prove_native_transfer_in_ppe;

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
pub const fn run_all(_fee_case: Option<usize>) -> Vec<PpeBenchResult> {
    Vec::new()
}

/// Runs every case, or only the fee case at `fee_case` in [`ppe_impl::FeeCase::ALL`]: with
/// `RISC0_PPROF_OUT` set, the profile left behind is then that case's circuit run.
#[cfg(feature = "ppe")]
#[must_use]
pub fn run_all(fee_case: Option<usize>) -> Vec<PpeBenchResult> {
    if let Some(index) = fee_case {
        return ppe_impl::FeeCase::ALL
            .get(index)
            .map(|case| ppe_impl::run_fee_transfer(*case))
            .into_iter()
            .collect();
    }
    let mut results = Vec::new();

    // What `AccountManager::PADDED_PRIVATE_ACTIONS` padding actually costs: the transfer's private
    // recipient takes 1 of the 7 actions, so a real wallet tx carries 6 dummies.
    for count in [0_usize, 2, 3, 6] {
        eprintln!("PPE: running native Transfer with {count} dummy inputs");
        results.push(ppe_impl::run_native_transfer_with_dummies(count));
    }

    for depth in [1_u32, 3, 5, 9] {
        eprintln!("PPE: running scripted to native Transfer depth={depth}");
        results.push(ppe_impl::run_scripted_transfers(depth));
    }

    for case in ppe_impl::FeeCase::ALL {
        eprintln!("PPE: running a deshielding transfer fee case");
        results.push(ppe_impl::run_fee_transfer(case));
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
