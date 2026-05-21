//! Criterion bench for `Receipt::verify(PRIVACY_PRESERVING_CIRCUIT_ID)`.
//!
//! Produces the `G_verify` fee-model parameter. Setup: one full PPE prove of an
//! `auth_transfer` Transfer (minutes, runs once outside the timed loop). Measured
//! op: `Receipt::verify` over a real PPE receipt.
//!
//! Run with: `cargo bench -p cycle_bench --features ppe --bench verify`.

use std::{hint::black_box, time::Duration};

use anyhow::Context as _;
use criterion::{Criterion, criterion_group, criterion_main};
use cycle_bench::ppe::prove_auth_transfer_in_ppe;
use nssa::program_methods::PRIVACY_PRESERVING_CIRCUIT_ID;
use risc0_zkvm::{InnerReceipt, Receipt};

fn bench_verify(c: &mut Criterion) {
    let (output, proof) = prove_auth_transfer_in_ppe().expect("prove auth_transfer in PPE");
    let journal = output.to_bytes();
    let proof_bytes = proof.into_inner();
    let inner: InnerReceipt = borsh::from_slice(&proof_bytes)
        .context("decode InnerReceipt")
        .expect("InnerReceipt deserialize");
    let receipt = Receipt::new(inner, journal);

    // Sanity check before the timed loop.
    receipt
        .verify(PRIVACY_PRESERVING_CIRCUIT_ID)
        .expect("verify sanity check");

    let mut g = c.benchmark_group("ppe");
    g.sample_size(100)
        .warm_up_time(Duration::from_secs(2))
        .measurement_time(Duration::from_secs(15))
        .noise_threshold(0.05);
    g.bench_function("verify_auth_transfer", |b| {
        b.iter(|| {
            receipt
                .verify(black_box(PRIVACY_PRESERVING_CIRCUIT_ID))
                .expect("verify failed mid-loop");
        });
    });
    g.finish();
}

criterion_group!(benches, bench_verify);
criterion_main!(benches);
