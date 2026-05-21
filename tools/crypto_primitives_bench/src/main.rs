//! Cryptographic primitive microbenchmarks used by client/wallet code.
//!
//! Measures:
//! - `KeyChain::new_os_random` (mnemonic → SSK → NSK/VSK + public keys)
//! - `KeyChain::new_mnemonic` (same, but mnemonic exposed)
//! - `SharedSecretKey::new` (Diffie-Hellman shared key derivation, the per-recipient cost)
//! - `EncryptionScheme::encrypt` / `decrypt` (Account note encryption)
//!
//! Reports best-of-N wall time per operation. No live stack required.

#![expect(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_precision_loss,
    clippy::float_arithmetic,
    clippy::print_stdout,
    reason = "Bench tool"
)]

use std::{path::PathBuf, time::Instant};

use anyhow::Result;
use key_protocol::key_management::KeyChain;
use nssa_core::{
    Commitment, EncryptionScheme, SharedSecretKey,
    account::{Account, AccountId},
    encryption::{EphemeralPublicKey, EphemeralSecretKey},
    program::PrivateAccountKind,
};
use rand::{RngCore as _, rngs::OsRng};
use serde::Serialize;

const ITERS: usize = 100;

#[derive(Debug, Serialize)]
struct OpResult {
    op: &'static str,
    iters: usize,
    best_us: f64,
    mean_us: f64,
    stdev_us: f64,
}

fn time<F: FnMut()>(op: &'static str, iters: usize, mut f: F) -> OpResult {
    // Warmup
    for _ in 0..2 {
        f();
    }
    let mut samples_ns: Vec<f64> = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = Instant::now();
        f();
        samples_ns.push(t.elapsed().as_nanos() as f64);
    }
    let best_ns = samples_ns.iter().copied().fold(f64::INFINITY, f64::min);
    let mean_ns: f64 = samples_ns.iter().sum::<f64>() / iters as f64;
    let stdev_ns = if iters > 1 {
        let var: f64 = samples_ns
            .iter()
            .map(|s| (s - mean_ns).powi(2))
            .sum::<f64>()
            / (iters - 1) as f64;
        var.sqrt()
    } else {
        0.0
    };
    OpResult {
        op,
        iters,
        best_us: best_ns / 1_000.0,
        mean_us: mean_ns / 1_000.0,
        stdev_us: stdev_ns / 1_000.0,
    }
}

fn main() -> Result<()> {
    let mut results: Vec<OpResult> = Vec::new();

    results.push(time("KeyChain::new_os_random", ITERS, || {
        let _kc = KeyChain::new_os_random();
    }));

    results.push(time("KeyChain::new_mnemonic", ITERS, || {
        let (_kc, _mnemonic) = KeyChain::new_mnemonic("");
    }));

    // SharedSecretKey: caller has ephemeral secret, recipient has VSK→VPK.
    // We bench the SENDER side: derive ephemeral pubkey, then SharedSecretKey::new(scalar, point).
    let recipient_kc = KeyChain::new_os_random();
    let vpk = recipient_kc.viewing_public_key;
    results.push(time("SharedSecretKey::new (sender DH)", ITERS, || {
        let mut bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let esk: EphemeralSecretKey = bytes;
        let _epk = EphemeralPublicKey::from(&esk);
        let _ssk = SharedSecretKey::new(esk, &vpk);
    }));

    // EncryptionScheme::encrypt / decrypt over a small Account note.
    let account = Account::default();
    let account_id = AccountId::new([7; 32]);
    let commitment = Commitment::new(&account_id, &account);
    let shared = {
        let mut bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let esk: EphemeralSecretKey = bytes;
        SharedSecretKey::new(esk, &vpk)
    };
    let kind = PrivateAccountKind::Regular(0_u128);
    let output_index: u32 = 0;

    let mut produced_ct = None;
    results.push(time("EncryptionScheme::encrypt", ITERS, || {
        let ct = EncryptionScheme::encrypt(&account, &kind, &shared, &commitment, output_index);
        produced_ct = Some(ct);
    }));
    let ct = produced_ct.expect("encrypt produced ciphertext");
    results.push(time("EncryptionScheme::decrypt", ITERS, || {
        let _decoded = EncryptionScheme::decrypt(&ct, &shared, &commitment, output_index);
    }));

    print_table(&results);
    write_json(&results)?;
    Ok(())
}

fn print_table(results: &[OpResult]) {
    let ow = results
        .iter()
        .map(|r| r.op.len())
        .max()
        .unwrap_or(0)
        .max("op".len());
    let cw = 22_usize;
    println!(
        "{:<ow$}  {:>6}  {:>cw$}  {:>cw$}  {:>cw$}",
        "op", "iters", "best_us (ms)", "mean_us (ms)", "stdev_us (ms)",
    );
    println!("{}", "-".repeat(ow + 6 + cw * 3 + 8));
    for r in results {
        println!(
            "{:<ow$}  {:>6}  {:>cw$}  {:>cw$}  {:>cw$}",
            r.op,
            r.iters,
            fmt_us_ms(r.best_us),
            fmt_us_ms(r.mean_us),
            fmt_us_ms(r.stdev_us),
        );
    }
}

fn fmt_us_ms(us: f64) -> String {
    let ms = us / 1_000.0;
    if ms < 0.01 {
        format!("{us:.2} (<0.01 ms)")
    } else {
        format!("{us:.2} ({ms:.2} ms)")
    }
}

fn write_json(results: &[OpResult]) -> Result<()> {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()?;
    let out_path = workspace_root
        .join("target")
        .join("crypto_primitives_bench.json");
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&out_path, serde_json::to_string_pretty(&results)?)?;
    println!("\nJSON written to {}", out_path.display());
    Ok(())
}
