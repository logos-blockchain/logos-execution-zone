//! Criterion microbenchmarks for client/wallet cryptographic primitives.
//!
//! Measures:
//! - `KeyChain::new_os_random` (mnemonic → SSK → NSK/VSK + public keys)
//! - `KeyChain::new_mnemonic` (same, but mnemonic exposed)
//! - `SharedSecretKey::new` (Diffie-Hellman shared key derivation, the per-recipient cost)
//! - `EncryptionScheme::encrypt` / `decrypt` (Account note encryption)

use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use key_protocol::key_management::KeyChain;
use nssa_core::{
    Commitment, EncryptionScheme, SharedSecretKey,
    account::{Account, AccountId},
    encryption::{EphemeralPublicKey, EphemeralSecretKey},
    program::PrivateAccountKind,
};
use rand::{RngCore as _, rngs::OsRng};

fn bench_keychain(c: &mut Criterion) {
    let mut g = c.benchmark_group("keychain");
    g.sample_size(50).noise_threshold(0.05);
    g.bench_function("new_os_random", |b| b.iter(KeyChain::new_os_random));
    g.bench_function("new_mnemonic", |b| {
        b.iter(|| {
            let (_kc, _mnemonic) = KeyChain::new_mnemonic("");
        });
    });
    g.finish();
}

fn bench_shared_secret_key(c: &mut Criterion) {
    // One-time setup: recipient's viewing public key (sender side bench).
    let recipient_kc = KeyChain::new_os_random();
    let vpk = recipient_kc.viewing_public_key;

    let mut g = c.benchmark_group("shared_secret_key");
    g.sample_size(50).noise_threshold(0.05);
    g.bench_function("sender_dh", |b| {
        b.iter(|| {
            let mut bytes = [0_u8; 32];
            OsRng.fill_bytes(&mut bytes);
            let esk: EphemeralSecretKey = bytes;
            let _epk = EphemeralPublicKey::from(&esk);
            SharedSecretKey::new(esk, &vpk)
        });
    });
    g.finish();
}

fn bench_encryption(c: &mut Criterion) {
    // One-time setup: a fixed Account/Commitment and a SharedSecretKey to bench
    // encrypt/decrypt over a representative note. ESK gen is excluded from the
    // measured loop (covered by the SharedSecretKey bench above).
    let recipient_kc = KeyChain::new_os_random();
    let vpk = recipient_kc.viewing_public_key;
    let npk = recipient_kc.nullifier_public_key;
    let account = Account::default();
    let account_id = AccountId::for_regular_private_account(&npk, 0);
    let commitment = Commitment::new(&account_id, &account);
    let shared = {
        let mut bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let esk: EphemeralSecretKey = bytes;
        SharedSecretKey::new(esk, &vpk)
    };
    let kind = PrivateAccountKind::Regular(0_u128);
    let output_index: u32 = 0;

    let mut g = c.benchmark_group("encryption");
    g.sample_size(50).noise_threshold(0.05);
    g.bench_function("encrypt", |b| {
        b.iter(|| EncryptionScheme::encrypt(&account, &kind, &shared, &commitment, output_index));
    });
    // One ciphertext for the decrypt bench (encrypt is deterministic given inputs).
    let ct = EncryptionScheme::encrypt(&account, &kind, &shared, &commitment, output_index);
    g.bench_function("decrypt", |b| {
        b.iter(|| EncryptionScheme::decrypt(&ct, &shared, &commitment, output_index));
    });
    g.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(2))
        .measurement_time(Duration::from_secs(10));
    targets = bench_keychain, bench_shared_secret_key, bench_encryption
}
criterion_main!(benches);
