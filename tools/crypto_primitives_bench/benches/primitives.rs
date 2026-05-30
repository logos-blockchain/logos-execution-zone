//! Criterion microbenchmarks for client/wallet cryptographic primitives.
//!
//! Measures:
//! - `KeyChain::new_os_random` (mnemonic → SSK → NSK/VSK + public keys)
//! - `KeyChain::new_mnemonic` (same, but mnemonic exposed)
//! - `SharedSecretKey::encapsulate` (ML-KEM-768 encapsulation, the per-recipient cost)
//! - `EncryptionScheme::encrypt` / `decrypt` (Account note encryption)

use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use key_protocol::key_management::KeyChain;
use lee_core::{
    Commitment, EncryptionScheme, SharedSecretKey,
    account::{Account, AccountId},
    program::PrivateAccountKind,
};

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
    g.bench_function("sender_encapsulate", |b| {
        b.iter(|| SharedSecretKey::encapsulate(&vpk));
    });
    g.finish();
}

fn bench_encryption(c: &mut Criterion) {
    // One-time setup: a fixed Account/Commitment and a SharedSecretKey to bench
    // encrypt/decrypt over a representative note. Encapsulation cost is covered
    // by the SharedSecretKey bench above.
    let recipient_kc = KeyChain::new_os_random();
    let npk = recipient_kc.nullifier_public_key;
    let account = Account::default();
    let account_id = AccountId::for_regular_private_account(&npk, 0);
    let commitment = Commitment::new(&account_id, &account);
    let (shared, _epk) = SharedSecretKey::encapsulate(&recipient_kc.viewing_public_key);
    let kind = PrivateAccountKind::Regular(0_u128);
    let output_index: u32 = 0;

    let mut g = c.benchmark_group("encryption");
    g.sample_size(50).noise_threshold(0.05);
    g.bench_function("encrypt", |b| {
        b.iter(|| EncryptionScheme::encrypt(&account, &kind, &shared, &commitment, output_index));
    });
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
