# crypto_primitives_bench

Cryptographic primitives used by client/wallet code. Measures the per-call cost of key derivation, sender-side DH for note encryption, and Account note symmetric encrypt/decrypt. Standalone host binary, no live stack required.

## Machine

| Field | Value |
|---|---|
| Chip | Apple M2 Pro (8P+4E) |
| RAM | 16 GB |
| OS | macOS 15.5 |
| Rust | 1.94.0 |
| Profile | release |

## Results

100 timed iterations per operation, 2 warmup discarded.

| Operation | best (µs) | mean (µs) | stdev (µs) |
|---|---:|---:|---:|
| KeyChain::new_os_random | 2,979.62 (2.98 ms) | 3,138.18 (3.14 ms) | 258.59 (0.26 ms) |
| KeyChain::new_mnemonic | 2,979.12 (2.98 ms) | 3,012.76 (3.01 ms) | 46.09 (0.05 ms) |
| SharedSecretKey::new (sender DH) | 74.17 (0.07 ms) | 74.48 (0.07 ms) | 0.22 (<0.01 ms) |
| EncryptionScheme::encrypt | 0.88 (<0.01 ms) | 0.92 (<0.01 ms) | 0.03 (<0.01 ms) |
| EncryptionScheme::decrypt | 0.75 (<0.01 ms) | 0.78 (<0.01 ms) | 0.04 (<0.01 ms) |

## Findings

- Keychain creation is dominated by the 2048-round HMAC-SHA512 PBKDF in the mnemonic-to-SSK path. ≈ 3 ms.
- Per-recipient DH (secp256k1) is ≈ 80 µs. Outbound shielded transfers to N recipients cost ≈ 80·N µs of crypto on top of proving.
- Symmetric encrypt/decrypt over a 49-byte Account note is sub-µs. Bulk encryption is not the bottleneck.

## Reproduce

```sh
cargo run --release -p crypto_primitives_bench
```

JSON output: `target/crypto_primitives_bench.json`.

## Caveats

- Single-thread, no SIMD acceleration. Bench dev box uses the pure-Rust secp256k1 backend.
