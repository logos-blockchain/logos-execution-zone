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

Criterion sample_size = 50, warm_up_time = 2 s, measurement_time = 10 s. Slope-regression point estimate in the middle column; 95% confidence interval bounds in the outer columns.

| Operation | low | point | high | outliers (mild + severe) |
|---|---:|---:|---:|---:|
| keychain/new_os_random | 3.11 ms | 3.21 ms | 3.34 ms | 3 + 5 |
| keychain/new_mnemonic | 3.05 ms | 3.11 ms | 3.23 ms | 0 + 2 |
| shared_secret_key/sender_dh | 76.7 µs | 78.4 µs | 80.6 µs | 3 + 4 |
| encryption/encrypt | 1.11 µs | 1.17 µs | 1.25 µs | 1 + 5 |
| encryption/decrypt | 907 ns | 928 ns | 954 ns | 0 + 3 |

Numbers from a single M2 Pro dev box. For full estimates (slope, mean, median, MAD, std-dev) and the noise model, see `target/criterion/<group>/<bench>/estimates.json` after running locally.

## Findings

- Keychain creation is dominated by the 2048-round HMAC-SHA512 PBKDF in the mnemonic-to-SSK path. ≈ 3 ms.
- Per-recipient DH (secp256k1) is ≈ 80 µs. Outbound shielded transfers to N recipients cost ≈ 80·N µs of crypto on top of proving.
- Symmetric encrypt/decrypt over a 49-byte Account note is sub-µs. Bulk encryption is not the bottleneck.

## Reproduce

```sh
cargo bench -p crypto_primitives_bench --bench primitives
```

JSON estimates: `target/criterion/<group>/<bench>/estimates.json`. HTML report: `target/criterion/report/index.html`.

## Baseline comparison

```sh
# On main:
cargo bench -p crypto_primitives_bench --bench primitives -- --save-baseline main
# On your branch:
cargo bench -p crypto_primitives_bench --bench primitives -- --baseline main
```

Criterion reports per-bench change as a percentage with a 95% confidence interval; deltas within the CI are reported as "no significant change" rather than red.

## Caveats

- Single-thread, no SIMD acceleration. Bench dev box uses the pure-Rust secp256k1 backend.
