# crypto_primitives_bench

Cryptographic primitives used by client/wallet code. Measures the per-call cost of key derivation, sender-side ML-KEM-768 encapsulation for note encryption, and Account note symmetric encrypt/decrypt. Standalone host binary, no live stack required.

## Machine

| Field | Value |
|---|---|
| Chip | AMD Ryzen 7 PRO 7840U w/ Radeon 780M Graphics |
| Threads (`nproc`) | 16 |
| RAM (`free -g`) | 61 GiB |
| OS | Linux Mint 21.3 |
| Rust | 1.94.0 |
| Profile | release |

## Results

Criterion sample_size = 50, warm_up_time = 2 s, measurement_time = 10 s. Slope-regression point estimate in the middle column; 95% confidence interval bounds in the outer columns.

| Operation | low | point | high | outliers (mild + severe) |
|---|---:|---:|---:|---:|
| keychain/new_os_random | 2.761 ms | 2.774 ms | 2.793 ms | 0 + 5 |
| keychain/new_mnemonic | 2.778 ms | 2.787 ms | 2.796 ms | 2 + 3 |
| shared_secret_key/sender_encapsulate | 34.21 µs | 34.32 µs | 34.43 µs | 0 + 3 |
| encryption/encrypt | 467.3 ns | 468.7 ns | 470.4 ns | 1 + 3 |
| encryption/decrypt | 373.1 ns | 374.3 ns | 375.8 ns | 1 + 4 |

Numbers from a single dev box (see Machine above). For full estimates (slope, mean, median, MAD, std-dev) and the noise model, see `target/criterion/<group>/<bench>/estimates.json` after running locally.

## Findings

- Keychain creation is ≈ 2.8 ms, dominated by the 2048-round HMAC-SHA512 PBKDF in the mnemonic-to-SSK path. `new_os_random` and `new_mnemonic` are equal within noise, as expected: they run the same derivation.
- Per-recipient ML-KEM-768 encapsulation is ≈ 34 µs on the host (pure-Rust `ml-kem`). Outbound shielded transfers to N recipients cost ≈ 34·N µs of crypto on top of proving. The in-guest cost of the same encapsulation is a different regime and is not this number; it is measured by cycle_bench's private-init circuit case.
- Symmetric encrypt/decrypt over an Account note is sub-µs. Bulk encryption is not the bottleneck.

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

- Single-thread, no SIMD acceleration. Bench dev box uses the pure-Rust `ml-kem` backend.
