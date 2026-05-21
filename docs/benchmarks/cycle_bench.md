# cycle_bench

Per-program Risc0 cycle counts, prover wall time, PPE composition cost, and verifier wall time for the built-in LEZ programs. Inputs for the fee model's `G_executor`, `G_prove`, `G_verify`, and `S_agg` parameters.

## Machine

| Field | Value |
|---|---|
| Chip | Apple M2 Pro (8P+4E) |
| RAM | 16 GB |
| OS | macOS 15.5 |
| Rust | 1.94.0 |
| Risc0 zkVM | 3.0.5 |
| Profile | release |
| GPU acceleration | none |

## Executor cycles

`SessionInfo::cycles()` per instruction. Deterministic across runs. Wall time is `best / mean ± stdev` over 5 timed iterations (1 warmup discarded).

| Program | Instruction | user_cycles | segments | exec_ms (best / mean ± stdev) |
|---|---|---:|---:|---|
| authenticated_transfer | Initialize | 43,642 | 1 | 18.86 / 19.41 ± 0.48 |
| authenticated_transfer | Transfer | 77,095 | 1 | 19.67 / 20.84 ± 1.16 |
| token | Burn | 116,546 | 1 | 24.86 / 25.46 ± 0.63 |
| token | Mint | 116,862 | 1 | 24.47 / 25.08 ± 0.42 |
| token | Transfer | 127,726 | 1 | 25.00 / 25.40 ± 0.29 |
| clock | Tick (no rollups) | 137,022 | 1 | 21.18 / 21.57 ± 0.41 |
| ata | Create | 175,056 | 1 | 23.64 / 24.94 ± 1.09 |
| amm | SwapExactInput | 508,634 | 1 | 34.21 / 34.77 ± 0.55 |
| amm | AddLiquidity | 642,774 | 1 | 37.59 / 37.87 ± 0.28 |

## Real proving (`--prove`)

`prover.prove(env, elf)` wall time per program on CPU. `total_cycles` is `user_cycles` rounded up to the next power of two (Risc0 padding).

| Program | Instruction | total_cycles | prove_ms | prove_s |
|---|---|---:|---:|---:|
| authenticated_transfer | Initialize | 131,072 | 11,881 | 11.9 |
| authenticated_transfer | Transfer | 131,072 | 13,705 | 13.7 |
| token | Burn | 262,144 | 22,893 | 22.9 |
| token | Mint | 262,144 | 23,927 | 23.9 |
| token | Transfer | 262,144 | 27,178 | 27.2 |
| clock | Tick | 262,144 | 23,486 | 23.5 |
| ata | Create | 262,144 | 21,093 | 21.1 |
| amm | AddLiquidity | 1,048,576 | 111,654 | 111.7 |
| amm | SwapExactInput | 1,048,576 | 126,400 | 126.4 |

Linear fit across po2 buckets: ≈ 100 µs per total cycle (≈ 10k cycles/s throughput on this CPU).

## PPE composition + chain-call sweep (`--ppe`)

Same `auth_transfer Transfer` instruction, standalone vs wrapped in the privacy circuit; plus the `chain_caller` test program with N chained `authenticated_transfer` calls. `proof_bytes` is the borsh-serialized. InnerReceipt (S_agg in the fee model).

| Case | prove_ms | prove_s | proof_bytes |
|---|---:|---:|---:|
| auth_transfer Transfer standalone | 13,705 | 13.7 | n/a |
| auth_transfer Transfer in PPE | 61,486 | 61.5 | 223,551 |
| chain_caller depth=1 | 122,590 | 122.6 | 223,551 |
| chain_caller depth=3 | 231,974 | 232.0 | 223,551 |
| chain_caller depth=5 | 372,123 | 372.1 | 223,551 |
| chain_caller depth=9 | 544,280 | 544.3 | 223,551 |

Linear fit depth=1..9: ≈ 53 s per additional chained call, intercept ≈ 73 s. Composition tax (single program PPE − standalone): ≈ 48 s. `proof_bytes` is constant: the outer succinct proof has fixed size; the journal carried alongside it scales with public state and is reported separately by `--verify`.

## Verifier (criterion bench)

One PPE receipt generated once (auth_transfer Transfer in PPE), then `Receipt::verify(PRIVACY_PRESERVING_CIRCUIT_ID)` measured under criterion's statistical sampler. Bench file: `tools/cycle_bench/benches/verify.rs`. Setup (one full PPE prove) is outside the timed `iter` loop.

Numbers from the most recent local run on the machine listed above. Criterion sample_size = 100, measurement_time = 15 s, warm_up_time = 2 s. Slope-regression point estimate in the middle column; 95% CI bounds on either side. Run `cargo bench -p cycle_bench --features ppe --bench verify` to refresh.

| Bench | low | point | high | outliers (mild + severe) |
|---|---:|---:|---:|---:|
| ppe/verify_auth_transfer | 12.016 ms | 12.215 ms | 12.469 ms | 1 + 10 |

The corresponding `proof_bytes` (S_agg) for the bench receipt is captured by `--ppe` above; the verify bench itself only times the verify call.

## Findings

- Proving cost scales with po2-bucketed `total_cycles`, not raw `user_cycles`. Trimming user_cycles only helps if it crosses a 2^N boundary.
- Single-program PPE composition tax on M2 Pro CPU: ≈ 48 s (61.5 − 13.7).
- Chained-call cost is linear at ≈ 53 s per call. A max-depth chain (10) would take ≈ 600 s standalone on this CPU.
- `G_verify` is ≈ 12 ms (criterion CI: 12.0–12.5 ms over 100 samples) and roughly constant per outer receipt. The succinct outer proof is fixed at 223,551 bytes (S_agg); verify is not on the latency critical path.

## Reproduce

```sh
cargo run --release -p cycle_bench
cargo run --release -p cycle_bench --features prove -- --prove
cargo run --release -p cycle_bench --features ppe -- --prove --ppe

# Verifier microbench via criterion:
cargo bench -p cycle_bench --features ppe --bench verify
```

JSON output: `target/cycle_bench.json` (bin), `target/criterion/ppe/verify_auth_transfer/` (verify bench).

## Caveats

- CPU-only proving on a dev laptop. Production prover hardware (GPU, specialised CPU pipelines) will produce much smaller numbers; relative ordering should be preserved.
- Single-segment cases only; multi-segment programs would pay continuation overhead not measured here.
