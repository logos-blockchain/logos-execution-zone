# cycle_bench

Per-program Risc0 cycle counts, prover wall time, PPE composition cost, and verifier wall time for the built-in LEZ programs. Inputs for the fee model's `G_executor`, `G_prove`, `G_verify`, and `S_agg` parameters.

## Machine

| Field | Value |
|---|---|
| Chip | Apple M2 Pro (8P+4E) |
| RAM | 16 GB |
| OS | macOS 26.5.1 |
| Rust | 1.94.0 |
| Risc0 zkVM | 3.0.5 |
| Profile | release |
| GPU acceleration | none |

## Executor cycles and public-execution ms

`SessionInfo::cycles()` per instruction, split by phase: one `plan` row, plus one `apply` row per effect the plan emits. Deterministic across runs. Wall time is `best / mean ± stdev` over the timed iterations (1 warmup discarded; `--exec-iters` sets the count, 50 below). `calib_ms` and `net_ms` are the public-execution time in milliseconds, on the same axis as the private `G_verify` so the fee model has one common unit for both paths. See the calibration block below for how they are derived.

| Program | Instruction | Phase | user_cycles | segments | exec_ms (best / mean ± stdev) | calib_ms | net_ms |
|---|---|---|---:|---:|---|---:|---:|
| clock | Tick (block_id+1, no multiples) | plan | 13,272 | 1 | 25.84 / 28.26 ± 1.63 | 0.83 | -0.67 |
| clock | Tick (block_id+1, no multiples) | apply | 8,156 | 1 | 26.77 / 27.80 ± 0.21 | 0.51 | 0.26 |
| clock | Tick (10-block rollup) | plan | 14,766 | 1 | 27.77 / 28.34 ± 0.27 | 0.92 | 1.27 |
| clock | Tick (10-block rollup) | apply | 8,156 | 1 | 26.12 / 27.68 ± 0.39 | 0.51 | -0.39 |
| clock | Tick (10-block rollup) | apply | 8,074 | 1 | 26.08 / 27.86 ± 0.50 | 0.50 | -0.43 |
| clock | Tick (10 and 50-block rollups) | plan | 15,812 | 1 | 26.71 / 28.18 ± 0.48 | 0.99 | 0.20 |
| clock | Tick (10 and 50-block rollups) | apply | 8,156 | 1 | 27.70 / 27.85 ± 0.11 | 0.51 | 1.19 |
| clock | Tick (10 and 50-block rollups) | apply | 8,074 | 1 | 27.08 / 27.82 ± 0.18 | 0.50 | 0.57 |
| clock | Tick (10 and 50-block rollups) | apply | 8,074 | 1 | 26.42 / 27.86 ± 0.36 | 0.50 | -0.09 |
| fee | Distribute | plan | 26,043 | 1 | 29.40 / 30.75 ± 0.26 | 1.63 | 2.89 |
| fee | Distribute | apply | 8,312 | 1 | 28.11 / 29.64 ± 0.29 | 0.52 | 1.60 |
| fee | Distribute | apply | 23,228 | 1 | 28.53 / 30.47 ± 0.39 | 1.45 | 2.02 |
| fee | Refund | plan | 13,652 | 1 | 29.63 / 30.14 ± 0.21 | 0.85 | 3.12 |
| data_writer | Write 4 KiB | plan | 44,452 | 1 | 29.00 / 29.74 ± 0.25 | 2.78 | 2.49 |
| data_writer | Write 4 KiB | apply | 35,797 | 1 | 27.79 / 29.17 ± 0.27 | 2.24 | 1.28 |
| data_writer | Write 64 KiB | plan | 552,625 | 1 | 61.26 / 62.35 ± 0.23 | 34.55 | 34.75 |
| data_writer | Write 64 KiB | apply | 451,810 | 1 | 54.53 / 57.23 ± 2.84 | 28.25 | 28.02 |

`data_writer` is a test program whose instruction payload is written straight into a shard, so its byte count is a cycle dial. It is present only to condition the fit: every built-in program left in the repo sits under 30k cycles, which is too narrow a span to separate the slope from the host-side overhead. The bench refuses to report a calibration from fewer than three rows or from a single program.

### Public-execution ms calibration

The binary fits `best_ms = intercept + slope · user_cycles` by ordinary least squares across all rows (best-of-N, not mean, so one OS scheduling spike cannot tilt the slope). On the machine above:

| Field | Value |
|---|---|
| throughput (1 / slope) | 15,994 cycles/ms |
| fixed overhead (intercept) | 26.51 ms per call |
| R² | 0.9911 |
| rows fitted | 17 |

- `calib_ms = user_cycles / throughput` is the compute-only time, a pure function of the deterministic cycle count and the one pinned-hardware constant, so it reproduces run to run where raw wall-time does not. This is the number to put on the common public/private ms axis.
- `net_ms = best exec_ms − fixed overhead` is the measured compute with the host-side overhead stripped. For rows under about 15k cycles the compute is far below the intercept's own scatter, so `net_ms` lands near zero and sometimes slightly negative. Read `calib_ms` for those rows, not `net_ms`.
- The `fixed overhead` is host-side per-call setup (ELF parse into a `MemoryImage`, `ExecutorEnv` build) that is outside the cycle count and does not scale with the instruction's work.

The throughput constant depends on the instruction mix it is fitted over. The high-cycle end of this fit is a 64 KiB shard write, which is memory-bound, so the constant is lower than a fit anchored by compute-bound program logic would give.

The fixed overhead is paid per transaction in the current node, not amortized. The public-execution path at `lee/state_machine/src/program.rs` builds a fresh `ExecutorEnv` and calls `default_executor().execute(env, self.elf())` per call with the raw ELF bytes; no parsed image is cached across transactions. So the real per-public-tx sequencer cost is the raw `exec_ms` (around 26 ms for the cheapest phase), overhead-dominated. Caching the parsed `MemoryImage` per `ProgramId` would drop the per-tx cost to `calib_ms`. Public execution is also cycle-capped at `MAX_NUM_CYCLES_PUBLIC_EXECUTION`, which bounds the worst-case public-tx cost.

## Real proving (`--prove`)

`prover.prove(env, elf)` wall time per phase on CPU. `total_cycles` is `user_cycles` rounded up to the next power of two (Risc0 padding).

| Program | Instruction | Phase | total_cycles | prove_ms | prove_s |
|---|---|---|---:|---:|---:|
| clock | Tick (block_id+1, no multiples) | plan | 65,536 | 4,468 | 4.5 |
| clock | Tick (block_id+1, no multiples) | apply | 65,536 | 4,378 | 4.4 |
| clock | Tick (10-block rollup) | plan | 65,536 | 4,433 | 4.4 |
| clock | Tick (10-block rollup) | apply | 65,536 | 4,405 | 4.4 |
| clock | Tick (10-block rollup) | apply | 65,536 | 4,383 | 4.4 |
| clock | Tick (10 and 50-block rollups) | plan | 65,536 | 4,433 | 4.4 |
| clock | Tick (10 and 50-block rollups) | apply | 65,536 | 4,430 | 4.4 |
| clock | Tick (10 and 50-block rollups) | apply | 65,536 | 4,416 | 4.4 |
| clock | Tick (10 and 50-block rollups) | apply | 65,536 | 4,440 | 4.4 |
| fee | Distribute | plan | 131,072 | 9,002 | 9.0 |
| fee | Distribute | apply | 65,536 | 4,383 | 4.4 |
| fee | Distribute | apply | 131,072 | 8,824 | 8.8 |
| fee | Refund | plan | 65,536 | 4,397 | 4.4 |
| data_writer | Write 4 KiB | plan | 131,072 | 8,757 | 8.8 |
| data_writer | Write 4 KiB | apply | 131,072 | 8,803 | 8.8 |
| data_writer | Write 64 KiB | plan | 1,048,576 | 76,391 | 76.4 |
| data_writer | Write 64 KiB | apply | 1,048,576 | 76,598 | 76.6 |

Proving time tracks the po2 bucket, not the raw cycle count: every 65,536 bucket costs about 4.4 s regardless of whether it holds 8k or 15k user cycles. Across buckets the rate is roughly 73 µs per total cycle.

## PPE composition + chain-call sweep (`--ppe`)

A native Transfer wrapped in the privacy circuit, swept over the dummy-input count the wallet pads with, then the `chain_caller` test program issuing N chained native Transfers. `proof_bytes` is the borsh-serialized `InnerReceipt` (`S_agg` in the fee model).

| Case | prove_ms | prove_s | proof_bytes |
|---|---:|---:|---:|
| native Transfer in PPE, 0 dummy inputs | 18,020 | 18.0 | 223,403 |
| native Transfer in PPE, 2 dummy inputs | 25,375 | 25.4 | 226,813 |
| native Transfer in PPE, 3 dummy inputs | 25,222 | 25.2 | 228,518 |
| native Transfer in PPE, 5 dummy inputs | 25,869 | 25.9 | 231,928 |
| native Transfer in PPE, 7 dummy inputs | 25,299 | 25.3 | 235,338 |
| chain_caller depth=1 | 45,871 | 45.9 | 223,468 |
| chain_caller depth=3 | 44,805 | 44.8 | 223,808 |
| chain_caller depth=5 | 64,017 | 64.0 | 224,148 |
| chain_caller depth=9 | 65,390 | 65.4 | 224,828 |

`AccountManager::MAX_PRIVATE_ACCOUNTS` pads every privacy-preserving transaction to 7 private slots, so a real wallet transaction pays the padded cost, not the unpadded 18.0 s. Prove time steps once at the first occupied slot and is then flat: 2 and 7 slots cost the same within noise, because the step is a po2 boundary rather than per-slot work. `proof_bytes` is linear at 1,705 bytes per slot, a 1,088-byte ML-KEM epk plus the 512-byte padded ciphertext. Lowering the pad from 7 to 3 would therefore save no measurable proving time and about 3% of the payload.

The chain-sweep callee here is the native token program, which has no guest to prove, so each additional hop adds only the circuit's own bookkeeping. Cost therefore steps with segment boundaries rather than rising per call: depths 1 and 3 cost the same, as do depths 5 and 9. A sweep against a guest-program callee would scale per hop instead; the repo no longer ships a non-native program this harness can chain into.

`proof_bytes` grows by 85 bytes per chained call and is otherwise fixed: the outer succinct proof has constant size, and the journal carried alongside it scales with public state.

## Verifier (criterion bench)

One PPE receipt generated once (native Transfer in PPE), then `Receipt::verify(PRIVACY_PRESERVING_CIRCUIT_ID)` measured under criterion's statistical sampler. Bench file: `tools/cycle_bench/benches/verify.rs`. Setup (one full PPE prove) is outside the timed `iter` loop.

Criterion sample_size = 100, measurement_time = 15 s, warm_up_time = 2 s. Slope-regression point estimate in the middle column; 95% CI bounds on either side.

| Bench | low | point | high | outliers (mild + severe) |
|---|---:|---:|---:|---:|
| ppe/verify_native_transfer | 11.510 ms | 11.531 ms | 11.563 ms | 8 + 8 |

## Findings

- Proving cost is set by the po2-bucketed `total_cycles`, not raw `user_cycles`. Trimming cycles only pays when it crosses a 2^N boundary.
- Public execution is host-overhead-bound. The 26.5 ms per-call setup dwarfs the 0.5 to 3 ms of compute every built-in program needs.
- Chaining native calls inside the PPE is cheap and steps with segment boundaries rather than scaling per hop.
- `G_verify` is about 11.5 ms and roughly constant per outer receipt. The succinct outer proof is about 223 KB (`S_agg`); verify is not on the latency critical path.

## Reproduce

```sh
# Executor cycles + public-execution ms calibration (no proving). --exec-iters sets the sample count.
cargo run --release -p cycle_bench -- --exec-iters 50
cargo run --release -p cycle_bench --features prove -- --prove
cargo run --release -p cycle_bench --features ppe -- --prove --ppe

# Verifier microbench via criterion:
cargo bench -p cycle_bench --features ppe --bench verify
```

JSON output: `target/cycle_bench.json` (bin), `target/criterion/ppe/verify_native_transfer/` (verify bench).

## Caveats

- CPU-only proving on a dev laptop. Production prover hardware (GPU, specialised CPU pipelines) will produce much smaller numbers; relative ordering should be preserved.
- Single-segment cases only; multi-segment programs would pay continuation overhead not measured here.
- The calibration's high-cycle anchor is a test program, not a built-in one. No program shipped in the repo exceeds 30k cycles.
