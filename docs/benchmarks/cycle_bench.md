# cycle_bench

Per-program Risc0 cycle counts, prover wall time, PPE composition cost, and verifier wall time for the built-in LEZ programs. Inputs for the fee model's `G_executor`, `G_prove`, `G_verify`, and `S_agg` parameters.

## Machine

| Field | Value |
|---|---|
| Chip | Apple M5 Pro (15 cores, 5+10) |
| RAM | 24 GB |
| OS | macOS 26.6.2 |
| Rust | 1.94.0 |
| Risc0 zkVM | 3.1.0 |
| Profile | release (fat LTO, 1 codegen unit) |
| GPU acceleration | none |

## Executor cycles and public-execution ms

`SessionInfo::cycles()` per guest transition an operation takes, so an instruction with two transitions has two rows. Deterministic across runs. Wall time is `best / mean ± stdev` over the timed iterations (1 warmup discarded; `--exec-iters` sets the count, 50 below). `calib_ms` and `net_ms` are the public-execution time in milliseconds, on the same axis as the private `G_verify` so the fee model has one common unit for both paths. See the calibration block below for how they are derived.

| Program | Instruction | user_cycles | segments | exec_ms (best / mean ± stdev) | calib_ms | net_ms |
|---|---|---:|---:|---|---:|---:|
| clock | Tick | 6,697 | 1 | 9.95 / 10.80 ± 0.68 | 0.07 | -6.34 |
| fee | Distribute | 25,674 | 1 | 12.78 / 13.11 ± 0.18 | 0.28 | -3.51 |
| fee | Distribute | 30,373 | 1 | 12.70 / 13.00 ± 0.28 | 0.34 | -3.59 |
| fee | Refund | 13,875 | 1 | 12.31 / 12.56 ± 0.23 | 0.15 | -3.97 |
| scripted | Write 4 KiB | 41,255 | 1 | 12.24 / 12.64 ± 0.84 | 0.46 | -4.05 |
| scripted | Write 64 KiB | 549,430 | 1 | 30.37 / 31.72 ± 0.95 | 6.09 | 14.09 |
| system_upgrader | Schedule (committee 2) | 116,012 | 1 | 17.49 / 17.74 ± 0.21 | 1.29 | 1.20 |
| sequencer_stake | Schedule (committee 2) | 1,976,504 | 3 | 45.11 / 46.89 ± 2.04 | 21.90 | 28.82 |
| system_upgrader | Schedule (committee 4) | 150,028 | 1 | 18.01 / 18.34 ± 0.21 | 1.66 | 1.72 |
| sequencer_stake | Schedule (committee 4) | 3,004,165 | 4 | 55.17 / 55.95 ± 0.48 | 33.29 | 38.88 |
| system_upgrader | Schedule (committee 7) | 217,880 | 1 | 18.79 / 19.07 ± 0.18 | 2.41 | 2.50 |
| sequencer_stake | Schedule (committee 7) | 4,998,338 | 6 | 75.93 / 79.08 ± 1.96 | 55.39 | 59.64 |
| system_upgrader | Schedule (committee 10) | 285,812 | 1 | 19.70 / 19.90 ± 0.15 | 3.17 | 3.41 |
| sequencer_stake | Schedule (committee 10) | 7,015,551 | 8 | 95.55 / 98.54 ± 2.03 | 77.74 | 79.27 |
| system_upgrader | Schedule (committee 20) | 524,391 | 1 | 23.06 / 23.63 ± 0.67 | 5.81 | 6.77 |
| sequencer_stake | Schedule (committee 20) | 14,019,069 | 15 | 166.87 / 177.48 ± 27.91 | 155.35 | 150.58 |

`scripted` is a test program whose instruction payload is written straight into a shard, so its byte count is a cycle dial. The `Schedule` rows are an upgrade's approval checks at growing committee sizes; `sequencer_stake`'s reach 14M cycles and are what the high end of the fit rests on. The bench refuses to report a calibration from fewer than three rows or from a single program.

### Public-execution ms calibration

The binary fits `best_ms = intercept + slope · user_cycles` by ordinary least squares across all rows (best-of-N, not mean, so one OS scheduling spike cannot tilt the slope). On the machine above:

| Field | Value |
|---|---|
| throughput (1 / slope) | 90,241 cycles/ms |
| fixed overhead (intercept) | 16.29 ms per call |
| R² | 0.9890 |
| rows fitted | 16 |

- `calib_ms = user_cycles / throughput` is the compute-only time, a pure function of the deterministic cycle count and the one pinned-hardware constant, so it reproduces run to run where raw wall-time does not. This is the number to put on the common public/private ms axis.
- `net_ms = best exec_ms − fixed overhead` is the measured compute with the host-side overhead stripped.
- The `fixed overhead` is host-side per-call setup (ELF parse into a `MemoryImage`, `ExecutorEnv` build) that is outside the cycle count and does not scale with the instruction's work.

The fit is not a good one at the low end. Its intercept is above the whole wall time of every row under 50k cycles (10 to 13 ms), so their `net_ms` is negative: the multi-segment `sequencer_stake` rows set the line, and the single-segment rows sit below it. Read `calib_ms` for the small rows, and treat the throughput as the rate of long compute-bound sessions. It depends on the instruction mix it is fitted over: an earlier fit, on another machine and with the memory-bound 64 KiB shard write as its high end, gave 15,994 cycles/ms.

The bench calls `default_executor().execute(env, elf)` with the raw ELF bytes per call, as `Program::execute_session` in `lee/state_machine/src/program/mod.rs` does when built without the `prove` feature, so the per-call overhead is paid per transaction there. Public execution is cycle-capped at `DEFAULT_PUBLIC_CYCLE_BUDGET`.

## Real proving (`--prove`)

`prover.prove(env, elf)` wall time per transition on CPU. `total_cycles` is what proving pays for: each segment's user and paging cycles, rounded up to a power of two.

| Program | Instruction | total_cycles | segments | prove_ms | prove_s |
|---|---|---:|---:|---:|---:|
| clock | Tick | 65,536 | 1 | 2,923 | 2.9 |
| fee | Distribute | 65,536 | 1 | 2,791 | 2.8 |
| fee | Distribute | 131,072 | 1 | 5,527 | 5.5 |
| fee | Refund | 65,536 | 1 | 2,803 | 2.8 |
| scripted | Write 4 KiB | 131,072 | 1 | 5,650 | 5.6 |
| scripted | Write 64 KiB | 1,048,576 | 1 | 50,712 | 50.7 |
| system_upgrader | Schedule (committee 2) | 262,144 | 1 | 12,173 | 12.2 |
| sequencer_stake | Schedule (committee 2) | 2,228,224 | 3 | 105,645 | 105.6 |
| system_upgrader | Schedule (committee 4) | 262,144 | 1 | 12,120 | 12.1 |
| sequencer_stake | Schedule (committee 4) | 3,407,872 | 4 | 166,404 | 166.4 |
| system_upgrader | Schedule (committee 7) | 524,288 | 1 | 24,459 | 24.5 |
| sequencer_stake | Schedule (committee 7) | 5,505,024 | 6 | 276,619 | 276.6 |
| system_upgrader | Schedule (committee 10) | 524,288 | 1 | 26,800 | 26.8 |
| sequencer_stake | Schedule (committee 10) | 7,864,320 | 8 | 407,774 | 407.8 |
| system_upgrader | Schedule (committee 20) | 1,048,576 | 1 | 57,257 | 57.3 |
| sequencer_stake | Schedule (committee 20) | 15,204,352 | 15 | 769,499 | 769.5 |

Proving time tracks the po2 bucket, not the raw cycle count: every 65,536 bucket costs about 2.8 s whether it holds 7k or 26k user cycles. Across buckets and segments the rate is roughly 50 µs per total cycle.

## PPE composition + send-depth sweep (`--ppe`)

A native Transfer wrapped in the privacy circuit, swept over the dummy-input count the wallet pads with, then the `scripted` test actor sending N native Transfers out of a private account. `user_cycles`, `total_cycles` and `segments` are the privacy circuit's own run; `prove_ms` is the whole `execute_and_prove`, down to the succinct receipt. `proof_bytes` is the borsh-serialized `InnerReceipt` with its claim pruned to a digest, as the wallet sends it (`PROOF_BYTES` in the fee model).

| Case | user_cycles | total_cycles | segments | prove_ms | prove_s | proof_bytes |
|---|---:|---:|---:|---:|---:|---:|
| native Transfer in PPE, 0 dummy inputs | 808,346 | 1,048,576 | 1 | 90,018 | 90.0 | 223,047 |
| native Transfer in PPE, 2 dummy inputs | 832,373 | 1,048,576 | 1 | 88,222 | 88.2 | 223,047 |
| native Transfer in PPE, 3 dummy inputs | 844,562 | 1,048,576 | 1 | 88,064 | 88.1 | 223,047 |
| native Transfer in PPE, 6 dummy inputs | 882,387 | 1,081,344 | 2 | 104,493 | 104.5 | 223,047 |
| scripted to native Transfer depth=1 | 820,098 | 1,048,576 | 1 | 101,076 | 101.1 | 223,047 |
| scripted to native Transfer depth=3 | 870,175 | 1,048,576 | 1 | 100,752 | 100.8 | 223,047 |
| scripted to native Transfer depth=5 | 923,141 | 1,179,648 | 2 | 120,105 | 120.1 | 223,047 |
| scripted to native Transfer depth=9 | 1,026,899 | 1,310,720 | 2 | 124,484 | 124.5 | 223,047 |

`AccountManager::PADDED_PRIVATE_ACTIONS` pads every privacy-preserving transaction to 7 private actions, so a real wallet transfer carries 6 dummies and pays that row, not the unpadded one. A dummy costs about 12k user cycles. That is little by itself, but the circuit sits just under the 2^20-cycle segment limit, and by six dummies it has tipped into a second segment, which is where the 16 s go. Each action also adds about 1,705 bytes to the message (a 1,088-byte ML-KEM epk plus the 512-byte padded ciphertext), which storage gas meters.

The sweep's callee is the native token program, which has no guest to prove, so each additional send adds only the circuit's own bookkeeping, about 26k user cycles. Cost again steps with the segment count: depths 1 and 3 cost the same, as do depths 5 and 9.

`proof_bytes` is constant across every case: a succinct receipt proves RISC Zero's fixed recursion circuit, and the pruned claim drops the copy of the journal the message already carries.

### Fee cases (`--ppe-fee-case N`)

A deshielding transfer from one private account, which also pays the fee inside the proof. These rows close a plain `--ppe` run; `--ppe-fee-case N` runs one alone, and under `RISC0_DEV_MODE=1` it prints the cycle counts in under a second.

| N | Case | user_cycles | total_cycles | segments | prove_ms | prove_s | proof_bytes |
|---:|---|---:|---:|---:|---:|---:|---:|
| 0 | deshield, no fee | 813,896 | 1,048,576 | 1 | 86,151 | 86.2 | 223,047 |
| 1 | deshield, fee, recovery under its own key | 1,603,318 | 2,097,152 | 2 | 143,108 | 143.1 | 223,047 |
| 2 | deshield, fee, recovery under the note key | 904,585 | 1,114,112 | 2 | 94,355 | 94.4 | 223,047 |
| 3 | deshield, fee, public refund target | 876,936 | 1,048,576 | 1 | 80,913 | 80.9 | 223,047 |

One ML-KEM encapsulation costs about 700k user cycles, and a private payer's fee needs none beyond its note's: the fee fallback shares the note's encapsulation, and so does the refund's recovery binding when it is bound under the note's ephemeral key, as the wallet does (case 2). A binding under a key of its own pays for a second encapsulation and a second full segment (case 1). A refund to a public target needs no binding (case 3).

## Verifier (criterion bench)

One PPE receipt generated once (native Transfer in PPE), then `Receipt::verify(PRIVACY_PRESERVING_CIRCUIT_ID)` measured under criterion's statistical sampler. Bench file: `tools/cycle_bench/benches/verify.rs`. Setup (one full PPE prove) is outside the timed `iter` loop.

Criterion sample_size = 100, measurement_time = 15 s, warm_up_time = 2 s. Slope-regression point estimate in the middle column; 95% CI bounds on either side.

| Bench | low | point | high | outliers (mild + severe) |
|---|---:|---:|---:|---:|
| ppe/verify_native_transfer | 8.863 ms | 8.916 ms | 9.012 ms | 0 + 4 |

At the calibrated throughput, `G_verify` is 8.916 ms × 90,241 cycles/ms ≈ 804,607 cycles.

## Findings

- Proving cost is set by the po2-bucketed `total_cycles`, not raw `user_cycles`. Trimming cycles only pays when it crosses a 2^N boundary or drops a segment.
- The privacy circuit runs just under one 2^20-cycle segment, so small additions (six dummies, five sends, the fee's recovery binding) cost a second segment.
- Public execution of the small built-in programs is host-overhead-bound: 10 to 13 ms per call, against well under 1 ms of compute.
- `G_verify` is about 8.9 ms and roughly constant per outer receipt. The succinct outer proof is about 223 KB (`S_agg`); verify is not on the latency critical path.

## Reproduce

```sh
# Executor cycles + public-execution ms calibration (no proving). --exec-iters sets the sample count.
cargo run --release -p cycle_bench -- --exec-iters 50
cargo run --release -p cycle_bench --features prove -- --prove
cargo run --release -p cycle_bench --features ppe -- --prove --ppe
# One fee case alone, cycle counts only:
RISC0_DEV_MODE=1 cargo run --release -p cycle_bench --features ppe -- --ppe --ppe-fee-case 2

# Verifier microbench via criterion:
cargo bench -p cycle_bench --features ppe --bench verify
```

JSON output: `target/cycle_bench.json` (bin), `target/criterion/ppe/verify_native_transfer/` (verify bench).

## Caveats

- CPU-only proving on a dev laptop. Production prover hardware (GPU, specialised CPU pipelines) will produce much smaller numbers; relative ordering should be preserved.
- Prove wall time is one sample per row.
