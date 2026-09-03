# cycle_bench

Per-program Risc0 cycle counts, privacy-circuit executor cycles, prover wall time, PPE composition cost, and verifier wall time for the built-in LEZ programs. Inputs for the fee model's `G_executor`, `G_prove`, `G_verify`, and `S_agg` parameters.

## Machine

| Field | Value |
|---|---|
| Chip | AMD Ryzen 7 PRO 7840U |
| vCPUs | 6 |
| RAM | 16 GB |
| OS | Ubuntu 24.04.4 LTS |
| Rust | 1.94.0 |
| Risc0 zkVM | 3.0.5 (r0vm 3.0.6) |
| Profile | release |
| GPU acceleration | none |

Provenance: the committed guest artifacts at commit 65fa3d914 ("chore: artifacts", the tip of PR #817); `test_programs` guests built locally with the rzup toolchain.

`user_cycles` are deterministic and machine-independent; wall-time columns are machine-specific.

The prover-side tables (`--prove`, `--ppe`, and the verify bench) are pending a re-run on this branch: their previous numbers were measured on different artifacts, at an order of magnitude more user cycles, and have been removed rather than carried forward.

## Executor cycles and public-execution ms

`SessionInfo::cycles()` per instruction. Deterministic across runs. Wall time is `best / mean ± stdev` over the timed iterations (1 warmup discarded; `--exec-iters` sets the count, 50 below). `calib_ms` and `net_ms` are the public-execution time in milliseconds, on the same axis as the private `G_verify` so the fee model has one common unit for both paths. See the calibration block below for how they are derived.

| Program | Instruction | user_cycles | segments | exec_ms (best / mean ± stdev) | calib_ms | net_ms |
|---|---|---:|---:|---|---:|---:|
| authenticated_transfer | Transfer | 11,294 | 1 | 21.18 / 23.39 ± 1.41 | 3.18 | 1.95 |
| token | Mint | 15,249 | 1 | 24.85 / 27.57 ± 2.88 | 4.29 | 5.62 |
| token | Burn | 15,257 | 1 | 25.18 / 28.45 ± 3.09 | 4.29 | 5.95 |
| token | Transfer | 15,571 | 1 | 25.55 / 28.07 ± 1.56 | 4.38 | 6.31 |
| clock | Tick (block_id+1, no multiples) | 17,900 | 1 | 21.09 / 23.77 ± 2.35 | 5.03 | 1.85 |
| ata | Create | 20,162 | 1 | 23.62 / 25.97 ± 1.60 | 5.67 | 4.38 |
| amm | SwapExactInput | 37,694 | 1 | 31.63 / 35.27 ± 3.71 | 10.60 | 12.39 |
| amm | AddLiquidity | 45,399 | 1 | 30.97 / 33.51 ± 1.80 | 12.76 | 11.74 |

### Public-execution ms calibration

The binary fits `best_ms = intercept + slope · user_cycles` by ordinary least squares across the eight cases (best-of-N, not mean, so one OS scheduling spike cannot tilt the slope). On the machine above:

| Field | Value |
|---|---|
| throughput (1 / slope) | 3,557 cycles/ms |
| slope | 2.812e-4 ms per user cycle |
| fixed overhead (intercept) | 19.23 ms per call |
| R² | 0.765 |
| n | 8 |

- `calib_ms = user_cycles / throughput` is the compute-only time, a pure function of the deterministic cycle count and the one pinned-hardware constant, so it reproduces run to run where raw wall-time does not. This is the number to put on the common public/private ms axis.
- `net_ms = best exec_ms − fixed overhead` is the measured compute with the host-side overhead stripped; it agrees with `calib_ms` to within the per-program overhead scatter (the intercept is an ELF-size-averaged constant, so this decomposition is first-order, not mechanistic).
- The `fixed overhead` is host-side per-call setup (ELF parse into a `MemoryImage`, `ExecutorEnv` build) that is outside the cycle count and does not scale with the instruction's work.
- R² = 0.765 over these eight cases: the cycle range is narrow relative to the per-call overhead and its jitter, so the wall-time fit is only indicative on this box. The cycle counts themselves are exact.

The fixed overhead is paid per transaction in the current node, not amortized. The public-execution path at `lee/state_machine/src/program/mod.rs:57-87` builds a fresh `ExecutorEnv` and calls `default_executor().execute(env, self.elf())` per call (line 75) with the raw ELF bytes; no parsed image is cached across transactions. So today the real per-public-tx sequencer cost is the raw `exec_ms` (best 21.09 ms for the cheapest case above), overhead-dominated. Caching the parsed `MemoryImage` per `ProgramId` would drop the per-tx cost to `calib_ms` (3.18–12.76 ms). Public execution is also cycle-capped at `MAX_NUM_CYCLES_PUBLIC_EXECUTION` (const at `lee/state_machine/src/program/mod.rs:16`, applied as the session limit at `:65`), which bounds the worst-case public-tx cost.

## Privacy circuit (executor, `--circuit`)

A twin of executor cases that isolates the circuit's private path: a no-op program is executed once through the executor, then its journal is decoded and re-fed to the privacy-circuit ELF, which is executed over that input. The circuit's `env::verify` of the program output is satisfied by an unresolved risc0 assumption on the journal's receipt claim, so nothing is proven and the reported numbers are executor cycles only.

| Label | program_cycles | circuit_cycles | segments | exec_ms (best / mean ± stdev) |
|---|---:|---:|---:|---|
| noop / 1 public account | 8,251 | 33,368 | 1 | 39.09 / 46.56 ± 13.54 |
| noop / 1 private account init | 8,251 | 905,461 | 1 | 56.82 / 62.58 ± 9.28 |

The private row is 872,093 circuit cycles (27.1×) over the public control. The two rows run the same no-op program over the same default account; the only difference is the account identity fed to the circuit (`InputAccountIdentity::Public` vs a `Private` witness in the Init lifecycle, mirroring lee's circuit test `init_note_view_tag_is_derived_from_account_keys`). The delta is therefore the circuit's private path: account-id derivation, init nullifier, commitment, in-guest ML-KEM-768 encapsulation, ChaCha20 note encryption, view tag, and output sorting. 905,461 user cycles already exceeds 2^19 = 524,288, so a proof of that run pads to at least the 2^20 bucket before paging is counted; the public control sits under 2^16.

## Real proving (`--prove`)

`prover.prove(env, elf)` wall time per program on CPU. `total_cycles` is `user_cycles` rounded up to the next power of two (Risc0 padding).

Pending re-run on this branch:

```sh
cargo run --release -p cycle_bench --features prove -- --prove
```

## PPE composition + chain-call sweep (`--ppe`)

Same `auth_transfer Transfer` instruction, standalone vs wrapped in the privacy circuit; the no-op program with one private account initialised, wrapped in the privacy circuit; plus the `chain_caller` test program with N chained `authenticated_transfer` calls. `proof_bytes` is the borsh-serialized InnerReceipt (S_agg in the fee model).

| Case | prove_ms | prove_s | proof_bytes |
|---|---:|---:|---:|
| auth_transfer Transfer standalone | pending | pending | n/a |
| auth_transfer Transfer in PPE | pending | pending | pending |
| noop private init in PPE | pending | pending | pending |
| chain_caller depth=1 | pending | pending | pending |
| chain_caller depth=3 | pending | pending | pending |
| chain_caller depth=5 | pending | pending | pending |
| chain_caller depth=9 | pending | pending | pending |

`proof_bytes` is expected constant across the PPE cases: the outer succinct proof has fixed size; the journal carried alongside it scales with the number of public and private actions and is not included.

Pending re-run on this branch:

```sh
cargo run --release -p cycle_bench --features ppe -- --prove --ppe
```

## Verifier (criterion bench)

One PPE receipt generated once (auth_transfer Transfer in PPE), then `Receipt::verify(PRIVACY_PRESERVING_CIRCUIT_ID)` measured under criterion's statistical sampler. Bench file: `tools/cycle_bench/benches/verify.rs`. Setup (one full PPE prove) is outside the timed `iter` loop. Criterion sample_size = 100, measurement_time = 15 s, warm_up_time = 2 s; slope-regression point estimate with 95% CI bounds on either side.

Pending re-run on this branch:

```sh
cargo bench -p cycle_bench --features ppe --bench verify
```

## Findings

- Initialising one private account costs 872,093 circuit cycles (27.1×) over the public control, on an otherwise identical no-op execution. The private path (account-id derivation, init nullifier, commitment, in-guest ML-KEM-768 encapsulation, ChaCha20 note encryption, view tag, output sorting) is the whole delta.
- That delta crosses po2 buckets, which is what proving pays for: 905,461 user cycles is past 2^19 = 524,288, so the private-init run pads to at least 2^20 before paging, while the public control sits under 2^16.
- `user_cycles` and `circuit_cycles` are deterministic and machine-independent; `exec_ms`, `calib_ms`, and `net_ms` are specific to the box in the Machine section, and at R² = 0.765 the wall-time calibration is indicative only.
- Proving-side findings (`G_prove`, composition tax, per-chained-call cost, `G_verify`, `S_agg`) are pending the re-run on this branch; the previous figures were measured on different artifacts and are not carried forward.

## Reproduce

```sh
# Executor cycles + public-execution ms calibration (no proving). --exec-iters sets the sample count.
cargo run --release -p cycle_bench -- --exec-iters 50

# Privacy-circuit executor cases (no proving). Needs the `test_programs` guests
# actually built: they are an empty stub whenever `RISC0_SKIP_BUILD` is set.
cargo run --release -p cycle_bench -- --circuit --exec-iters 50

cargo run --release -p cycle_bench --features prove -- --prove

# --ppe also needs the locally built `test_programs` guests (noop, chain_caller).
cargo run --release -p cycle_bench --features ppe -- --prove --ppe

# Verifier microbench via criterion:
cargo bench -p cycle_bench --features ppe --bench verify
```

JSON output: `target/cycle_bench.json` (bin; keys `standalone`, `calibration`, `circuit`, `ppe`), `target/criterion/ppe/verify_auth_transfer/` (verify bench).

## Caveats

- CPU-only proving on a dev laptop. Production prover hardware (GPU, specialised CPU pipelines) will produce much smaller numbers; relative ordering should be preserved.
- Single-segment cases only; multi-segment programs would pay continuation overhead not measured here.
- `--circuit` and `--ppe` depend on locally built `test_programs` guests, whose image ids differ from lee's `test_methods` copies. Irrelevant to cycle counts, but it means these cases are not reproducible from committed artifacts alone.
