# cycle_bench

Per-program Risc0 cycle counts, privacy-circuit executor cycles, prover wall time, PPE composition cost, and verifier wall time for the built-in LEZ programs. Inputs for the fee model's `G_executor`, `G_prove`, `G_verify`, and `S_agg` parameters.

## Machine

| Field | Value |
|---|---|
| Chip | AMD Ryzen 7 PRO 7840U w/ Radeon 780M Graphics |
| Threads (`nproc`) | 16 |
| RAM (`free -g`) | 61 GiB |
| OS | Linux Mint 21.3 |
| Rust | 1.94.0 |
| Risc0 zkVM | 3.0.5 |
| Profile | release |
| GPU acceleration | none (CPU prover) |

Provenance: the committed guest artifacts at commit 65fa3d914 ("chore: artifacts", the tip of PR #817); `test_programs` guests built locally with the rzup toolchain.

Every table below except the verifier bench comes from one invocation on mains power:

```sh
cargo run --release -p cycle_bench --features ppe -- --circuit --prove --ppe --exec-iters 50
```

followed by the verify criterion bench.

`user_cycles` are deterministic and machine-independent, and reproduced exactly against an independent machine. The one exception is the noop program's own count in the circuit section: that guest is built by the local toolchain (8,188 here versus 8,251 on another toolchain), and the circuit cycles do not vary with it. Wall-time columns are machine-specific.

## Executor cycles and public-execution ms

`SessionInfo::cycles()` per instruction. Deterministic across runs. Wall time is `best / mean ± stdev` over the timed iterations (1 warmup discarded; `--exec-iters` sets the count, 50 below). `calib_ms` and `net_ms` are the public-execution time in milliseconds, on the same axis as the private `G_verify` so the fee model has one common unit for both paths. See the calibration block below for how they are derived.

| Program | Instruction | user_cycles | segments | exec_ms (best / mean ± stdev) | calib_ms | net_ms |
|---|---|---:|---:|---|---:|---:|
| authenticated_transfer | Transfer | 11,294 | 1 | 15.91 / 16.83 ± 0.85 | 2.59 | 1.19 |
| token | Mint | 15,249 | 1 | 19.67 / 21.05 ± 1.45 | 3.50 | 4.95 |
| token | Burn | 15,257 | 1 | 19.81 / 20.77 ± 1.27 | 3.50 | 5.09 |
| token | Transfer | 15,571 | 1 | 19.18 / 20.76 ± 1.13 | 3.57 | 4.46 |
| clock | Tick (block_id+1, no multiples) | 17,900 | 1 | 16.77 / 17.95 ± 1.44 | 4.11 | 2.05 |
| ata | Create | 20,162 | 1 | 18.60 / 19.86 ± 0.85 | 4.63 | 3.88 |
| amm | SwapExactInput | 37,694 | 1 | 24.08 / 25.59 ± 1.18 | 8.65 | 9.37 |
| amm | AddLiquidity | 45,399 | 1 | 24.72 / 26.08 ± 0.89 | 10.42 | 10.00 |

### Public-execution ms calibration

The binary fits `best_ms = intercept + slope · user_cycles` by ordinary least squares across the eight cases (best-of-N, not mean, so one OS scheduling spike cannot tilt the slope). On the machine above:

| Field | Value |
|---|---|
| throughput (1 / slope) | 4,357 cycles/ms |
| slope | 2.295e-4 ms per user cycle |
| fixed overhead (intercept) | 14.72 ms per call |
| R² | 0.813 |
| n | 8 |

- `calib_ms = user_cycles / throughput` is the compute-only time, a pure function of the deterministic cycle count and the one pinned-hardware constant, so it reproduces run to run where raw wall-time does not. This is the number to put on the common public/private ms axis.
- `net_ms = best exec_ms − fixed overhead` is the measured compute with the host-side overhead stripped; it agrees with `calib_ms` to within the per-program overhead scatter (the intercept is an ELF-size-averaged constant, so this decomposition is first-order, not mechanistic).
- The `fixed overhead` is host-side per-call setup (ELF parse into a `MemoryImage`, `ExecutorEnv` build) that is outside the cycle count and does not scale with the instruction's work.
- R² = 0.813 over these eight cases, whose cycle range is narrow relative to the per-call overhead, so the wall-time fit is indicative. The cycle counts themselves are exact.

The fixed overhead is paid per transaction in the current node, not amortized. The public-execution path at `lee/state_machine/src/program/mod.rs:57-87` builds a fresh `ExecutorEnv` and calls `default_executor().execute(env, self.elf())` per call (line 75) with the raw ELF bytes; no parsed image is cached across transactions. So today the real per-public-tx sequencer cost is the raw `exec_ms` (best 15.91 ms for the cheapest case above), overhead-dominated. Caching the parsed `MemoryImage` per `ProgramId` would drop the per-tx cost to `calib_ms` (2.59–10.42 ms). Public execution is also cycle-capped at `MAX_NUM_CYCLES_PUBLIC_EXECUTION` (const at `lee/state_machine/src/program/mod.rs:16`, applied as the session limit at `:65`), which bounds the worst-case public-tx cost.

## Privacy circuit (executor, `--circuit`)

A twin of executor cases that isolates the circuit's private path: a no-op program is executed once through the executor, then its journal is decoded and re-fed to the privacy-circuit ELF, which is executed over that input. The circuit's `env::verify` of the program output is satisfied by an unresolved risc0 assumption on the journal's receipt claim, so nothing is proven and the reported numbers are executor cycles only.

| Label | program_cycles | circuit_cycles | segments | exec_ms (best / mean ± stdev) |
|---|---:|---:|---:|---|
| noop / 1 public account | 8,188 | 33,368 | 1 | 30.83 / 32.33 ± 0.91 |
| noop / 1 private account init | 8,188 | 905,461 | 1 | 44.53 / 45.68 ± 0.87 |

`program_cycles` is the locally built noop guest's own count and varies with the guest toolchain (8,251 on another toolchain), whereas `circuit_cycles` does not.

The private row is 872,093 circuit cycles (27.1×) over the public control. The two rows run the same no-op program over the same default account; the only difference is the account identity fed to the circuit (`InputAccountIdentity::Public` vs a `Private` witness in the Init lifecycle, mirroring lee's circuit test `init_note_view_tag_is_derived_from_account_keys`). The delta is therefore the circuit's private path: account-id derivation, init nullifier, commitment, in-guest ML-KEM-768 encapsulation, ChaCha20 note encryption, view tag, and output sorting. 905,461 user cycles already exceeds 2^19 = 524,288, so a proof of that run pads to at least the 2^20 bucket before paging is counted; the public control sits under 2^16.

## Real proving (`--prove`)

`prover.prove(env, elf)` wall time per program on CPU. `total_cycles` is the power-of-two bucket the segment pads to once paging and reserved cycles are added on top of `user_cycles`, which is why the two AMM cases land in 2^17 with under 46k user cycles.

| Program | Instruction | total_cycles | prove_ms | prove_s |
|---|---|---:|---:|---:|
| authenticated_transfer | Transfer | 65,536 | 5,474 | 5.5 |
| token | Transfer | 65,536 | 5,815 | 5.8 |
| token | Mint | 65,536 | 5,873 | 5.9 |
| token | Burn | 65,536 | 5,924 | 5.9 |
| clock | Tick (block_id+1, no multiples) | 65,536 | 5,980 | 6.0 |
| ata | Create | 65,536 | 6,327 | 6.3 |
| amm | SwapExactInput | 131,072 | 12,112 | 12.1 |
| amm | AddLiquidity | 131,072 | 12,310 | 12.3 |

All eight are single-segment. 2^16 proves in 5.5–6.3 s and 2^17 in 12.1–12.3 s, about 90 µs per padded cycle.

## PPE composition + chain-call sweep (`--ppe`)

Same `auth_transfer Transfer` instruction, standalone vs wrapped in the privacy circuit; the no-op program with one private account initialised, wrapped in the privacy circuit; plus the `chain_caller` test program with N chained `authenticated_transfer` calls. `proof_bytes` is the borsh-serialized InnerReceipt (S_agg in the fee model).

| Case | prove_ms | prove_s | proof_bytes |
|---|---:|---:|---:|
| auth_transfer Transfer standalone | 5,474 | 5.5 | n/a |
| auth_transfer Transfer in PPE | 67,018 | 67.0 | 223,493 |
| noop private init in PPE | 277,086 | 277.1 | 224,497 |
| chain_caller depth=1 | 111,031 | 111.0 | 223,493 |
| chain_caller depth=3 | 201,291 | 201.3 | 223,493 |
| chain_caller depth=5 | 327,587 | 327.6 | 223,493 |
| chain_caller depth=9 | 491,244 | 491.2 | 223,493 |

- The composition tax for one all-public program is 67.0 − 5.5 = 61.5 s.
- A least-squares fit over depth 1..9 gives ≈ 48 s per additional chained call, with intercept ≈ 66 s.
- Initialising one private account raises the composition from 67.0 s to 277.1 s (4.1×). The circuit run behind it is 905,461 user cycles, past 2^19, so its segment pads to the 2^20 bucket; that is where the extra cost comes from.
- `proof_bytes` is constant across cases with the same journal shape (223,493 B for the five cases whose journal holds two public actions) because the succinct outer proof has fixed size and the journal travels inside the receipt claim. The private-init case is 224,497 B, 1,004 B more, because its journal carries one private action, dominated by the 1,088-byte ML-KEM ciphertext.

## Verifier (criterion bench)

One PPE receipt generated once (auth_transfer Transfer in PPE), then `Receipt::verify(PRIVACY_PRESERVING_CIRCUIT_ID)` measured under criterion's statistical sampler. Bench file: `tools/cycle_bench/benches/verify.rs`. Setup (one full PPE prove) is outside the timed `iter` loop. Criterion sample_size = 100, measurement_time = 15 s, warm_up_time = 2 s; slope-regression point estimate with 95% CI bounds on either side.

| Bench | low | point | high | outliers (mild + severe) |
|---|---:|---:|---:|---:|
| ppe/verify_auth_transfer | 11.640 ms | 11.664 ms | 11.692 ms | 1 + 7 |

## Findings

- Initialising one private account costs 872,093 circuit cycles (27.1×) over the public control, on an otherwise identical no-op execution. The private path (account-id derivation, init nullifier, commitment, in-guest ML-KEM-768 encapsulation, ChaCha20 note encryption, view tag, output sorting) is the whole delta.
- That delta crosses po2 buckets, which is what proving pays for: 905,461 user cycles is past 2^19 = 524,288, so the private-init run pads to at least 2^20 before paging, while the public control sits under 2^16.
- Standalone proving costs about 90 µs per padded cycle: 5.5–6.3 s in the 2^16 bucket and 12.1–12.3 s in 2^17. The two AMM instructions land in 2^17 at under 46k user cycles, so the bucket, not the user-cycle count, is what `G_prove` is priced on.
- Composing one all-public program into the privacy circuit costs 61.5 s (5.5 s standalone to 67.0 s in PPE), and each additional chained call adds ≈ 48 s (least-squares over depth 1..9, intercept ≈ 66 s).
- Initialising one private account inside the composition costs 277.1 s, 4.1× the all-public composition, for the po2 reason above.
- `G_verify` is ≈ 11.7 ms, thousands of times cheaper than any composition proof above. `S_agg` is 223,493 B for a journal with two public actions, and 1,004 B more with one private action (the 1,088-byte ML-KEM ciphertext dominates that difference).
- `user_cycles` and `circuit_cycles` are deterministic and machine-independent; `exec_ms`, `calib_ms`, `net_ms`, and the prover/verifier ms columns are specific to the box in the Machine section, and at R² = 0.813 the wall-time calibration is indicative.

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
