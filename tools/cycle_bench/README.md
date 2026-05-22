# cycle_bench

Per-program Risc0 cycle counts, prover wall time, PPE composition cost, and verifier wall time for the built-in LEZ programs. Feeds the fee model (`G_executor`, `G_prove`, `G_verify`, `S_agg`).

## Run

The binary handles executor cycles, prover wall time, and PPE composition cost:

```sh
# Executor cycles only (fast, ~seconds)
cargo run --release -p cycle_bench

# + real proving per program (slow, ~minutes)
cargo run --release -p cycle_bench --features prove -- --prove

# + PPE composition cases (very slow, ~hour)
cargo run --release -p cycle_bench --features ppe -- --prove --ppe
```

The verifier microbenchmark (`G_verify`) lives in a criterion bench under `benches/verify.rs`:

```sh
# Generates one PPE receipt for auth_transfer Transfer (~minutes of setup),
# then times Receipt::verify under criterion's statistical sampler.
cargo bench -p cycle_bench --features ppe --bench verify
```

`RISC0_DEV_MODE=1` skips proving entirely and is only useful for the executor path. The bin writes to `target/cycle_bench.json`; criterion writes per-bench estimates under `target/criterion/`.

## What you'll see

- Per-program executor cycles and segments, plus exec wall time as `best / mean ± stdev (n=N)`.
- With `--prove`: prover total cycles, paging cycles, segments, and wall time.
- With `--ppe`: end-to-end `execute_and_prove` wall time and `S_agg` (the borsh-serialized InnerReceipt length) for one auth-transfer-in-PPE case and a chain-caller depth sweep.
- From the `verify` criterion bench: `ppe/verify_auth_transfer` slope-regression point estimate with 95% CI bounds.

## Baseline comparison (verify bench)

```sh
# On main:
cargo bench -p cycle_bench --features ppe --bench verify -- --save-baseline main
# On your branch:
cargo bench -p cycle_bench --features ppe --bench verify -- --baseline main
```
