# cycle_bench

Per-program Risc0 cycle counts, prover wall time, PPE composition cost, and verifier wall time for the built-in LEZ programs. Feeds the fee model (`G_executor`, `G_prove`, `G_verify`, `S_agg`).

## Run

```sh
# Executor cycles only (fast, ~seconds)
cargo run --release -p cycle_bench

# + real proving per program (slow, ~minutes)
cargo run --release -p cycle_bench --features prove -- --prove

# + PPE composition cases (very slow, ~hour)
cargo run --release -p cycle_bench --features ppe -- --prove --ppe

# + verifier microbench (G_verify): generates one PPE receipt, times verify x1000
cargo run --release -p cycle_bench --features ppe -- --verify --verify-iters 1000
```

`RISC0_DEV_MODE=1` skips proving entirely and is only useful for the executor path. Combine flags freely; output is printed to stdout and written to `target/cycle_bench.json` for regression diffs.

## What you'll see

- Per-program executor cycles and segments, plus exec wall time as `best / mean ± stdev (n=N)`.
- With `--prove`: prover total cycles, paging cycles, segments, and wall time.
- With `--ppe`: end-to-end `execute_and_prove` wall time and S_agg (the borsh-serialized InnerReceipt length) for one auth-transfer-in-PPE case and a chain-caller depth sweep.
- With `--verify`: verify wall time `best / mean ± stdev`, plus `proof_bytes` and `journal_bytes`.
