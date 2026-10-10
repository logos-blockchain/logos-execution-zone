# integration_bench

End-to-end LEZ scenarios driven through the wallet against a docker-compose Bedrock node + in-process sequencer + indexer (via `test_fixtures::TestContext`). Times each step and records borsh sizes per block, split by tx variant.

Numbers below are from a single-host docker-compose run on an Apple M2 Pro (CPU only, no GPU acceleration), macOS 26.5.1, Rust 1.94.0, Risc0 3.0.5. Absolute wall time and block sizes depend heavily on the bedrock config (block cadence and confirmation depth) and on dev-mode vs real proving; re-run the bench locally to characterise your own setup.

## Scenarios

| Scenario | Description |
|---|---|
| fanout | One sender → N recipients, sequential. All public native transfers. |
| private | Shielded, deshielded, private→private chained private flow. |
| parallel | N senders submit concurrently into one block. All public native transfers. |

All three draw from a genesis-funded public account and move the native token; no program-issued token is involved.

## Dev-mode vs real-proving

`RISC0_DEV_MODE=1` makes the prover emit stub receipts instead of running the recursive STARK pipeline.

| Quantity | Public-only scenarios (dev → real) | PPE-bearing scenarios (dev → real) |
|---|---|---|
| Wall time per step | same in both modes | real adds the PPE prove time per private step |
| `public_tx_bytes` | same in both modes | same in both modes |
| `ppe_tx_bytes` | n/a | dev ≈ 24 KB stub → real ≈ 223 KB (matches `S_agg` from cycle_bench) |
| `block_bytes` | same in both modes | real adds about 223 KB per PPE tx in the block |
| `bedrock_finality_s` | same in both modes | same in both modes (L1 cadence, not LEZ prover) |
| Blocks captured | similar in both modes | real captures more empty clock-only ticks that fill prove wall-time |

Tables below report dev mode for all three scenarios. A real-proving sweep is not run here; `cycle_bench --ppe` measures the per-PPE prove cost directly.

## Methodology

Per scenario, every produced block is fetched via `getBlock(BlockId)` and serialized with `borsh::to_vec(&Block)`. Each transaction is serialized individually and counted by variant. Empty clock-only ticks give the per-block fixed-cost baseline. Wall time is captured per step (submit + inclusion + wallet sync) and aggregated to the per-scenario `total_s`. The one-time stack-setup cost (`shared_setup_s` at the run level) and the closing bedrock finality wait (`bedrock_finality_s` per scenario) are reported separately, not folded into `total_s`.

`bedrock_finality_s` is the time for the indexer's L1-finalised block id to reach the sequencer tip. If it does not within `--finality-timeout-s` (default 300), the scenario records it as unmeasured rather than reporting the deadline as a latency.

## Step latencies, dev mode (`RISC0_DEV_MODE=1`)

| Scenario | total_s | bedrock_finality_s |
|---|---:|---:|
| multi_recipient_fanout | 300.59 | 3.53 |
| private_chained_flow | 90.41 | 0.00 |
| parallel_fanout | 600.93 | 0.00 |

Shared TestContext setup: 8.06 s (paid once per run). Total dev-mode wall time across all three scenarios: 1003.6 s.

A finality of 0.00 means the indexer had already reached the tip when the scenario finished, which is what long scenarios produce.

Per-step breakdown for `private_chained_flow`:

| Step | submit_s | inclusion_s | total_s |
|---|---:|---:|---:|
| create_acc_priv_a | 0.009 | n/a | 0.009 |
| create_acc_priv_b | 0.009 | n/a | 0.009 |
| fund_private_account (PPE) | 30.093 | 0.000 | 30.110 |
| deshielded_transfer (PPE) | 30.108 | 0.001 | 30.128 |
| private_to_private (PPE) | 30.138 | 0.000 | 30.158 |

In dev mode every submitting step costs about 30 s, which is block cadence and not compute: the harness waits two blocks before reading back. Dev-mode step times are therefore cadence-bound and say nothing about prover cost.

## Block and transaction sizes, dev mode

| Scenario | blocks | block_bytes (mean) | block_bytes (min..max) | public_tx (mean / n) | ppe_tx (mean / n) |
|---|---:|---:|---|---:|---:|
| multi_recipient_fanout | 30 | 933 | 810..1,181 | 322 / 70 | n/a |
| private_chained_flow | 9 | 8,891 | 810..25,210 | 314 / 18 | 24,244 / 3 |
| parallel_fanout | 60 | 933 | 810..1,181 | 322 / 140 | n/a |

The `private_chained_flow` `ppe_tx_bytes` above are dev-mode stubs. Under real proving they become the `S_agg` figure from cycle_bench, about 223 KB each.

## Findings

- Public native transfers are small and uniform: 258 to 371 bytes per transaction, under 1.2 KB per block.
- A PPE transaction dominates its block. Even the dev-mode stub takes a block from 810 bytes to 25 KB, and real proofs take it to roughly 223 KB.
- Wall time in dev mode is set by block cadence, not by the node's work.

## Reproduce

```sh
# Prerequisite: a running Docker daemon and a resolved Bedrock node.
just resolve-bedrock-node

# All scenarios, dev mode
RISC0_DEV_MODE=1 cargo run --release -p integration_bench -- --scenario all

# One scenario, real proving (slow)
cargo run --release -p integration_bench -- --scenario private
```

JSON output: `target/integration_bench_dev.json` / `target/integration_bench_prove.json` (suffix toggled by `RISC0_DEV_MODE`).

## Caveats

- Dev-mode `ppe_tx_bytes` and PPE-step latencies are not representative of production. Any fee-model input touching storage or prover cost must come from a real-proving run.
- Single-host run, no GPU acceleration. Production prover hardware will move per-step latencies by orders of magnitude; byte counts will not change.
- Bedrock runs locally via docker-compose, so there is no network latency between sequencer and Bedrock, and `bedrock_finality_s` is set by that config's block cadence and confirmation depth.
- All scenarios share one TestContext for the run (a single Bedrock, sequencer, indexer and wallet, with chain state accumulating across scenarios), which matches how the node runs in production.
