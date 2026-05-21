# integration_bench

End-to-end LEZ scenarios driven through the wallet against a docker-compose Bedrock node + in-process sequencer + indexer (via `test_fixtures::TestContext`). Times each step and records borsh sizes per block, split by tx variant.

Numbers below are from a single-host docker-compose run on an Apple M2 Pro (CPU only, no GPU acceleration). Absolute wall time and block sizes depend heavily on the bedrock config (block cadence and confirmation depth) and on dev-mode vs real proving; re-run the bench locally to characterise your own setup.

## Scenarios

| Scenario | Description |
|---|---|
| token | Sequential public token Send + one shielded recipient setup. |
| amm | Pool create, add liquidity, swap, remove liquidity. All public. |
| fanout | One sender → N recipients, sequential. All public. |
| private | Shielded, deshielded, private→private chained private flow. |
| parallel | N senders submit concurrently into one block. All public. |

## Dev-mode vs real-proving

`RISC0_DEV_MODE=1` makes the prover emit stub receipts instead of running the recursive STARK pipeline. The table compares each quantity in dev mode vs real proving for the two classes of scenarios:

| Quantity | Public-only scenarios (dev → real) | PPE-bearing scenarios (dev → real) |
|---|---|---|
| Wall time per step | same in both modes | real adds ~100 s per PPE step |
| `public_tx_bytes` | same in both modes | same in both modes |
| `ppe_tx_bytes` | n/a | dev ≈ 2 KB stub → real ≈ 225 KB (matches `S_agg` from cycle_bench) |
| `block_bytes` | same in both modes | real adds ~225 KB per PPE tx in the block |
| `bedrock_finality_s` | same in both modes | same in both modes (L1 cadence, not LEZ prover) |
| Blocks captured | similar in both modes | real captures more empty clock-only ticks that fill prove wall-time |

Tables below report dev-mode for all five scenarios. Real-proving numbers are included for `amm_swap_flow` (representative all-public) and `private_chained_flow` (representative chained-private flow); public-only scenarios converge between modes within run-to-run jitter, so a full real-proving sweep is not run here.

## Methodology

Per scenario, every produced block is fetched via `getBlock(BlockId)` and serialized with `borsh::to_vec(&Block)`. Each transaction is serialized individually and counted by variant. Empty clock-only ticks give the per-block fixed-cost baseline. Wall time is captured per step (submit + inclusion + wallet sync) and aggregated to the per-scenario `total_s`. The one-time stack-setup cost (`shared_setup_s` at the run level) and the closing bedrock finality wait (`bedrock_finality_s` per scenario) are reported separately, not folded into `total_s`.

## Step latencies — dev mode (`RISC0_DEV_MODE=1`)

Per-scenario wall time and Bedrock L1-finality latency for the closing tip.

| Scenario | total_s | bedrock_finality_s |
|---|---:|---:|
| token_onboarding | 61.36 | 5.88 |
| amm_swap_flow | 156.50 | 27.99 |
| multi_recipient_fanout | 214.40 | 31.71 |
| private_chained_flow | 109.31 | 8.73 |
| parallel_fanout | 234.42 | 20.29 |

Shared TestContext setup: 139.80 s (paid once per run). Total dev-mode wall time across all five scenarios: 1010.4 s.

## Step latencies — real proving (selected scenarios)

| Scenario | total_s | bedrock_finality_s | Δ vs dev |
|---|---:|---:|---:|
| amm_swap_flow | 156.20 | 26.95 | ~0 (all-public) |
| private_chained_flow | 391.74 | 9.40 | +282.4 s (≈ 94 s per PPE step × 3) |

Per-step breakdown for `private_chained_flow` in real proving:

| Step | submit_s | inclusion_s | total_s |
|---|---:|---:|---:|
| token_new_fungible (public) | 0.003 | 10.857 | 11.006 |
| shielded_transfer (PPE) | 125.416 | 0.001 | 125.469 |
| deshielded_transfer (PPE) | 126.261 | 0.001 | 126.311 |
| private_to_private (PPE) | 128.875 | 0.001 | 128.934 |

PPE steps move the cost from `inclusion_s` (waiting for the next sealed block) to `submit_s` (the wallet itself proving the PPE circuit before sending). Each PPE prove is ≈ 127 s on this CPU.

## Block + tx sizes (borsh) — dev mode

Per scenario, every produced block is fetched via `getBlock(BlockId)` and serialized with `borsh::to_vec(&Block)`. Each transaction is serialized individually and counted by variant. The empty clock-only ticks at `min` give the per-block fixed-cost baseline (≈ 334 bytes across all scenarios).

| Scenario | blocks | block_bytes (mean) | block_bytes (min..max) | public_tx (mean / n) | ppe_tx (mean / n) |
|---|---:|---:|---|---:|---:|
| token_onboarding | 6 | 881 | 334..2,890 | 206 / 8 | 2,556 / 1 |
| amm_swap_flow | 16 | 553 | 334..1,011 | 248 / 24 | n/a |
| multi_recipient_fanout | 22 | 513 | 334..707 | 221 / 33 | n/a |
| private_chained_flow | 10 | 1,186 | 334..3,565 | 173 / 11 | 2,715 / 3 |
| parallel_fanout | 24 | 646 | 334..3,904 | 248 / 45 | n/a |

## Block + tx sizes (borsh) — real proving

| Scenario | blocks | block_bytes (mean) | block_bytes (min..max) | public_tx (mean / n) | ppe_tx (mean / n) |
|---|---:|---:|---|---:|---:|
| amm_swap_flow | 16 | 553 | 334..1,011 | 248 / 24 | n/a |
| private_chained_flow | 39 | 17,707 | 334..226,578 | 158 / 40 | 225,728 / 3 |

`amm_swap_flow` is byte-identical between dev and real (no proof payload). `private_chained_flow`'s `ppe_tx_bytes` matches the cycle_bench `S_agg` measurement (≈ 225 KB borsh InnerReceipt). The `block_bytes` max (226,578) is the block containing the largest PPE transaction.

## Findings

- Public-only scenarios converge between dev mode and real proving in both latency and byte counts. Either mode is suitable to characterize them.
- PPE transactions are ≈ 225 KB on the wire in real proving, dominated by the outer succinct proof. Dev mode emits a ≈ 2.7 KB stub that does not represent the L1 payload; fee-model storage gas inputs must come from a real-proving run.
- Per-PPE-step prove cost on this CPU is ≈ 127 s, paid on the wallet side at submit time, not on the sequencer. For a single-program chained flow the cost stacks linearly.
- Empty clock-only ticks set the per-block fixed-cost baseline at ≈ 334 bytes across all scenarios and both modes.
- Bedrock L1 finality varies in the 6 to 32 s range across scenarios, driven by L1 cadence and which tick the closing wait happens to land on, not by the LEZ prover.

## Reproduce

Prerequisite: a running local Docker daemon (the `bedrock/docker-compose.yml` is brought up by the bench).

```sh
# Dev-mode sweep (fast)
RISC0_DEV_MODE=1 cargo run --release -p integration_bench -- --scenario all

# Real-proving for representative private flow
cargo run --release -p integration_bench -- --scenario private

# Real-proving for representative public flow
cargo run --release -p integration_bench -- --scenario amm
```

JSON output: `target/integration_bench_dev.json` / `target/integration_bench_prove.json` (suffix toggled by `RISC0_DEV_MODE`).

## Caveats

- Dev-mode `ppe_tx_bytes` and PPE-step latencies are not representative of production; use real-proving numbers for any fee-model input that touches the storage or prover-cost components.
- Single-host run, no GPU acceleration. Real-proving on production prover hardware will move per-step latencies by orders of magnitude; byte counts will not change.
- Bedrock running locally via docker-compose; no real network latency between sequencer and Bedrock.
- Bedrock L1 finality (`bedrock_finality_s`) is set by the bedrock config in `bedrock/docker-compose.yml` (block cadence × confirmation depth). Different configs will shift `bedrock_finality_s` materially.
- All scenarios share a single TestContext for the run (one bedrock + sequencer + indexer + wallet for the whole run, chain state accumulating across scenarios), which matches how the node runs in production.
