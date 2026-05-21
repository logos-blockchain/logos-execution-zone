# integration_bench

End-to-end LEZ scenarios driven through the wallet against a docker-compose Bedrock node + in-process sequencer + indexer (via `test_fixtures::TestContext`). Times each step (submit, inclusion, wallet sync) and records borsh sizes for every block produced, split into per-tx-variant counts.

## Run

Prerequisite: a running local Docker daemon. The Bedrock service comes up via the same `bedrock/docker-compose.yml` that integration tests use, so no host-side binary or env vars are required.

```sh
# All scenarios, dev-mode proving (fast)
RISC0_DEV_MODE=1 cargo run --release -p integration_bench -- --scenario all

# One scenario, real proving (slow)
cargo run --release -p integration_bench -- --scenario amm
```

Scenarios: `token`, `amm`, `fanout`, `private`, `parallel`, `all`.

All scenarios share a single TestContext for the run (one Bedrock + sequencer + indexer + wallet across the whole run, chain state accumulating), which matches how the node runs in production.

## What you'll see

Per scenario: a step table (`submit_s`, `inclusion_s`, `sync_s`, `total_s`) and a size summary covering every block captured during the scenario (block_bytes total/mean/min/max; per-tx-variant sizes for public, PPE, and program-deployment transactions).

The fanout, parallel, and private scenarios are the most representative for L1-payload-size measurements since they put multiple txs per block.

JSON output is written to `target/integration_bench_dev.json` (dev mode) or `target/integration_bench_prove.json` (real proving).
