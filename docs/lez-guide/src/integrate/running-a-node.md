# Running a node

A local stack is three processes: a Logos blockchain node, the LEZ indexer, and the LEZ sequencer. The sequencer needs a channel on the L1 node, which it creates once during setup.

The commands below are the full set. If they ever drift, the repository `README.md` under "Run the sequencer and node" is where the canonical version lives.

## With `just`

```bash
just run-bedrock        # the L1 node, from Docker
```

Then the indexer and sequencer in their own terminals. The `Justfile` also carries `resolve-bedrock-node`, `resolve-host-bedrock-node`, `run-monitoring`, `run-explorer`, `build-artifacts`, `test`, `clean` and the cross-zone demos.

## Manually

The L1 node first:

```bash
just run-bedrock
```

The node binary is resolved from LEZ's locked Cargo dependency rather than built here. The resolver accepts a release only when its tag, asset checksum and commit match the Cargo-resolved revision, otherwise it builds that exact checkout. See `bedrock/README.md`.

Then the indexer:

```bash
RUST_LOG=info cargo run -p indexer_service lez/indexer/service/configs/debug/indexer_config.json
```

Then the sequencer, set up once and started thereafter:

```bash
cargo run -p sequencer_service -- setup lez/sequencer/service/sequencer_home \
  --config lez/sequencer/service/configs/debug/sequencer_config.json \
  --funding-public-key 2e03b2eff5a45478e7e79668d2a146cf2c5c7925bce927f2b1c67f2ab4fc0d26 \
  --create-channel

RUST_LOG=info cargo run -p sequencer_service -- start lez/sequencer/service/sequencer_home
```

`--create-channel` is the step that makes the zone exist: a zone is a channel on the L1, and everything the sequencer later writes is an inscription into it ([Finality](finality.md)).

Optionally the explorer:

```bash
cargo install cargo-leptos
cargo leptos build --release && cargo leptos serve --release
```

## Starting clean

Three directories hold state, and leaving any of them behind gives a confusing half-restart:

- `state` in the `logos-blockchain` checkout, unless running the node in Docker
- `lez/sequencer/service/sequencer_home`
- `lez/indexer/service/rocksdb-<channel id>`

`just clean` handles the LEZ side.

## What this chapter is not

Joining a live channel, staking into the committee, unstaking and slashing are operator concerns rather than integrator ones. The `sequencer_stake` program is summarized for program authors in [System programs](../build/system-programs.md), which covers the stake lifecycle, the two-step unstake and the two-thirds slashing rule. Channel parameters are genesis-immutable, so a channel's exit delay and minimum stake are decided when it is created.
