# devnet_configs

Builds what the four-node docker devnet runs on — `lez/sequencer/service/docker-compose.devnet.yml`,
included by the repo-root compose file.

```sh
just regenerate-devnet-configs   # cargo run -p devnet_configs
```

It writes, under `lez/configs/docker-all-in-one/devnet/`:

- `sequencer_config.json`, shared by all four nodes. Extended from the single-node config next to it
  with the genesis that stakes all four channel signing keys — so the leader opens the channel
  already accrediting the whole committee — plus mDNS-discovered gossip and a turn short enough to
  watch rotation happen.
- `seq-<n>/channel_signing_key`, the only thing left that differs between the nodes: the Bedrock
  identity the node's stake accredits, mounted into its home. 32 random bytes, drawn fresh on every
  run.

The committee is arranged the way `integration_tests/tests/multi_sequencer.rs` arranges its own —
staked at genesis rather than joining later — but keyed independently of it.

## When to rerun

Most of the shared config is safe to edit by hand. The genesis stake entries are not: each
`stake_signature` covers the minimum stake and the node's position in the committee, so changing
`minimum_sequencer_stake`, the number of nodes, their order, or the stake message format invalidates
all four, and a node with an invalid founding stake panics as it applies genesis. Rerun here instead.
This crate's unit test checks the committed signatures, so a stale config fails CI rather than the
devnet.

Every run draws new keys and new signatures, so it always rewrites everything — there is no such
thing as a no-op rerun here. That also makes it a new committee on a new genesis block: wipe the
nodes' stores (`just clean`) before bringing the devnet back up, or they will come back to a channel
their fresh keys were never accredited on.
