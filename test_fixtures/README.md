# test_fixtures

Shared test/bench fixtures that spin up bedrock + sequencer + indexer + wallet end-to-end.

## Library

`TestContext` drives the full stack for integration tests and benches:

```rust
let ctx = TestContext::new().await?;              // fast: restores the prebuilt db dump
let ctx = TestContext::builder()
    .from_scratch()                                // apply genesis + fund private accounts live
    .with_genesis(actions)                         // custom genesis (implies from_scratch)
    .disable_indexer()
    .build().await?;
```

`TestContext::new()` restores `fixtures/prebuilt_sequencer_db.dump` (genesis + private-funding
blocks) instead of re-applying genesis and re-proving the private transfers, then syncs the wallet. Use
`from_scratch()` to build genesis live.

## Binary

`regenerate_test_fixture` regenerates that dump (needs Docker):

```sh
just regenerate-test-fixture   # RISC0_DEV_MODE=1 cargo run -p test_fixtures --bin regenerate_test_fixture
```

Rerun and commit `fixtures/prebuilt_sequencer_db.dump` after changing genesis, the default accounts,
block format, or initial state.
