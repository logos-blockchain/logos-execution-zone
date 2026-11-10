# Clock timestamp experiment

A transaction in block N must read block N's timestamp and ID through the clock actor. The fix makes the clock tick the first transaction and leaves the fee transaction last: `[clock, user transactions..., fee]`. Production, genesis, and replay use the same order.

## Run the regression tests

```sh
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export CARGO_BUILD_JOBS=2
RISC0_DEV_MODE=1 cargo test --locked -p sequencer_core --lib clock_reads_current_block_values -- --nocapture
RISC0_DEV_MODE=1 cargo test --locked -p sequencer_core --test clock_timestamp -- --nocapture
```

The first run compiles Rust dependencies and RISC Zero test programs. Later runs use the build cache. The settings above disable debug symbols and incremental compilation to reduce disk use, and limit compilation to two jobs. These tests need no running node or live network.

`clock_reads_current_block_values` deploys the existing `clock_reader` guest, queues signed, fee-paying timestamp and block-ID reads through the mempool, and builds a block at a fixed offset from its parent's timestamp. It checks the actual producer working state before replay. It then replays that produced block from the parent state with `chain_state::apply_block` and checks the replies and full resulting state. The test does not prescribe a body layout, so the same assertion can demonstrate the bug before the fix.

`lez/sequencer/core/tests/clock_timestamp.rs` is a smaller replay experiment. It applies genesis block 1 at 100 ms, followed by blocks 2 and 3 at 200 ms and 300 ms. It checks timestamp and block-ID reads separately, with granularity 1. The reader stores the clock's reply in its actor state. The test also checks the clock account's final state.

## Before the fix

The baseline is PR #988 at `f94ca8a7550fa0012222b9fb5990dfe44c54a3dc`. Its body order is `[user transactions..., fee, clock]`.

The original replay experiment passed with previous-block assertions on 2026-11-10:

```text
block=2 current=Timestamp(200) parent=Timestamp(100) observed=Timestamp(100)
block=3 current=Timestamp(300) parent=Timestamp(200) observed=Timestamp(200)
block=2 current=BlockId(2) parent=BlockId(1) observed=BlockId(1)
block=3 current=BlockId(3) parent=BlockId(2) observed=BlockId(2)
```

Changing its assertion to require the current timestamp failed with `left: Timestamp(100), right: Timestamp(200)`. The clock account itself still contained the current timestamp after the block completed.

The producer regression was also run before the ordering fix. It failed at the clock reply comparison:

```text
actual:   [Timestamp(1794332195878), BlockId(3)]
expected: [Timestamp(1794332196878), BlockId(4)]
```

Both actual values were from the parent. This failure came from the producer's working state, before replay could hide a production-only ordering error.

### Reproduce the failure at the test-only commit

Commit `160d507e916c0a1ef4da96df59c69e26109091ec` adds only the producer regression and its private test seam on top of #988. The fix follows in a separate commit. The producer regression's assertions are unchanged between them.

Start at the PR head with a clean working tree. Keep the low-disk environment settings from above, then run:

```sh
git switch --detach 160d507e916c0a1ef4da96df59c69e26109091ec
RISC0_DEV_MODE=1 cargo test --locked -p sequencer_core --lib clock_reads_current_block_values -- --nocapture
git switch -
RISC0_DEV_MODE=1 cargo test --locked -p sequencer_core --lib clock_reads_current_block_values -- --nocapture
```

The first test run fails because it reads the parent's values. The second passes at the PR head. The replay integration test is added with the fix and is not available at the test-only commit.

## After the fix

Both regressions passed on 2026-11-10. The producer test passed without changes to its assertions. The replay experiment reported:

```text
block=2 current=Timestamp(200) parent=Timestamp(100) observed=Timestamp(200)
block=3 current=Timestamp(300) parent=Timestamp(200) observed=Timestamp(300)
block=2 current=BlockId(2) parent=BlockId(1) observed=BlockId(2)
block=3 current=BlockId(3) parent=BlockId(2) observed=BlockId(3)
```

The forced clock has physical body position 0. User positions start at 1. The forced fee is last. Event indices and reverted transaction indices use those same physical positions. Neither forced transaction can be listed as reverted.

Focused clock, replay-validation, cross-zone, and reorg checks also passed. These checks used a temporary build directory with debug symbols and incremental compilation disabled. Build files used about 3.1 GB and were removed after verification. The full workspace suite was not run in this verification pass.

## Documentation and intent

The [baseline clock API docs](https://github.com/logos-blockchain/logos-execution-zone/blob/f94ca8a7550fa0012222b9fb5990dfe44c54a3dc/lez/programs/clock/core/src/lib.rs#L14-L15) explicitly state: "The sequencer ticks the clock as the last transaction of every block, so every other transaction sees the previous block's ID and timestamp."

The [review asks whether reads should return current-block values](https://github.com/logos-blockchain/logos-execution-zone/pull/988#discussion_r4477765720). The [author suggests moving the tick to the beginning in another PR](https://github.com/logos-blockchain/logos-execution-zone/pull/988#discussion_r4483657668). Previous-block reads were documented behavior at that revision. This fix implements the current-block behavior discussed in the review.

The original [clock PR #403](https://github.com/logos-blockchain/logos-execution-zone/pull/403) also put the clock invocation last. This ordering predates the single-clock actor change. No separate clock ADR was found in the repository.

## Compatibility and private proofs

This changes block validation, transaction positions, and block hashes. It requires a coordinated regenesis and targets the fresh-chain update already required by #988. The new validator rejects the old clock-last layout; it does not accept both layouts.

A private proof prepared against the parent clock reply can become invalid at the next tick. A coarser granularity keeps the rounded reply stable within a bucket, but crossing the bucket boundary invalidates that read. An exact timestamp read is not guaranteed to remain valid for inclusion. This fix does not change proof dependency checks.

## Database fixture

The stored database fixture must be regenerated before submission because the genesis order changed. This step needs Docker and additional disk space. It is still pending for this change; the existing dump has not been updated. See `test_fixtures/README.md` and run `just regenerate-test-fixture` in an environment with enough free space.

## Check on a live network

Use a reader actor that stores or emits the clock reply. Submit a public transaction that calls `ReadTimestamp { granularity: 1 }` and identify the block that includes it. Compare the captured reply with that block's header timestamp and its parent's header timestamp. Use different timestamps for the two blocks; otherwise the comparison is inconclusive. A block-ID read can provide a second check.

A direct clock-account query after block N is applied should show block N's timestamp. That query alone cannot show what a transaction inside block N saw. Also avoid using private proof-generation time as the observation: that can reflect an earlier simulation state.
