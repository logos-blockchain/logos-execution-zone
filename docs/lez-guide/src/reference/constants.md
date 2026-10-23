# Protocol constants and limits

Values read from the code at commit `faaa07251`. Check them against your checkout.

| Constant | Value | Where |
|---|---|---|
| Program segments per program | at most 20 | `MAX_PROGRAM_SEGMENTS`, `lee/state_machine/core/src/program/mod.rs` |
| Execution budget of a public transaction | 32 M cycles | `DEFAULT_PUBLIC_CYCLE_BUDGET`, `lee/state_machine/src/program/mod.rs` |
| Private actions per wallet-built private transaction | padded to 7 | `PADDED_PRIVATE_ACTIONS`, `lez/wallet/src/account_manager.rs` |
| Note padding | 512 bytes | `CIPHERTEXT_PAD_SIZE`, same file |
| Clock granularities | every 1, 10 and 50 blocks | `lez/programs/clock/core/src/lib.rs` |
| Note encryption | ML-KEM-768 | `lee/state_machine/core/src/encryption` |
| Collected messages per transaction | 1 | a transaction has one root |

## Limits that are missing

Review of the pull request found no cap on two things. Both may change before release.

- **The size of an actor's state.**
- **The number of messages one transaction may send.** Execution is bounded by the cycle budget, not by a count.

Design as if both were capped: keep state small and bounded, and keep conversations short.

## Interim choices

| Choice | Effect on a design |
|---|---|
| Private transactions pay no fee | proving is the only cost of a private action, for now |
| A transaction collects one stored message | draining a mailbox costs one proof per message |
| Padding to seven private actions | past seven the wallet pads with nothing and warns, so the transaction is still built but its exact count is no longer hidden |
