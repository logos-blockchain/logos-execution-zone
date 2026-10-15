# System programs and the block

Some programs are part of the protocol's operation rather than user applications. Program authors mostly consume them (the clock) or must stay out of their way (fee and clock accounts). This chapter covers what each one offers a program and how a block is put together.

## The block

Every block is: user transactions, then the **fee** transaction, then the **clock** transaction, both forced and byte-checked by every follower (`lez/chain_state/src/apply.rs`). Every user transaction's diff, public or private, then passes `validate_user_state_modification` (`lez/common/src/transaction.rs`): it may never change a clock or fee account; it may change the bridge escrow only by increasing its native balance (a deposit's debit is a sequencer injection, never a user transaction); and it may never change any account's cross-zone inbox shard (only a dispatch does). Those accounts can be **read** by anyone, through guards, but not written.

## Clock

`clock_core::CLOCK_01_PROGRAM_ACCOUNT_ID`, `CLOCK_10_…`, `CLOCK_50_…` hold

```rust
pub struct ClockAccountData { pub block_id: u64, pub timestamp: Timestamp /* ms */ }
```

under the clock program's shard, refreshed every 1, 10 and 50 blocks respectively. A program reads time with a guard:

```rust
let Ok([state, clock]) = <[_; 2]>::try_from(input.accounts.clone()) else {
    panic!("Expected exactly 2 input accounts: state, clock");
};
assert_eq!(clock.account_id, CLOCK_01_PROGRAM_ACCOUNT_ID);
plan.inspect(&clock, clock.program_account_id, &Effect::TimestampIs(proposed));
// apply: assert_eq!(ClockAccountData::from_bytes(pre_data).timestamp, proposed); None
```

The pattern (from `test_programs/guest/src/bin/cooldown.rs`) is: the instruction proposes the current time, the clock guard pins it, and the program's own effects use the proposed value. `time_locked_transfer.rs` shows the inequality form (`timestamp >= deadline`). The clock is the only source of time and of "now"; there is no host call.

In a private transaction the clock guard is a deferred public effect: it runs at settlement, on the sequencer, against the clock as it is then. A private "withdraw what has vested" therefore proposes a timestamp, the note is proven with it, and the settlement checks the clock has reached it. If the proposed time is in the past the transaction settles; if in the future it waits, or rather is refused until resubmitted. Combine with a timestamp validity window to bound how long a prepared transaction stays acceptable.

## Fee

The fee program owns three PDAs: state (the market), escrow, and inbox. User programs never interact with it; the sequencer invokes it. What matters to authors is in [Transactions](transactions.md): public calls declare gas and pay per cycle, private calls are exempt for now, and a program cannot itself be a fee payer or recipient except by explicit transfers into its own PDAs.

## Native token

The native token program (`lee/state_machine/core/src/native_token.rs`) is protocol code with one instruction, `Transfer { amount }`, over exactly two native-balance selectors: an authorized sender and a distinct recipient. Effects are `Debit(amount)` and `Credit(amount)`, applied with checked arithmetic. Programs move native balance only by chaining into it, and delegate a PDA seed to spend from a vault (`custody_transfer`). Because it is recomputed in the circuit rather than proven, native transfers are cheap in private transactions and disclose no program.

## Bridge

The bridge program mints L1 deposits: a sequencer-injected `Deposit` credits the recipient from the bridge PDA (which holds the unissued supply) and writes a receipt PDA keyed by the L1 operation id so a deposit can never be replayed. Withdrawals are disabled in the current version. Genesis balances are deposits with synthetic ids.

## Sequencer stake

`sequencer_stake` (`lez/programs/sequencer_stake/`) records who is on the committee: a stake is a native transfer into a per-owner funds PDA plus an entry in a config PDA; unstaking is a two-step request (dated by a `requested_at` block the request must land close to) and a permissionless finalize allowed only after the channel's `exit_delay` blocks; slashing burns a stake into a sink PDA on two-thirds committee approval. It is a good reference for a program with a global config PDA, per-user records, a permissionless instruction whose safety rests entirely on recorded state, and ed25519 signature checking inside `apply`.

## Cross-zone messaging

Zones talk through two programs and a watcher. A program on the source zone chains into `cross_zone_outbox::Emit`, which writes an `OutboxRecord` into a slot PDA keyed by `(emitter, target zone, ordinal)`; the emitter must refuse to be chained into by any program (`assert!(input.caller_account_id.is_none())`), because the outbox records its **immediate** caller while cross-zone discovery names the top-level program. The destination zone's sequencer watches the peer's finalized blocks and injects `cross_zone_inbox::Dispatch`, which records the delivery in a per-peer-block "seen" shard and chains into the target program with a **source marker** PDA at position 0 followed by the selectors the message named.

A target that wants to accept cross-zone messages must do two things, both shown by `wrapped_token` and `ping_receiver`:

1. pin its caller to the inbox (`assert_eq!(caller_account_id, Some(cfg.deliverer))`, checked in `apply` against a config PDA);
2. re-derive the marker from the sources it authorizes (`inbox_source_marker_account_id(inbox, src_zone, src_program)`) and refuse any other.

A target that does neither is reachable by any peer with any instruction bytes. If your program has a privileged instruction and you have not pinned its caller, a peer zone can call it. Cross-zone delivery is public-only: the inbox is a top-level sequencer transaction and the message is on the peer's public chain.

`bridge_lock` and `wrapped_token` together form a lock-and-mint bridge with per-source lifetime mint caps and an optional renounceable authority; read them as the reference for "config PDA written once at genesis, updated by an authority, acted on through a governance program by delegation".

## What is not there

No randomness. No oracle. No host calls except reading the inputs and committing the output. No timers or scheduled execution: a program runs only when a transaction invokes it. No inter-transaction messaging except through shards. The catalog's [idea list](../catalog/ideas.md) records which designs this rules out and which substitutes exist.
