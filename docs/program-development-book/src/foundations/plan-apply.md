# Plan and apply: the execution model

Every program has two entrypoints, and the runtime calls them in a fixed choreography. Understanding that choreography is most of what it takes to write a correct LEZ program, and all of what it takes to understand why private transactions can stay valid while public state changes underneath them.

Source: `lee/state_machine/core/src/program/mod.rs` and `lee/state_machine/core/src/execution_state.rs`.

## The two entrypoints

```rust
pub fn run_program<I, E, P, D>(
    plan:  impl FnOnce(&PlanInput, I) -> Plan,
    apply: impl FnOnce(E, &P) -> Option<D>,
) -> !
```

- **`plan`** receives the call's metadata and the decoded instruction, and returns a `Plan`: a list of *effects*, a list of *chained calls*, optional validity windows and events. It never sees any account's contents.
- **`apply`** receives one decoded effect and the current bytes of exactly one shard, and returns `None` to leave the shard as it is or `Some(bytes)` to replace it. It sees nothing else: not the other shards of the same account, not the other accounts, not the instruction.

A program is shaped like this:

```rust
use lee_core::program::{run_program, Plan, PlanInput};

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum Instruction { /* what the caller asks for */ }

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum Effect { /* what plan proposes to one shard */ }

fn plan(input: &PlanInput, instruction: Instruction) -> Plan {
    let mut plan = Plan::new(input);
    // inspect input.accounts and instruction, then:
    // plan.effect(&meta, &Effect::..);        // write or check own shard
    // plan.inspect(&meta, owner, &Guard::..); // check another program's shard
    // plan.call(ChainedCall::new(..));        // ask another program to act
    plan
}

fn apply(effect: Effect, pre_data: &[u8]) -> Option<Vec<u8>> {
    match effect { /* decode pre_data, check, produce post bytes */ }
}

fn main() { run_program(plan, apply) }
```

`apply`'s second parameter may be `&[u8]` or `&ShardData`; its return may be `Option<Vec<u8>>` or `Option<ShardData>`. A returned `Vec` longer than 100 KiB fails the call.

## PlanInput

```rust
pub struct PlanInput {
    pub self_account_id: AccountId,          // where this program is deployed
    pub caller_account_id: Option<AccountId>,// None at top level, Some(program) in a chained call
    pub accounts: Vec<AccountMeta>,          // one per selector, in order
    pub instruction_data: InstructionData,   // borsh bytes; run_program decodes them for you
}
```

`self_account_id` is the dispatch address, which is what a program hashes with when deriving its PDAs. `caller_account_id` is the authenticated identity of the program that chained into this one; the runtime, not the caller, fills it, and the program's echo of it is checked. It is the tool for "only I may call this instruction" and "only the inbox may deliver".

## Effects

```rust
plan.effect(&meta, &effect);            // selector must be one of this program's shards
plan.inspect(&meta, owner, &guard);     // selector must be `owner`'s shard
```

Both push a `ShardEffect { selector, data }` where `data` is the borsh encoding of the value. The only difference is the assertion: `effect` requires `meta.program_account_id == self_account_id`, `inspect` requires it to equal `owner`. The runtime later enforces the real rule in `validate_apply_output`: an apply that returns `Some` for a shard the program does not own fails the transaction. So `inspect` is for guards that must return `None`, and the name documents intent.

Rules the runtime enforces on the plan (`validate_plan`):

- every effect's selector must be one of the call's input selectors (`EffectOutsideInputs`);
- selectors in one call must be unique;
- the plan must echo the exact `PlanInput` it was given, so a guest cannot claim different accounts, a different caller or a different self id. `Plan::new` does this for you; [the next chapter](echo.md) explains why it is load-bearing.

Effects are applied **in emission order**, one at a time, and each apply sees the shard as the previous applies left it. Emitting an effect on the second account before one on the first is fine; the order is yours.

## Chained calls

```rust
plan.call(ChainedCall::new(program_account_id, shard_selectors, &instruction)
    .with_pda_seeds(vec![seed]));
```

A chained call names another program (or this one), the selectors it should receive, an instruction, and PDA seeds to delegate (next chapter). Every selector must name an account that is an input of the **root** call; a chained call can open a different shard of such an account, but cannot introduce an account the transaction never listed.

Order of execution for one call:

1. `plan` runs.
2. Every effect in the plan is applied, in order.
3. The chained calls are scheduled **depth first, in emission order**: the first chained call runs (its plan, its effects, then its own chained calls, recursively) before the second one starts.
4. Events are collected and the validity windows are intersected.

So a parent's effects always land before any child's. The AMM relies on this: it pins the offer against the pool with an effect, and only then chains the two token transfers. If a child fails, the whole transaction fails; there is no partial success and no catching.

A transaction may run the root call plus at most `MAX_NUMBER_CHAINED_CALLS` = 10 chained calls in total, counting nested ones.

## What apply sees

```rust
pub struct ApplyInput {
    pub self_account_id: AccountId,
    pub selector: ProgramShardSelector,
    pub pre_data: ShardData,     // the one shard, as staged so far in this transaction
    pub effect_data: EffectData, // what plan emitted
}
```

`pre_data` is the shard's contents **as of this point in the transaction**, including writes by earlier effects and earlier calls. A missing shard is empty bytes. In a public transaction the sequencer reads the live state; in a private transaction the value depends on the account's kind, which is the subject of the next section.

## The proposal-and-guard discipline

Because `plan` cannot read anything, every decision that depends on state has to be made twice: **proposed** in `plan` from the instruction, and **confirmed** in `apply` against the real bytes. The repository's programs call the proposal a *binding* and the check a *guard*. Three recurring shapes:

**Self-checking write.** The effect carries what the caller claims; `apply` panics if the shard disagrees.

```rust
// token transfer, sender side
Effect::Withdraw { descriptor, amount }
// apply: decode holding, assert definition and kind match `descriptor`,
// checked_sub(amount) or panic, re-encode.
```

**Guard on someone else's shard.** The effect is aimed at a shard the program does not own; `apply` returns `None` after asserting.

```rust
plan.inspect(&clock, clock.program_account_id, &DeadlineReached(deadline));
// apply: decode ClockAccountData, assert timestamp >= deadline, return None
```

**Branch pinned by a flag.** When `plan` must choose between two shapes (create versus mint, initialize versus top-up), the instruction carries the choice and the shard's own effect asserts the shard agrees.

```rust
Effect::InitializePool { pool_is_empty, definition }
// apply: assert_eq!(pre_data.is_empty(), pool_is_empty)
```

The discipline sounds like extra work and it is. What it buys is that a plan is a **pure function of the instruction and the account list**. The plan does not depend on state, so a proof of the plan does not depend on state, so a private transaction proven at one point in time is still verifiable later. The state-dependent part, `apply`, is small, single-shard and can be re-run by whoever holds the shard.

## Panics

A panic anywhere in `plan` or `apply` fails the transaction. There is no error return. Use `assert!`, `expect` and `panic!` with messages; the message becomes the sequencer's log line and, for public transactions, the reason in the charged revert. Do not try to recover: a program that catches its own failures would just produce a plan that lies.

Non-zero exit codes (`env::exit(3)`) are also failures. Only `Halted(0)` counts.

## Validity windows

```rust
plan.block_window(10..);          // valid from block 10 onward
plan.timestamp_window(..deadline); // valid before `deadline` ms
```

A plan may bound the block id and the timestamp at which it is valid. Windows across a transaction's calls are intersected; an empty intersection fails the transaction. For a public transaction the check is against the block being built. For a private transaction the intersected windows are published in the message and checked at settlement, which makes them the main expiry mechanism for prepared private transactions. Windows are the only thing a plan can say about time; reading the clock is a guard, not a window.

## Events

```rust
plan.event(ProgramEvent { selector: [u8; 8], data: Vec<u8> });
```

Events are recorded with the emitting program's account id in public transactions. They are **dropped in private transactions** to preserve function privacy; a program that needs to notify anyone from a private execution has to write a shard instead.

## The three backends

The same `ExecutionState::run` drives three backends:

| Backend | Where | Public account effects | Private account effects |
|---|---|---|---|
| `PublicBackend` (sequencer, public tx) | `lee/state_machine/src/validated_state_diff/public_backend.rs` | applied now against live state | n/a (no witnesses) |
| `Prover` (wallet, private tx) | `…/privacy_preserving_transaction/circuit/mod.rs` | **deferred**: recorded as `DeferredPublicEffect` | applied now, receipts collected |
| `PrivateBackend` (circuit guest) | `lee/privacy_preserving_circuit/src/private_backend.rs` | deferred (same) | re-verified from receipts |

A **deferred public effect** is `(program_account_id, shard_program_account_id, effect bytes)`. At settlement the sequencer loads the program by its account id from chain state, runs its `apply` against the live shard and takes the result. That is the whole mechanism by which a private swap prepared at reserves 1000/1000 settles correctly, or is refused, against reserves 1200/850: the reserves were never in the proof. See `a_private_roots_public_outputs_settle_against_live_state` in `lee/state_machine/src/state/tests/privacy_preserving.rs` for the deferred apply, and `two_deshielded_transfers_to_one_recipient_compose_at_settlement` for the case where the reserves move in between.

Design consequence: in a private transaction, `apply` for a public shard runs **in the clear, later, on the sequencer**, with `effect_data` visible to everyone. The effect's bytes must therefore contain nothing you want hidden, and the program's `apply` for public shards must be deterministic given the effect and the shard alone (which it is by construction).

## Chained calls and the loader shard

The public backend resolves the callee's bytecode through `get_program_via`, which reads the loader shards staged in this very transaction before falling back to state. That is what lets one public transaction deploy a program and call it. In a private transaction every program that may run must be supplied to the prover up front in `ProgramWithDependencies`, keyed by the account id it is deployed at.
