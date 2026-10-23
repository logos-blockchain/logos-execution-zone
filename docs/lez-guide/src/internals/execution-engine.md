# The execution engine

One engine runs every transaction. The sequencer uses it directly for a public transaction; a prover uses the same code inside the circuit for a private one. That shared implementation is why a program cannot tell which case it is in, and it is the single most load-bearing design decision in the system.

It is also tested as such. `a_generated_call_graph_runs_the_same_whole_and_split` generates a call graph and asserts it produces the same result run whole and run split across the boundary (`lee/state_machine/core/src/execution_state/tests.rs`). If that test ever fails, the premise of the privacy model has failed with it.

Source: `lee/state_machine/core/src/execution_state.rs`, about 1,400 lines, with settlement in `lee/state_machine/src/validated_state_diff/mod.rs` and the executor wrapper in `lee/state_machine/src/program/mod.rs`.

## The shapes

```rust
pub enum TransactionEntry<R>      // the root: a sync message, or a consumed async one
pub struct PublicExecutionContext // actors, authorized accounts, promotions
pub struct WholeExecution<'w>     // a transaction with both halves
pub struct PrivatePart<'w>        // the half that runs under proof
pub struct PublicPart             // the half the sequencer runs
pub struct Delivery<S>            // one message on its way to one actor
pub enum BoundaryStep             // a crossing between the halves
pub enum Placement                // whether an actor is public or private
pub struct TransitionView<'e>     // one handler invocation, as the engine sees it
```

`WholeExecution` is the interesting one. A transaction is not "public" or "private" as a whole; it is a sequence of segments on either side of a boundary, and the engine tracks which half it is in.

## Delivery order

A work stack, processed depth first. When a handler returns several messages, the first is delivered and everything it triggers completes before the second is delivered. Within one response, sync messages go before the async messages that the same transaction can run.

Async ordering is more specific than that, and a test states it: `a_parents_async_messages_precede_its_childrens_and_never_run_their_recipients`. A parent's async messages come before its children's, and an async message does not run its recipient inside the sending transaction. The companion on the private side is `a_promoted_private_async_message_keeps_its_own_presentation_and_crosses_after_the_calls`: async crosses the boundary after the calls, not with them.

The ordering matters to program authors for one reason: a handler that sends two messages cannot assume they interleave. The first subtree finishes entirely first, and `a_failing_descendant_of_c1_stops_the_transaction_before_c2` asserts the consequence: a failure deep inside the first subtree stops the transaction before the second message is ever delivered.

Re-entry works by staging. If a handler is invoked again inside the same transaction, it sees the state the earlier invocation left, not the state the transaction started with.

## No depth cap

There is no bound on how deep the message tree may go, and no bound on fan-out. The plan/apply model had `MAX_NUMBER_CHAINED_CALLS` of 10; the actor model removed it.

What bounds a transaction instead:

| Execution | Bound |
|---|---|
| Public | `DEFAULT_PUBLIC_CYCLE_BUDGET`, 32M RISC Zero cycles, shared across every transition in the transaction |
| Private | prover time and the patience of whoever is waiting |

Two tests pin this down rather than leaving it to inference. `a_long_self_send_chain_completes_in_every_part` builds a long chain of self-sends and asserts it completes in every part of a mixed transaction, and `a_long_self_send_chain_fits_the_public_budget` (`lee/state_machine/src/state/tests/chained_calls.rs`) asserts the same chain fits the public cycle budget. The budget is the bound, not a depth counter. `transitions_share_one_budget` (`lee/state_machine/src/validated_state_diff/tests.rs`) confirms the budget is shared across every transition rather than granted per handler.

Review of the change noted the missing cap as a gap that may be closed before release. Design as if one exists: keep conversations short and state small.

## The boundary

When execution crosses between public and private, the engine records a `BoundaryStep`. Each crossing names an `Actor`, and an `Actor` is `{ account_id, program_account_id }`.

That second field is the one with privacy consequences. Blinding a sender replaces the account id and leaves the program account id in the clear, so a boundary crossing always reveals which program was on the private side. [Programs, deployment and identity](../build/programs.md) covers what that means for an undisclosed claim, and it is the reason an undisclosed program's identity survives only a transaction that never crosses the boundary.

The engine also predicts the messages that will cross, and the circuit checks the prediction. The mismatch errors (`MissingPredictedCrossMessages`, `UnusedPredictedCrossMessages`, `BoundaryMismatch`, `CrossMessageMismatch`, `IncompleteBoundary`) all mean the prover and the sequencer disagree about what crossed. `a_nested_mixed_graph_is_predicted_bracketed_and_replayed_through_every_part` exercises the whole mechanism on a nested graph, and `a_nested_boundary_settles_both_public_writes` checks that a crossing nested inside another still settles correctly.

## Settlement

For a private transaction the sequencer does not re-run handlers. It verifies the proof and applies the effects that were deferred to public accounts, in the order the traversal emitted them, against live state.

Two consequences follow, and both are stated elsewhere in this guide because they shape designs rather than internals. A prepared private transaction still settles later against public state that has since moved, because that state was never in the proof. And every guard on public state has to be strong on its own, because the sequencer will not re-derive the reasoning that produced it.

## Where to read next

[The privacy circuit](privacy-circuit.md) is the other half: what the proof actually covers.

## How this chapter was checked

Every claim above corresponds to a named test in the tree, and the suite passes: 483 tests across `lee` and `lee_core`, all green, run with `RISC0_DEV_MODE=1 cargo nextest run -p lee -p lee_core`.

That is deliberately a weaker claim than "this chapter is correct". A passing test proves the behaviour it asserts; it does not prove this prose characterises that behaviour well. The test names are quoted so a reader can check the characterisation against the assertion rather than taking it on trust.
