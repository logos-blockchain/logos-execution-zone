# The input echo: why proofs bind to their inputs

Every `PlanOutput` starts with a full copy of the `PlanInput` it was computed from, and every `ApplyOutput` starts with a full copy of its `ApplyInput`. Nothing about a program's *logic* needs that copy. It exists because of how zkVM proofs work, and it is the reason chained calls can be trusted at all. This chapter explains the problem, how the old interface handled it, and what changed with the plan/apply model.

## The problem: a receipt says nothing about its inputs

A RISC Zero receipt proves "image `I`, run on *some* input, halted with exit code 0 and committed these journal bytes". The input is private to the prover. The verifier sees the image id and the journal, nothing else.

For a single, top-level program that is fine: the program's output *is* the journal, and the verifier reads it. It stops being fine the moment one call depends on another. Consider the AMM chaining into the token program: the AMM's plan says "call `token` with selectors `[vault, user]` and instruction `Transfer { 75 }`". The circuit must then verify a receipt for `token`'s image id. But which run of `token`? A prover could hand over a perfectly valid receipt of `token` executed on `Transfer { 1 }` with different accounts, and the receipt would verify: the input was never part of the claim.

So the input has to get *into* the journal. The program must **echo** what it was given, and the orchestrator that scheduled the call must compare the echo against what it meant to give. Once that comparison holds, the receipt is bound to the scheduled call: image `I`, on exactly these accounts with exactly these authorization bits, this caller, this instruction, committed this output.

There is no way around this in the zkVM model. Inputs are private by construction; the only channel from the input to the verifier is the journal, and the only party that can write the journal is the guest.

## Before PR 912: the echo was a convention

The previous interface asked the program to construct its own output:

```rust
// old model, for contrast
ProgramOutput::new(self_account_id, caller_account_id, instruction_data, state_diffs).write()
```

where every `state_diff` carried a `pre_state: AccountInput` with the account id, its authorization bit, the selected shard **and that shard's contents**. The developer was expected to copy all of those through from the input. The validator (`lee/state_machine/core/src/validation.rs` on the pre-912 tree) then checked what it could: the echoed instruction data, self id and caller id against the scheduled call; the echoed selectors against the chained call's selectors; the echoed pre-state contents against the account as the traversal had it so far; that no account was undeclared and no shard was dropped.

Three weaknesses followed from "expected, not enforced":

1. **It was the developer's job.** A program that forgot an account, echoed a stale field, reordered its pre-states or hand-built the output wrong produced a journal the validator either rejected (good, but a correctness bug that only surfaced at runtime) or, in the gaps the checks did not cover, accepted. A whole family of test guests (`dropped_account`, `injects_undeclared_pre_state`, `malicious_self_program_id`, `malicious_caller_program_id`, `references_undeclared_account`) exists to pin those gaps shut one by one.
2. **Pre-state contents were part of the echo.** Inside the circuit a public account has no authoritative value, so the validator **adopted the guest's claim** about it the first time it was named (`AccountSource::AdoptClaims`) and the sequencer checked that claim against live state at settlement. A private transaction was therefore pinned to the exact bytes of every public shard it had read. If anything changed in between, even an unrelated field of the same shard, the transaction was dead. Two users could not both prepare a swap against the same pool.
3. **Authorization travelled in the echo too.** Each `pre_state.is_authorized` in the callee's journal was what extended the authorized set down the call tree, and the validator had to judge every one of those bits against witnesses and grants. Getting the judgement wrong in either direction was an authorization bug (the repository's audit history refers to one such issue).

## After PR 912: the echo is the SDK's, and it is total

The plan/apply model keeps the echo and moves it out of the program's hands.

**The echo is the whole input, verbatim.** `PlanOutput.input` is a `PlanInput`; `ApplyOutput.input` is an `ApplyInput`. `Plan::new(input)` clones the input into the output before the program adds a single effect, and `run_program` writes `ApplyOutput { input, post_data }` around whatever `apply` returned. A program written with `run_program` cannot mis-echo; there is no field for it to fill.

**The comparison is total.** The orchestrator (`ExecutionState`, the same code on the sequencer, in the prover and in the circuit guest) builds the `PlanInput` it intends to hand over: `self_account_id` from the chained call, `caller_account_id` from its own bookkeeping, `accounts` with authorization bits it computed from signatures, witnesses and seed grants, `instruction_data` from the call. After the guest runs, `validate_plan` requires `output.input == expected`, all fields, or fails with `PlanInputMismatch`. `validate_apply_output` does the same for `ApplyInput`, including `pre_data` and the selector, before it even judges whether the write is allowed (`ApplyInputMismatch`; test `an_apply_that_echoes_another_input_is_rejected_before_ownership_is_judged`). The `forges_apply_echo` guest forges each field in turn and every variant is refused (`assert_forged_field_is_refused`).

**The journal is tagged.** The guest commits `GuestOutput::Plan(..)` or `GuestOutput::Apply(..)`, and the circuit reconstructs the journal from the tagged value before `env::verify`. A plan receipt cannot be presented where an apply receipt is scheduled, or the reverse, even though both come from the same image id.

**Contents are no longer claims.** `PlanInput` carries no shard data at all, so there is nothing to adopt. `ApplyInput.pre_data` is supplied by the orchestrator from its own staged state: for a private account, from the witness; for a public account in a public transaction, from live state; for a public account in a private transaction, the apply is not run in the proof at all, it is deferred to settlement where the sequencer supplies the live bytes. The echo of `pre_data` still matters (it binds the apply receipt to the bytes it was given), but the *source* of those bytes is always the verifier, never the guest.

**Authorization is computed, not read back.** The authorized set for each call is built by the orchestrator from the root signers, the witnesses' `ask`, and seed grants, and it is what goes *into* the `PlanInput`. The echo only confirms the guest saw that set. A guest cannot upgrade an account's authorization by claiming it in its journal.

## What this buys, concretely

- **Chained calls are sound without developer discipline.** A callee's receipt is accepted only for the exact call its caller scheduled. Every program in the repository, and every one you write with `run_program`, gets this for free.
- **Prepared private transactions survive public state changes.** Because public shard contents are not in the proof, the proof does not go stale when they change. Only the deferred applies, re-run at settlement, decide whether the transaction still fits. That is the "incremental updates" the pull request is named for; `two_deshielded_transfers_to_one_recipient_compose_at_settlement` in `lee/state_machine/src/state/tests/privacy_preserving.rs` is its demonstration.
- **`plan` is verifiably state-free.** The echo is the proof's only window onto the input, and the input has no state in it. A reader of a `PlanOutput` can trust the plan was a function of exactly those accounts and that instruction.

## What it costs, and what it does not hide

- **Journal size.** Every receipt carries its full input. Instruction data and account lists are repeated in every plan receipt and every apply receipt. Keep instructions compact; for large payloads, put the bytes in a shard first and pass an account.
- **The echo is not published.** The receipts and their journals stay on the prover's machine. What reaches the chain is the circuit's own journal (the `Message`), which contains the deferred public effects, the private actions and the claims, not the `PlanInput`s. Instruction data of a private transaction is therefore never on chain. The privacy analysis in [What a private transaction reveals](../privacy/what-leaks.md) starts from the circuit output, not from the receipts.
- **Hand-rolled outputs are still possible.** `GuestOutput::Plan(PlanOutput::new(PlanInput { .. }))` compiles, and the test guests use it to forge echoes on purpose. A program that builds its output this way regains every foot-gun the old model had, and the runtime will reject it at the first mismatch. Use `run_program` and `Plan::new`.

## A short rule to remember

The verifier never trusts the guest about what the guest was told. It tells the guest, the guest repeats it back, and the verifier checks the repetition. Everything the guest is free to decide (effects, calls, windows, events) is in the rest of the output; everything it was not free to decide is in the echo.
