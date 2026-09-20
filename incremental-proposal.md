# Incremental update proposal

Privacy-preserving executions are executed and proven locally in Risc0. The proof is bundled in a privacy transaction (with the relevant data). The sequencer verifies the proof against the chain's state and the provided data. Specifically, the sequencer uses the current state of each public account used in the privacy transaction. Validation fails when any of the public accounts' states differ from the ones used during proof generation. Thus, inducing a **race condition** in LEZ for privacy transactions.

Consider the example:

- Bob initializes a deshielded transfer to send Alice 5 tokens from his private account to her public account with state (`pub_alice_0`) known to him.
- During either Bob's proving time or while Bob's privacy transaction is sitting in mempool, Alice submits a public transaction that updates her account state (`pub_alice_1`).
- Once the sequencer attempts to validate Bob's transaction, Alice's account state (in LEZ) is `pub_alice_1` and not `pub_alice_0`. The transaction's proof verification fails. Thus, the sequencer rejects Bob's transaction.

The race condition is a consequence of LEE transaction design: LEE transactions (public and privacy) "fully" replace account states rather than simply update the entries. This race condition only exists for privacy transactions that touch a public account.

In this document, we propose a new LEZ program type that emits updates (for specified accounts) and applies an update to any given pre state. This design is an optional program type that developers can choose to use.

## 1 Big idea: incremental account update

LEZ programs consist of a match call for `ProgramCall` types. Currently, LEZ only supports `ProgramCall:Execute`. E.g., LEZ program's `main` calls each of the program's functions within `ProgramCall::Execute`.

We propose adding `CallKind::Incremental` as a new call type. A developer that chooses to support incremental updates would adopt a different paradigm in their program design: `ProgramCall::Execute` generates the change, delta, in account data and `CallKind::Incremental` applies the delta to a provided account state's data.


| type | workflow |
|----|----|
| regular program | `ProgramCall::Execute` given `pre_states` and outputs data. This data is verbatim replaces the `pre_states`' data.|
| incremental program | `ProgramCall::Execute` given `pre_states` and outputs data. <br>`CallKind::Incremental` takes `data` and an account's `pre_state`. The program's logic determines how `data` and `pre_state.data` interact with each other to produce the account's new `data`. </br>
|

Incremental provides an alternative to `Account.data` updates. This design allows LEZ programs to output `data` that can be applied to a different `pre_state`. This is crucial for privacy transactions that touch a public account.

**How is `Incremental` handled by transaction types?**

- Public transactions. Sequencer executes both `Execute` (program call) and `Incremental` in sequence.
- (Fully) Private transactions. `Execute` and `Incremental` is handled entirely (in sequence) in Risc0.
- Privacy transactions. `Execute` and `Incremental` is handled (in sequence) in Risc0. Additionally, for each public account (based on `InputAccountIdentity` in the `privacy_preserving_circuit`), the account is either resolved fully in-circuit or left with its updates accumulated (per account) and included in the transaction's receipt. The sequencer applies any accumulated updates to the public account's current state (using `Incremental`).

## 2 Program design that supports incremental updates

This section describes the program shape required to support incremental updates. Programs are not required to support incremental updates.

- `Execute` handles program logic that is directly called by a transaction's `Message`.
- `Incremental` resolves one account's `data` at a time, given that account's state and `delta: InstructionData`. To facilitate this and an incremental support check, `Incremental` supports the instruction shape `IncrementalCall { Probe, Update(delta) }`:
    - `Probe` provides a mechanism to establish whether a program supports `Incremental`. Support is inferred by the caller from the absence of an `UnsupportedCallKind` event.
    - `Update(delta)` is the actual resolution: given `pre_state.data` and the opaque, program-defined `delta` bytes, produce the account's new `data`.
    - A program that doesn't recognize this `Probe`/`Update` envelope at all falls back to `UnsupportedCallKind`. This is indistinguishable from a program that does not implement `Incremental`.

**Remarks**
- The use of `ProgramCall` ensures that the same program's ELF can be used for both program calls and updates.
- `Incremental`'s logic cannot be specified by a transaction's `Message`. Rather, `Incremental` is called by the sequencer and privacy preserving circuit to update an account's state.
- Incremental programs and regular programs emit outputs that possess the same shape. However, the logic used to update an account's data entry is different.

## 3 Protocol-level changes

A LEZ program can invoke another program through chain calls; for example, a program can invoke an `Incremental`-supporting program as part of its own logic. The caller's decisions are often based on the `pre_states` (and `instruction_data`) it was provided.

Consider two programs: `stripped_token` and `stripped_token_robinhood`.
- **`stripped_token`**: a simplified program that handles a token balance within its account's `data` field; no support for separate token definitions. The program (`Execute`) handles `initialize` and `transfer`, and `Incremental` to handle token balance changes (held in `data`).
- **`stripped_token_robinhood`**: swaps 1 token between two accounts; the account with the higher token balance pays a token to the other token account. `stripped_token_robinhood` program invokes `stripped_token` as a chain call for transfer. `stripped_token_robinhood`'s implementation does not support `Incremental`.

The correctness of `stripped_token_robinhood` requires the input (token) accounts to be anchored to the LEZ's state. E.g., the proof for privacy execution of `stripped_token_robinhood` requires the `pre_states` used in the execution to validate. This guarantees that the correct account receives the token. Thus, the correctness of `stripped_token_robinhood` relies on blocking  `stripped_token` from taking advantage of incremental updates at the sequencer level.

This example illustrates the need for restrictions for incremental updates in the privacy preserving circuit: any public account used by a regular program (one with no `Incremental` support), or merely *read* (no `post_data`) by any program regardless of its `Incremental` support, cannot defer its update. A read can drive a decision elsewhere in the call chain, as with `stripped_token_robinhood`, and a program's own `Incremental` support doesn't prove that decision is safe. Both cases anchor the account to LEZ's current state.


### 3.1 Current public transaction execution workflow

For each chained call, the sequencer:

1. Dispatches the program via `CallKind::Execute`, producing `program_output.state_diffs` — raw, as the program emitted them.
2. Checks the output's consistency with its caller (named accounts, `pre_state`s, `is_authorized`, `self`/`caller_account_id`, `call_kind`).
3. Runs `validate_execution`.
4. Checks the block/timestamp validity window.
5. Applies each diff via `post_state` — protocol level application of `post_balance_diff: BalanceDiff` and, when applicable, replacement of `pre_state.account.data` with `post_data` — and enqueues the program's chained calls.

### 3.2 Public transaction execution workflow with incremental updates

For each chained call, the sequencer:

1. Dispatches the program via `CallKind::Execute`, producing `program_output.state_diffs` — raw, as the program emitted them.
2. Checks the output's consistency with its caller (named accounts, `pre_state`s, `is_authorized`, `self`/`caller_account_id`, `call_kind`).
3. Resolves each diff. Diff updates the `pre_state.account.data` via the executing program's `Incremental::Update` if it responds to `Update` at all (detected by the absence of an `UnsupportedCallKind` event), or the diff is taken verbatim otherwise.
4. Runs `validate_execution`.
5. Checks the block/timestamp validity window.
6. Applies each resolved diff via `post_state` (e.g., replacement of the `pre_state`'s data) and enqueues the program's chained calls.

Programs output updates as `AccountStateDiff`. The account's `post_state` is produced by protocol level application of `post_balance_diff: BalanceDiff` and, when applicable, replacement of `pre_state.account.data` with `post_data`.

## 4 Privacy transaction changes

### 4.1 Account generation in circuit

- Private accounts are fully materialized within the privacy preserving circuit. Only a write touch (`post_data.is_some()`) runs `Incremental::Update` in-circuit; a read triggers no `Incremental` call at all. The final private account state is committed to (and the initial state nullified). From the observer's perspective, private accounts owned by an `Incremental` program or a regular program are indistinguishable.
- Public accounts are materialized within the circuit the same way. This guarantees that resolved values can be used as the `pre_state` for consecutive chain calls. What's actually recorded in the execution's receipt per public account depends on how the account was used and whether the *executing call* backed that touch with a covering claim (below), not merely on whether the account's `program_owner` implements `Incremental` at all:
    - **A touch (read or write) covered by that call's `Probe` claim** appends the touch to that account's `resolutions` list (a `DeferredResolution` for a write; a read leaves no entry — see below), committed as `PublicAction::Deferred { account_id, resolutions }`.
    - **An uncovered touch** — no `Probe` claim, or one that doesn't extend to this kind of touch — resolves the account fully in-circuit and forces `PublicAction::Bound { pre, post }`, anchoring `pre` to a specific pre-state the sequencer checks against live chain state.
    - Once any touch on an account is forced `Bound`, the account stays `Bound` for the rest of the execution: its pending `resolutions` are discarded (their effect is already reflected in the account's internally-tracked resolved value; only what gets *emitted* changes).
    - A read never appears in `resolutions`, even when covered — a covered read is a no-op against the account's classification, not a recorded entry. There's nothing to replay for a read; `resolutions` only ever needs to reconstruct a *value*, and a read never changes one.

**Why a write needs a covering claim too, not just `Incremental::Update` support.** A working `Update` implementation isn't enough by itself: the call's decision to write may still depend on some *other* account's content it merely read (e.g. `stripped_token_robinhood`). So the requirement is uniform: a touch, read or write, is only ever left `Deferred` if that call's own `Probe` response declares it safe, via `DeferReads`:

```rust
pub enum DeferReads {
    WriteOnly,
    ReadOnly,
    All,
}
```

`DeferReads::covers(is_write)` decides whether a touch is included. One static answer per `Probe` call covers every public account touched, distinguishing write-safety from read-safety: `WriteOnly` trusts only writes, `ReadOnly` trusts only reads, `All` trusts both. A program confident in neither declines `Probe` entirely, or answers `UnsupportedCallKind`, and every touch that call makes is forced `Bound`.

**A finer defer mechanism was considered, but not pursued here.** It appeared too ambitious for a first version, and may be unnecessary for most programs. This can be revisited as a future direction.

Every mechanism above the "unconditionally `Bound`" floor is self-attested, at the same trust tier as today's plain "supports `Incremental`" flag — more granularity only reduces how often a touch gets needlessly forced `Bound`; it does not increase the strength of the guarantee. The `Probe`/`DeferReads` wire format already has room to grow to finer granularity — per-instruction or per-account — without a protocol change, if a program ever needs it.

### 4.2 Privacy transaction processing by sequencer

1. Proof verification. If proof fails, then the sequencer aborts.
2. Sequencer replays public accounts with `message.public_actions` in order for each entry. This derives the public account states based on the account's current state on-chain. If any update fails (program emits an error or balance update error), then the sequencer reverts the account states and aborts.
3. Provided no errors, the sequencer appends new nullifiers and commitments to the private state, and updates the public accounts.

## 5 Testing

§4.1's soundness rests on the circuit correctly verifying every `Probe`/`Update` receipt and deciding `Bound`/`Deferred` from what it actually attests to, not from what a prover merely claims. The tests here are built around that threat model directly: for each invariant the circuit is supposed to enforce, a purpose-built adversarial guest program lies about exactly the one thing that invariant checks, proven through the ordinary proving pipeline (not hand-spliced receipts), and the corresponding test confirms the circuit rejects it.

**Probe/Update receipt binding** (`lee/state_machine/test_methods/guest/src/bin/`):

| guest program | lies about | closes |
|----|----|----|
| `lying_probe_instruction` | answers `Probe` for a different instruction than the one `Execute` actually received | a prover reusing an unrelated `Probe` receipt to claim coverage it never actually evaluated |
| `lying_probe_self_id` / `lying_probe_caller_id` | `Probe`'s `self_account_id`/`caller_account_id` | a `Probe` receipt being misattributed to the wrong program or the wrong caller |
| `lying_update_self_id` / `lying_update_caller_id` | `Update`'s `self_account_id`/`caller_account_id` | the same misattribution on the resolution side; `Update`'s caller must always be `None` (§4.1 — `Update` is never caller-gated) |
| `lying_update_wrong_account` / `lying_update_wrong_pre_state` | which account, or which `pre_state`, `Update` resolved against | a resolution being silently applied to the wrong account, or computed against a `pre_state` the sequencer never actually fed it |
| `declining_probe` | claims no `Incremental` support at `Probe`, despite implementing `Update` correctly | exactly the write-side gap §4.1 accounts for: a genuine `Update` implementation is not itself sufficient to earn `Deferred` without a covering `Probe` claim |
| `write_only_touches_a_read` / `read_only_touches_a_write` | declares `DeferReads::WriteOnly`/`ReadOnly`, but the call actually makes the other kind of touch | `DeferReads`'s variants actually gate on `is_write`, rather than either variant silently covering everything |

**Settlement replay against live state** (`lee/state_machine/src/validated_state_diff/tests.rs`): a separate suite covers the host-side half of §4.2 — `resolve_public_action`'s replay logic — rather than the circuit's receipt verification:
- `resolve_public_action_replays_a_deferred_action_against_live_state` — the basic end-to-end proof that a `Deferred` action's raw delta actually resolves into a real, host-side balance at all.
- `resolve_public_action_passes_a_bound_action_through_unchanged` / `resolve_public_action_falls_back_to_copy_replace_when_incremental_is_unsupported` — the two straightforward, non-`Deferred` paths.
- `resolve_public_action_replays_multiple_resolutions_in_order` — an account touched by several different `Incremental`-eligible calls in one execution replays each resolution in the order they were recorded, each building on the last.
- `resolve_public_action_reflects_live_state_not_stale_state` / `resolve_public_action_fails_when_live_balance_cannot_cover_a_stale_deferred_debit` — the actual concurrency guarantee, both directions: a `Deferred` resolution replays against whatever the account *actually* holds at settlement, not what it held at proof time, and a resolution that was valid against a since-changed balance correctly fails rather than silently applying anyway. This is exactly case 4 in §6.2.
- `resolve_public_action_rejects_a_write_from_a_program_that_does_not_own_the_account` — the `executing_account_id`/`program_owner` authorization check discussed in §4.1: a resolution is only honored from the program that's actually authorized to write that account's data.

**The `stripped_token`/`stripped_token_robinhood` example from §3, exercised directly** (`lee/state_machine/src/state/tests/incremental_diff.rs`): `stripped_token_transfer_resolves_through_incremental_dispatch` confirms `stripped_token`'s own `Initialize`/`Transfer` correctly resolve through `Incremental` dispatch on the ordinary public-transaction path. Three further tests drive `stripped_token_robinhood` composing with it as a chain call:
- `stripped_token_robinhood_moves_one_unit_from_the_larger_account_to_the_smaller`
- `stripped_token_robinhood_follows_whichever_account_is_actually_larger`
- `stripped_token_robinhood_does_nothing_when_balances_are_equal`

These confirm §3's illustrative example is genuinely correct, not just plausible: `stripped_token_robinhood` reads both accounts' real balances to pick a route, and the chained `Transfer` on `stripped_token` moves the right amount between the right accounts, through the ordinary public-transaction path.

A fourth test, `stripped_token_robinhood_forces_both_accounts_bound` (`lee/state_machine/src/privacy_preserving_transaction/circuit/tests.rs`), drives this same composition through the privacy-preserving circuit itself: robinhood's own uncovered reads force both accounts `Bound`, even though the chained `Transfer` on `stripped_token` — which genuinely implements `Incremental` — resolves for real underneath (asserted on the final balances, not just the classification, so this isn't just both accounts defaulting `Bound` through an unrelated early exit). This is §3's restriction proven end to end through an actual proof, not merely asserted.

**Missing receipts entirely**, as opposed to a receipt that lies: a prover could try to skip supplying a `Probe` or `Update` receipt altogether rather than falsifying one. The `Omit` test harness proves a transaction with the receipt genuinely absent from the queue (not merely unused), covering both:
- `missing_probe_receipt_is_rejected` — no `Probe` receipt queued for a call that touches a public account.
- `missing_update_receipt_is_rejected` — no `Update` receipt queued for a write.

**End-to-end concurrency** (`integration_tests/tests/incremental_update.rs`): `concurrent_private_transfers_settle_against_live_state` exercises the motivating scenario from the introduction directly — two *different* senders privately transfer to the same public, non-signing receiver, both proven and submitted without waiting for the other to settle first, through the real proving pipeline and a live sequencer/indexer stack (not a unit-level circuit call). Both settle correctly against the receiver's live state rather than one invalidating the other's proof — the concrete, observable fix for Bob and Alice's race condition.

**What this leaves unverified.** All of the above proves the circuit rejects a *lying* receipt, or a *missing* one. It does not, and structurally cannot from inside the circuit, prove that an honestly-behaving program's own `Incremental::Update` computes the *correct* resolved value for its own program-specific logic — that correctness is the program author's responsibility, same as `Execute`'s own logic is today. What's protected here is exclusively the protocol-level contract between the circuit and any program: that whatever a program does claim, via `Probe`/`Update`, is bound to the real call it answers for, and that skipping the claim forces the safe (`Bound`) fallback.

## 6 Fees

**Disclaimer**: This section makes minor assumptions concerning fees/collateral based on [conversation](https://discord.com/channels/973324189794697286/1533941404735377428) with Sergio and Marvin.

We assume the existence of a collateral account (independent of the message's intended privacy transaction). This ensures that fees can be collected from a failed privacy transaction.

### 6.1 Public transactions

Public transactions fees for incremental account updates are handled as expected. A transaction is executed and accounts are updated until the fees are exhausted (or the computation is finished). If insufficient fees are provided, then the transaction's updates are reverted. The enforcement primitive this needs already exists and is directly tested (§5): `cycle_budget`/`cycles_used` accounting, where a call's `Execute` and any `Update` resolutions it triggers share one shrinking budget, and exhausting it (`LeeError::OutOfGas`) fails the whole transaction atomically rather than applying it partially. What's not yet wired up is translating a transaction's *paid fee* into that budget — today it's a fixed constant (`DEFAULT_PUBLIC_CYCLE_BUDGET`), not fee-derived.

### 6.2 Privacy transactions

Each privacy transaction emits a proof. This proof provides assurances that the provided `AccountStateDiff`s were generated correctly (based on some `pre_state`). Due to this a privacy transaction with a valid proof may fail. There are five possibilities for a privacy transaction updating LEZ state, in terms of proof validity and fees:

1. Provided proof is invalid.
2. Valid proof, but provided fees are below threshold (rejected before settlement is even attempted).
3. Valid proof, sufficient to attempt settlement, but the budget is exhausted partway through resolving accounts (the same `cycle_budget` mechanism as §6.1, shared across every `Deferred` resolution in the message — see §5).
4. Valid proof, but the `Update` resolution produces an error. E.g., a stale `Deferred` debit the live balance can no longer cover — directly tested, see §5.
5. Valid proof, and sufficient fees provided to update accounts.

Every part of a message associated to an invalid proof cannot be trusted. E.g., sequencer cannot collect fees from such a transaction. Transactions with invalid proofs are simply discarded from mempool. The sequencer can collect fees from transactions from 3-5.

Given a valid proof, the sequencer has some assurance that the fees were generated using some `pre_state`. The `pre_state` could correspond with either public or private accounts

- Private accounts (with a valid proof) guarantee the integrity of the fees. The private account state corresponds with a valid account state commitment. As long as the provided nullifier is new, then fees can be collected.
- Fees from a public account must be checked to ensure that the fees amount can be deducted from this account. Given that the account's balance exceeds the fees amount, the sequencer can begin to proceed.
Once the integrity of the fees has been verified, then the sequencer can begin to apply the `Update` resolution to each account.

3 and 4 fail during the `Update` resolution process. Either the fees are exhausted before accounts are updated, or an `Update` call returns an error. In either case, account states are reverted to their pre-transaction state, except that the fees themselves are still collected.

**Open question/remarks**

- Private accounts that pay fees cannot be partially updated by the sequencer. E.g., either the private account is fully updated by the transaction (fees paid and message execution) or fully reverted. This resulted in the necessity of separate collateral account to pay the fees. Imo: collateral seems unnecessary. We can simply require private accounts used for fees are independent of the desired program's execution.

## 7 Collisions within mempool

Multiple transactions may appear in mempool at a time. Each node needs to be able to prioritize transactions that update the same account.

**This is narrower than it would be without incremental updates.** Two privacy transactions that both touch the same public account as a `Deferred` write are *not* a collision requiring detection or discarding here — under the old, fully-replacing design, any two such transactions would have collided (one's proof would invalidate the other's), needing exactly the kind of priority rule this section is otherwise for. With `Deferred`, both proofs stay valid regardless of processing order; whichever settles first replays against whatever the account then holds, and the second replays against the result of the first. This isn't a guarantee that both actually succeed, though: if the account genuinely can't cover both, the second to settle fails with an ordinary `Update` resolution error (§6.2, case 4) rather than a discarded, invalidated proof — so the conflict is still real, it's just resolved by ordinary settlement-time execution instead of pre-emptive mempool prioritization, and fees remain collectible from the failing side either way.

- **Two transactions in mempool that update the same private account.**
    - Detection: Both transactions include the same nullifier.
    - Criteria: Provided both transactions include a valid proof, the node must discard one of these transactions. The transaction with the higher fees is maintained.
    - Explanation: A valid privacy transaction proof can only be generated by an entity that possesses the account's `nsk`. Higher fees are paid either from the same entity or a member of the shared group owner of the private account.
    The transaction maintained in mempool may still fail due to insufficient fees (2) or error from updating a public account (3). In this case, the private account is not updated at all. Purposeful exploit of this behavior is discouraged through fees.
- **Two transactions in mempool that increment the same public account's nonce.**
    - Detection: `tx1.account_ids[i] == tx2.account_ids[j]` and `tx1.nonces[i] == tx2.nonces[j]` where `account_ids[i]` is a signer for `tx1` and `account_ids[j]` is a signer for `tx2`.
    - Criteria: The transaction with higher fees is maintained.
    - Explanation: Signature authorization can only be done by an authorized party, so the higher fees should be viewed as the deliberate, intended transaction. Purposeful exploit of this behavior is discouraged through fees.

We add a requirement to prevent valid transactions from being removed through grifting. Anti-grift requirement to enter mempool:

- The selected transaction must have payable fees. E.g., for fees from public accounts the node needs to check the accounts' state to verify fees are payable from these accounts. For private accounts, the proof must be valid, and the account paying fees must be independent of the normal execution accounts.
- Any transaction that fails the anti-grift requirement is discarded immediately.

This rule does not guarantee that 3-5 from §6 cannot occur. It guarantees that fees are payable.

**Remarks**

- Shared group accounts could face front-running with this rule. The ramifications of this are program specific.
- Multiple transactions that are submitted to mempool with a future public account nonce re-opens a grifting issue. A "future transaction" can either be (1) processed (at the appropriate time) or (2) replaced by another transaction (by the rules above). When the "future transaction" was appended to mempool, the payable fees passed the anti-grifting requirement. This may have change overtime (as nonces are incremented for the public accounts). Thus, an entity can submit a group of transactions to mempool that pass anti-grifting checks but lack fees.
    - A plausible remedy is to require public accounts `nonce` to match with the known state. E.g., only one transaction using a public account can exist in mempool at a time (by the rules above). This prevents violation of anti-grifting rules. This explicitly forces sequential transactions and disallows pre-queuing. Interestingly, this provides a unified workflow (from user's pov) between public and private states as privacy transactions cannot be pre-queued due to membership proof requirement.

## 8 Analysis

### 8.1 Pros

- Incremental update approach reduces the surface of the account that a program can alter. Programs can directly manipulate an account's balance and data through `AccountStateDiff` (these updates are applied at the protocol-level with the assistance of `post_state` and the program's `Update` resolution). Additionally, the program can claim an account through the claiming mechanism; this is enforced at the protocol-level.
- Mitigates the race condition that affects privacy transactions with respect to public accounts. Updates to a public account used by a privacy transaction (before the privacy transaction is processed) no longer invalidates the proof. Rather, the privacy transaction includes the `AccountStateDiff` for each public account and these are applied to their corresponding account. This does not guarantee that all such privacy transactions will succeed: a provided `AccountStateDiff` and current `pre_state` may produce an error when applied to the appropriate `Update` resolution.
    - Better user experience with privacy transactions in LEZ, as transactions no longer fail merely because an unrelated account update happened to land first.
    - This also narrows mempool collision detection itself, not just proof invalidation after the fact — see §7.
    - Incremental update approach does not address the analogue race condition for private accounts that are updated.
- LEZ program logic only affects `data` and `balance` entries.
- Simplified chain call construction for developers. Chain calls construct program calls using `account_id`s instead of `pre_state`s. This ensures the sequencer (or privacy preserving circuit) can feed in the up to date account state (from the `Update` resolution).
- Removes attack vectors that malicious parties can exploit within LEZ programs: fewer account entries directly accessible, and `account_id` used for chain calls instead of `pre_state` (thus preventing `is_authorized` from being grifted).
- A proposed fees exploit for public transaction executed in the privacy circuit weakened. Plausibly, a complex program logic that affect public accounts (only) could be performed as a privacy transaction. However, with this construction the sequencer must perform the `Update` resolution step for each public account. This reduces the cost savings for such behavior.
- The `Update` resolution provides partial updates making fees collectable from some "failed" privacy transactions.

### 8.2 Cons

- Increased sequencer overhead for privacy preserving circuits. Sequencer must compute updates to public accounts. Under the current design, the sequencer merely replaces public account states (after validating proof).
- Privacy transaction fees are not constant (within a block). Under the current model, the sequencer validates privacy proofs, replaces the public account states (verbatim), and appends nullifiers and commitments to the appropriate digests. An incremental update to a public account is dependent on the account's `program_owner`'s `Update` implementation.
- Program devs parse normal function flow from `pre -> post` to `pre -> delta` and `delta + pre' -> post`. This may be difficult for program flow.
- A painful amount of refactoring of the current code base (lez repo and `lez-programs`).
- Previous internal audits and examinations are out of date.
- Moves rather than eliminates the conflict between two transactions genuinely contending for the same public account: what used to be a mempool-level collision requiring detection and discarding (§7) becomes an ordinary settlement-time `Update` resolution error for whichever transaction settles second. The failure surfaces later in the pipeline, and no longer invalidates a proof, but a genuine conflict still means one of the two fails.

## 9 Deadends

### Incremental updates for all accounts

Incremental updates was originally proposed as the program shape for all programs prior to the release candidate for Testnet 0.3. The program `stripped_token_robinhood` demonstrated that an account's delta is insufficient for enforcing program correctness between privacy execution and sequencer's update. As such, this direction was ditched in favor of opt-in.

### Predicate approach

An extension of incremental updates was for `Execute` functions to emit `predicate_data` that can be checked by the sequencer against by the real accounts' `pre_states`. The `predicate_data` is linked to a specific program's function and the accounts used. The sequencer checks `predicate_data` with current account states using `CheckPredicate`.

In the case of `stripped_token_robinhood`:
- `predicate_data` saves the balances used by `account_1` and `account_2`. This establishes which account was paid the token during the privacy execution (visible from the deltas for the `stripped_token`).
- The sequencer executes `CheckPredicate` along with proof verification. The `CheckPredicate` (optionally) receives account states. The sequencer passes public account states to `CheckPredicate` with the `predicate_data`; private accounts cannot be passed. At the sequencer level it is plausible (but complex) to distinguish between a claimed private account and a public account.
- `CheckPredicate` parses `old_account_1_bal` and `old_account_2_bal` (from `predicate_data`). Additionally, pull `curr_account_i_bal` from the provided account; if `None` provided for `i` then `curr_account_i_bal = old_account_i_bal` (this is safe for private accounts as the correctness is anchored by the provided proof). `CheckPredicate` can verify that the same route be executed by the sequencer as the privacy preserving circuit. If the route diverge, then `CheckPredicate` returns an error.

This example illustrates a few issues with this approach:
- Complex logic for handling the distinction between public and private accounts between sequencer and privacy preserving circuit.
- Complex logic for handling `CheckPredicate`. For certain programs, such as AMM, incremental updates can recompute thresholds which shifts the race condition from the protocol level to the program level. This is possible as AMM relies on `Data` held in a single account, `PoolDefinition` (along with the "delta"). For programs such as `stripped_token_robinhood` the necessary data is held across multiple accounts (neither owned by the program).
- `CheckPredicate` design explicitly acknowledges some accounts may be public or private. This violates a core philosophy of LEE: programs are privacy agnostic.

Due to these results, I do not believe predicate approach is appropriate. It is feasible to gain a little bit more coverage over programs than incremental updates can, but it increases developers' workload with minimal reward. Incremental updates as an opt-in that we discussed introduce in this document offers more benefits with minimal overhead.

## 10 Future directions

### Compressing deferred resolutions

Currently, `resolutions: Vec<DeferredResolution>` carries one entry per `Incremental`-eligible touch on a `Deferred` account, replayed in order at settlement (§4.2). An alternative would compress all of an account's touches into a single entry before committing it to the receipt, so its size stays constant regardless of how many times the account was actually touched. This wasn't adopted for this proposal — and only ever partially could be: `post_balance_diff` is trivially compressible, since `BalanceDiff::Add`/`Sub` amounts from any number of resolutions just sum into one net delta, but `post_data` is not. Each resolution's delta is opaque, program-defined bytes (§2); composing two of them into one still-opaque delta would require the protocol to understand a specific program's own composition rule, which it deliberately doesn't — the same reason the predicate approach in §9 was rejected. So compression, if pursued, could only ever apply to the balance side. Leaving both uncompressed has two accepted costs:

- Receipt size grows with the number of deferred touches on an account, rather than staying constant.
- A privacy execution's program design pattern is observable by counting the resolutions committed per account.
