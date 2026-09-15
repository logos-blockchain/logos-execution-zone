# Incremental update proposal

Privacy-preserving executions are executed and proven locally in Risc0. The proof is bundled in a privacy transaction (with the relevant data). The sequencer verifies the proof against the chain's state and the provided data. Specifically, the sequencer uses the current state of each public account used in the privacy transaction. Validation fails when any of the public accounts' states differ from the ones used during proof generation. Thus, inducing a **race condition** in LEZ for privacy transactions.

Consider the example:

- Bob initializes a deshielded transfer to send Alice 5 tokens from his private account to her public account with state (`pub_alice_0`) known to him.
- During either Bob's proving time or while Bob's privacy transaction is sitting in mempool, Alice submits a public transaction that updates her account state (`pub_alice_1`).
- Once the sequencer attempts to validate Bob's transaction, Alice's account state (in LEZ) is `pub_alice_1` and not `pub_alice_0`. The transaction's proof verification fails. Thus, the sequencer rejects Bob's transaction.

The race condition is a consequence of LEE transaction design: LEE transactions (public and privacy) "fully" replace account states rather than simply update the entries. This race condition only exists for privacy transactions that touch a public account.

In this document, we propose a new LEZ program type that emits updates (for specified accounts) and applies an update to any given pre state. This design is an optional program type that developers can choose to use.

## 1 Big idea: incremental account update

LEZ programs consist of a match call for `ProgramCall` types. Currently, LEZ only supports `ProgramCall:Execute`. E.g., LEZ program's `main` calls each of the program's function within `ProgramCall::Execute`.

We propose adding `ProgramCall::Incremental` as a new call type. A developer that chooses to support incremental updates would adopt a different paradigm in their program design: `ProgramCall::Execute` generates the change, delta, in account data and `ProgramCall::Incremental` applies the delta to a provided account state's data.


| type | workflow |
|----|----|
| regular program | `ProgramCall::Execute` given `pre_states` and outputs data. This data is verbatim replaces the `pre_states`' data.|
| incremental program | `ProgramCall::Execute` given `pre_states` and outputs data. <br>`ProgramCall:Incremental` takes `data` and an account's `pre_state`. The program's logic determines how `data` and `pre_state.data` interact with each other to produce the account's new `data`. </br>
|

Incremental provides an alternative to `Account.data` updates. This design allows LEZ programs to output `data` that can be applied to a different `pre_state`. This is crucial for privacy transactions that touch a public account.

**How is `Incremental` handled by transaction types?**

- Public transactions. Sequencer executes both `Execute` (program call) and `Incremental` in sequence.
- (Fully) Private transactions. `Execute` and `Incremental` is handled entirely (in sequence) in Risc0.
- Privacy transactions. `Execute` and `Incremental` is handled (in sequence) in Risc0. Additionally, for each public account (based on `InputAccountIdentity` in the `privacy_preserving_circuit`) the updates are accumulated (per account) and included in the transaction's receipt. The sequencer applies these updates to the public account's current state (using `Incremental`).

## 2 Program design that supports incremental updates

This section describes the program shape required to support incremental updates. Programs are not required to support incremental updates.

- `Execute` handles program logic that is directly called by a transaction's `Message`.
- `Incremental` resolves one account's `data` at a time, given that account's state and `delta: Data`. To facilitate this and an incremental support check, `Incremental` supports the instruction shape `IncrementalCall { Probe, Update(delta) }`:
    - `Probe` provides a mechanism to establish whether a program supports `Incremental`. Support is inferred by the caller from the absence of an `UnsupportedCallKind` event.
    - `Update(delta)` is the actual resolution: given `pre_state.data` and the opaque, program-defined `delta` bytes, produce the account's new `data`.
    - A program that doesn't recognize this `Probe`/`Update` envelope at all falls back to `UnsupportedCallKind`. This is indistinguishable from a program that does not implement `Incremental`.

**Remarks**
- The use of `ProgramCall` ensures that the same program's ELF can be used for both program calls and updates.
- `Incremental`'s logic cannot be specified by a transaction's `Message`. Rather, `Incremental` is called by the sequencer and privacy preserving circuit to update an account's state.
- Incremental programs and regular programs emit outputs that possess the same shape. However, the logic used to update an account's data entry is different.

## 3 Protocol-level changes

A LEZ program can invoke another program through chain calls; for example, a program can invoke an `Incremental`-supporting program as part of its own logic. The caller's decisions are often based on the `pre_states` (and `instruction_data`) it was provided.

Consider two programs: `incremental_simple_token` and `robinhood_token_exchange`.
- **`incremental_simple_token`**: a simplified program that handles a token balance within its account's `data` field; no support for separate token definitions. The program (`Execute`) handles `initialize` and `transfer`, and `Incremental` to handle token balance changes (held in `data`).
- **`robinhood_token_exchange`**: swaps 1 token between two accounts; the account with the higher token balance pays a token to the other token account. `robinhood_token_exchange` program invokes `incremental_simple_token` as a chaincall for transfer. `robinhood_token_exchange`'s implementation does not support `Incremental`.

The correctness of `robinhood_token_exchange` requires the input (token) accounts to be anchored to the LEZ's state. E.g., the proof for privacy execution of `robinhood_token_exchange` requires the `pre_states` used in the execution to validate. This guarantees that the correct account receives the token. Thus, the correctness of `robinhood_token_exchange` relies on blocking  `incremental_simple_token` from taking advantage of incremental updates at the sequencer level.

This example illustrates the need for restrictions for incremental updates in the privacy preserving circuit: any public account used by a regular program (one with no `Incremental` support), or merely *read* (no `post_data`) by any program regardless of its `Incremental` support, cannot defer its update. A read can drive a decision elsewhere in the call chain, as with `robinhood_token_exchange`, and a program's own `Incremental` support doesn't prove that decision is safe. Both cases anchor the account to LEZ's current state.


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
- Public accounts are materialized within the circuit the same way. This guarantees that resolved values can be used as the `pre_state` for consecutive chain calls. What's actually recorded in the execution's receipt per public account depends on how the account was used:
    - **A write** (`post_data.is_some()`) by a program that implements `Incremental::Update`, checked by attempting `Update` and detecting the absence of an `UnsupportedCallKind` event, appends a `DeferredResolution` (the raw delta) to that account's `resolutions` list, committed as `PublicAction::Deferred { account_id, resolutions }`.
    - **Everything else** resolves the account fully in-circuit and forces `PublicAction::Bound { pre, post }`; `pre` anchors the account to a specific `pre_state`, checked against live chain state by the sequencer. This includes a write declined via `UnsupportedCallKind`, and any read-only touch (`post_data.is_none()`, checked via `Probe`), regardless of the reading program's own `Incremental` support.
    - Once any touch on an account is forced `Bound`, the account stays `Bound` for the rest of the execution: its pending `resolutions` are discarded (their effect is already reflected in the account's internally-tracked resolved value; only what gets *emitted* changes), even if a later touch is itself `Incremental`-eligible.

This is the restricted baseline: a read-only touch is never left `Deferred`, regardless of the reading program's own `Incremental` support.

### 4.2 Privacy transaction processing by sequencer

1. Proof verification. If proof fails, then the sequencer aborts.
2. Sequencer replays public accounts with `message.public_actions` in order for each entry. This derives the public account states based on the account's current state on-chain. If any update fails (program emits an error or balance update error), then the sequencer reverts the account states and aborts.
3. Provided no errors, the sequencer appends new nullifiers and commitments to the private state, and updates the public accounts.

## 6 Fees

**Disclaimer**: This section makes minor assumptions concerning fees/collateral based on [conversation](https://discord.com/channels/973324189794697286/1533941404735377428) with Sergio and Marvin.

We assume that a collateral account (independent of the message's intended privacy transaction). This ensures that fees can be collected from a failed privacy transaction.

### 6.1 Public transactions

Public transactions fees for incremental account updates are handled as expected. A transaction is executed and accounts are updated until the fees are exhausted (or the computation is finished). If insufficient fees are provided, then the transaction's updates are reverted.

### 6.2 Privacy transactions

Each privacy transaction emits a proof. This proof provides assurances that the provided `AccountDiff`s were generated correctly (based on some `pre_state`). Due to this a privacy transaction with a valid proof may fail. There are four possibilities for privacy transaction updating LEZ state in terms of proof validity and fees:

1. Provided proof is invalid.
2. Valid proof, but provided fees are below threshold.
3. Valid proof, but insufficient fees provided to update accounts.
4. Valid proof, but `update_from_diff` produces an error.
5. Valid proof, and sufficient fees provided to update accounts.

Every part of a message associated to an invalid proof cannot be trusted. E.g., sequencer cannot collect fees from such a transaction. Transactions with invalid proofs are simply discarded from mempool. The sequencer can collect fees from transactions from 3-5.

Given a valid proof, the sequencer has some assurance that the fees were generated using some `pre_state`. The `pre_state` could correspond with either public or private accounts

- Private accounts (with a valid proof) guarantee the integrity of the fees. The private account state corresponds with a valid account state commitment. As long as the provided nullifier is new, then fees can be collected.
- Fees from a public account must be checked to ensure that the fees amount can be deducted from this account. Given that the account's balance exceeds the fees amoutn, the sequencer can begin to proceed.
Once the integrity of the fees has been verified, then the sequencer can begin to apply `update_from_diff` logic to each account.

3 and 4 fails during the `update_from_diff` process. Either the fees are exhausted before accounts are updated or an update returns Error. In either case, account states are reverted to their pre-transaction state. Except for the fees should be collected/

**Open question/remarks**

- Private accounts that pay fees cannot be partially updated by the sequencer. E.g., either the private account is fully updated by the transaction (fees paid and message execution) or fully reverted. This resulted in the necessity of separate collateral account to pay the fees. Imo: collateral seems unnecessary. We can simply require private accounts used for fees are independent of the desired program's execution.

## 7 Collisions within mempool

Multiple transactions may appear in mempool at a time. Each node needs to be able to prioritize transactions that update the same account.

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

This rule does not guarantee that 3-5 from Section 5 cannot occur. It guarantees that fees are payable.

**Remarks**

- Shared group accounts could face front-running with this rule. The ramifications of this are program specific.
- Multiple transactions that are submitted to mempool with a future public account nonce re-opens a grifting issue. A "future transaction" can either be (1) processed (at the appropriate time) or (2) replaced by another transaction (by the rules above). When the "future transaction" was appended to mempool, the payable fees passed the anti-grifting requirement. This may have change overtime (as nonces are incremented for the public accounts). Thus, an entity can submit a group of transactions to mempool that pass anti-grifting checks but lack fees.
    - A plausible remedy is to require public accounts `nonce` to match with the known state. E.g., only one transaction using a public account can exist in mempool at a time (by the rules above). This prevents violation of anti-grifting rules. This explicitly forces sequential transactions and disallows pre-queuing. Interestingly, this provides a unified workflow (from user's pov) between public and private states as privacy transactions cannot be pre-queued due to membership proof requirement.

## 8 Analysis

### 8.1 Pros

- Incremental update approach reduces the surface of the account that a program can alter. Programs can directly manipulate an account's balance and data through `AccountDiff` (these updates are applied at the protocol-level with the assistance of `apply_balance_diff` and the program's `update_from_diff`). Additionally, the program can claim an account through the claiming mechanism; this is enforced at the protocol-level.
- Migitates the race condition that affects privacy transactions with respect to public accounts. Updates to a public account used by a privacy transaction (before the privacy transaction is processed) no longer invalidates the proof. Rather, the privacy transaction includes the `AccountDiff` for each public account and these are applied to their corresponding account. This does not guarantee that all such privacy transactions will succeed: a provided `AccountDiff` and current `pre_state` may produce an error when applied to the appropriate `update_from_diff`.
    - Better user experience with privacy transactions in LEZ as
    - Incremental update approach does not address the analogue race condition for private accounts that are updated.
- LEZ program logic only affects `data` and `balance` entries.
- Simplified chain call construction for developers. Chain calls construct program calls using `account_id`s instead of `pre_state`s. This ensures the sequencer (or privacy preserving circuit) can feed in the up to date account state (from `UpdateFromDiff`).
- Removes attack vectors that malicious parties can exploit within LEZ programs: fewer account entries directly accessible, and `account_id` used for chain calls instead of `pre_state` (thus preventing `is_authorized` from being grifted).
- A proposed fees exploit for public transaction executed in the privacy circuit weakened. Plausibly, a complex program logic that affect public accounts (only) could be performed as a privacy transaction. However, with this construction the sequencer must perform the `UpdateFromDiff` step for each public account. This reduces the cost savings for such behavior.
- `UpdateFromDiff` provides partial updates making fees collectable from some "failed" privacy transactions.

### 8.2 Cons

- Increased sequencer overhead for privacy preserving circuits. Sequencer must compute updates to public accounts. Under the current design, the sequencer mere replaces public account states (after validating proof).
- Privacy transaction fees are not constant (within a block). Under the current model, the sequencer validates privacy proofs, replaces the public account states (verbatim), and appends nullifiers and commitments to the appropriate digests. An incremental update to a public account is dependent on the account's `program_owner`'s `update_from_diff`.
- Program devs parse normal function flow from `pre -> post` to `pre -> delta` and `delta + pre' -> post`. This may be difficult for program flow.
- A painful amount of refactoring of the current code base (lez repo and `lez-programs`).
- Previous internal audits and examinations are out of date.

## 9 Implementation strategy

- **PR 1 — additive core types only.** `AccountDiff`, `AccountDiffOutput`, `BalanceDiff`,
`apply_balance_diff`, `ProgramCall`/`CallKind`/`read_lee_call` land in `lee_core`/`lee`.
    - Add unit tests for these `AccountDiff`, `BalanceDiff`, `apply_balance_diff`.
    - *Depends on: nothing.*
- **PR 2 — incremental update wiring.** Program logic is updated to use `AccountDiff`, but the diffs are applied immediate. Thus, producing `post_states` within the circuit an d Protocol-level checks. This enables program and test changes to be done without major changes to the protocol.
    - **PR2.1**: Public logic wiring and public tests from `test-methods`.
    - **PR2.2**: Privacy logic wiring and privacy tests from `test-methods`.
- **PR 3 — privacy protocol adjustment.** **Update circuit to handle `AccountDiff` logic within the privacy preserving circuit. Public accounts are compressed as `post_state`s before emitting to the sequencer.
- **PR 4 — public protocol adjustment**. Update public Protocol to update accounts using `AccountDiff`.
    - **PR4.1**: Update each LEZ program relied on by the indexer.
    - **PR4.2**: Indexer/indexer-ffi updates.
- **PR 5 - remove dead code.**
    - Remove `AccountPostState` and orphaned unit tests as well as unnecessary `test-methods`.

The interconnectness of program output logic makes this proposal ambitious with respect to the engineering perspective. Thus, resulting in a PR2 that is hard to parse into smaller pieces.

## 10 Deadends

### Incremental updates for all accounts

Incremental updates was originally proposed as the program shape for all programs prior to the release candidate for Testnet 0.3. The program `robinhood_token_exchange` demonstrated that an account's delta is insufficient for enforcing program correctness between privacy execution and sequencer's update. As such, this direction was ditched in favor of opt-in.

### Predicate approach

An extension of incremental updates was to for `Execute` functions to emit `predicate_data` that can be checked by the sequencer against by the real accounts' `pre_states`. The `predicate_data` is linked to a specific program's function and the accounts used. The sequencer checks `predicate_data` with current account states using `CheckPredicate`.

In the case of `robinhood_token_exchange`:
- `predicate_data` saves the balances used by `account_1` and `account_2`. This establishes which account was paid the token during the privacy execution (visible from the deltas for the `incremental_token_program`).
- The sequencer executes `CheckPredicate` along with proof verification. The `CheckPredicate` (optionally) receives account states. The sequencer passes public account states to `CheckPredicate` with the `predicate_data`; private accounts cannot be passed. At the sequencer level it is plausible (but complex) to distinguish between a claimed private account and a public account.
- `CheckPredicate` parses `old_account_1_bal` and `old_account_2_bal` (from `predicate_data`). Additionally, pull `curr_account_i_bal` from the provided account; if `None` provided for `i` then `curr_account_i_bal = old_account_i_bal` (this is safe for private accounts as the correctness is anchored by the provided proof). `CheckPredicate` can verify that the same route be executed by the sequencer as the privacy preserving circuit. If the route diverge, then `CheckPredicate` returns an error.

This example illustrates a few issues with this approach:
- Complex logic for handling the distinction between public and private accounts between sequencer and privacy preserving circuit.
- Complex logic for handling `CheckPredicate`. For certain programs, such as AMM, incremental updates can recompute thresholds which shifts the race condition from the protocol level to the program level. This is possible as AMM relies on `Data` held in a single account, `PoolDefinition` (along with the "delta"). For programs such as `robinhood_token_exchange` the necessary data is held across multiple accounts (neither owned by the program).
- `CheckPredicate` design explicitly acknowledges some accounts may be public or private. This violates a core philosophy of LEE: programs are privacy agnostic.

Due to these results, I do not believe predicate approach is appropriate. It is feasible to gain a little bit more coverage over programs than incremental updates can, but it increases developers' workload with minimal reward. Incremental updates as an opt-in that we discussed introduce in this document offers more benefits with minimal overhead.

## 11 Future directions

### Compressing deferred resolutions

Currently, `resolutions: Vec<DeferredResolution>` carries one entry per `Incremental`-eligible touch on a `Deferred` account, replayed in order at settlement (§4.2). An alternative would compress all of an account's touches into a single entry before committing it to the receipt, so its size stays constant regardless of how many times the account was actually touched. This wasn't adopted for this proposal; the current, uncompressed design has two accepted costs:

- Receipt size grows with the number of deferred touches on an account, rather than staying constant.
- A privacy execution's program design pattern is observable by counting the resolutions committed per account.

## 12 Read-only account classification for `Deferred`/`Bound`

A read-only touch (`post_data: None`) on a public account by an `Incremental`-supporting program still needs a `Bound`/`Deferred` decision — the read can drive a decision elsewhere in the call chain (see §3's `robinhood_token_exchange` discussion), and that decision is only safe to leave unanchored if the read itself was safe to leave unanchored. Two mechanisms were tried and superseded before landing on the staged plan below:

- **Per-account write-backing reconciliation** (`verified_incremental_writers`/`trusted_readers`, an earlier revision of §4.1): forced `Bound` unless the reading program also had its own verified `Incremental::Update` write to the same account, somewhere in the execution. This closes the case where a *different* program's write incorrectly "covers" for another program's unrelated read, but not the case where the *same* program has an unrelated, incidental write to the account it's reading — a write's existence doesn't prove it's related to, or supersedes, whatever the read was used for.
- **Re-executing `Execute` with a placeholder** (comparing two receipts to prove a decision doesn't depend on a specific account's content): the only mechanism found that gives a cryptographic, rather than self-attested, guarantee. Rejected because it requires the protocol to reason about `Execute`'s behavior for every program, not just `Incremental`-opted-in ones — against the design principle (§10) that this feature stays fully opt-in and inert for a program that never implements `Incremental`.

Given no mechanism gets past self-attestation without touching `Execute`, the plan is staged by granularity instead. Every step reuses the same `Probe` call and sits at the same trust tier — self-attested, `Bound` as the default fallback:

1. **Restricted (shipped baseline).** Every read-only touch is unconditionally `Bound`. No claim, no trust required — the conservative floor every later step opts out of.
2. **Program-level.** `Probe`'s response carries a marker (an event, the same pattern as `UnsupportedCallKind`) declaring `DeferReads` for the whole program — present means every read-only touch by this program is asserted safe to leave `Deferred`; absent falls back to step 1's `Bound`. The guest can ignore `self_account_id`, `instruction_data`, and `pre_states` entirely — one static, program-wide answer.
3. **Function-level (documented now, not implemented).** `IncrementalCall::Probe` carries `instruction_data` — the same payload the original `Execute` call received — from the moment step 2 ships, even though a step-2 guest never needs to look at it. A program can later start dispatching on it to answer per-instruction instead of program-wide, with *no* wire-format or protocol change: the plumbing already exists.
4. **Account-level.** Not scoped yet, but already structurally free: `self_account_id` is already part of every `Incremental` call, including `Probe`, so a guest could already answer differently per account today if it chose to.

Steps 2 through 4 are the same trust tier as each other — self-attested, exactly like today's plain "supports `Incremental`" flag. Increasing granularity only reduces how often a read gets needlessly forced `Bound`; it does not increase the strength of the guarantee. Only step 1 requires no trust in the program's own claim.