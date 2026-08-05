# Iterative account update


## 2. Core Types

```rust
pub struct AccountDiff {
    pub id: AccountId,
    pub diff_balance: BalanceDiff,
    pub diff_data: Option<Vec<u8>>, // None signifies no change.
}
```

- `id` — `AccountId` of the account this `AccountDiff` corresponds to.
- `diff_balance` — the net change to `Account.balance`.
- `diff_data` — program specified encoding that describes how `Account.data` is updated.

```rust
pub struct AccountDiffOutput {
    diff: AccountDiff,
    claim: Option<Claim>,
}
```

`AccountDiffOutput` is now a program's actual per-call *output* type (§4), replacing
`AccountPostState`. `claim` carries the same meaning it always has — a program
requesting ownership of a still-`DEFAULT_PROGRAM_ID` account.

### 2.2 `BalanceDiff`

`Account.balance` has identical semantics for every account regardless of owning
program, so applying a balance diff is generic — protocol-level, not
program-authored:

```rust
enum BalanceDiff {
    Add(Balance),
    Sub(Balance),
}
```

```rust
fn apply_balance_diff(current: Balance, diff: BalanceDiff) -> Result<Balance, BalanceDiffError> {
    match diff {
        BalanceDiff::Add(amount) => current.checked_add(amount).ok_or(BalanceDiffError::Overflow),
        BalanceDiff::Sub(amount) => current.checked_sub(amount).ok_or(BalanceDiffError::InsufficientBalance),
    }
}
```

`apply_balance_diff` is what every orchestrator uses, every time a diff is applied
(intra-chain threading, commit-time application) — there's no `compute_balance_diff`
in this design: a program constructs its own `BalanceDiff::Add`/`Sub` directly, as
part of its own instruction logic, the same way it would decide the amount to
transfer. There's no separate "diff two states" step to invent, because there's no
step where a program computes a full new state and then something else diffs it —
the program only ever produces the diff, directly.

## 3 Program design

Incremental account updates introduces a two-path execution flow to LEZ programs:
- `Execute` handles program logic to construct `AccountDiff`s.
- `UpdateFromDiff` specifies how program owned accounts are updated given a `pre_state: Account` and `diff_data: Vec<u8>`. This function outputs `Data`.

### `CallKind` enum

```rust
pub enum CallKind {
    Execute,
    UpdateFromDiff,
}
```

Each LEZ program provides branching logic to handle `Execute` and `UpdateFromDiff`. This ensures that the same program ELF can be used for program calls and updates.

## 4 Protocol-level changes

### 4.1 Current `validate_execution`

LEE supports arbitrary program design. LEE only permits accounts to be updated by the program that "owns" it (e.g., `Account.program_owner = program_id`). This prevents malicious programs from manipulating another program's accounts.

LEE provides several rules (`validate_execution`) that guarantee a given execution's updates to accounts are valid:
1. The output's `pre_states` contain unique account IDs. Each `AccountId` in the list is unique.
2. The output's `pre_states` and `post_states` have the same length N.
3. Program cannot update an account's nonce. For all i in 0..N, pre_states[i].account.nonce == post_states[i].account.nonce.
4. Program cannot change the program owner of an account. For all i in 0..N, pre_states[i].account.program_owner == post_states[i].account.program_owner.
5. Program can only decrease the native token balance for accounts that the program owns. For all i in 0..N, if post_states[i].account.balance < pre_states[i].account.balance, then pre_states[i].account.program_owner == executing_program_id.
6. Program can only change an account's data for accounts that the program owns (or if the account is default). For all i in 0..N, if pre_states[i].account.data != post_states[i].account.data then either pre_states[i].account == Account::default() or pre_states[i].account.program_owner == executing_program_id.
7. Any account that has default program owner after execution must have been a default account before execution. For all i in 0..N, if post_states[i].account.program_owner == DEFAULT_PROGRAM_ID then pre_states[i].account == Account::default().
8. The sum of balances across all pre_states equals the sum across all post_states.

Programs output updates as `post_state: AccountPostState`. The account's `post_state` is a full replacement for the current account's state (based on the provided `pre_state: AccountWithMetadata`). Additionally, `post_state` specifies whether a program execution `claims` the account (indicates how `post_state.account.program_owner` should be set to `program_id` at the Protocol-level).

### 4.2 Proposal changes to `validate_execution`

Incremental account update changes the design paradigm for programs. Programs only specify the updates that are made to an account by outputting `AccountDiffOutput`. This indicates changes to `Account.balance` and `Account.data`, and whether the program `claims` the account.

Programs no longer have the potential to update `program_owner` or `nonce` directly. Thus, we can remove (3), (4), and (7) from the `validate_execution` workflow.
- (3) and (4) are removed because `AccountDiff` has no `nonce`/`program_owner` field at all. Thus, programs cannot alter these account fields.
- (7) is removed. `AccountDiff` does not permit `program_owner` to revert back to `DEFAULT_PROGRAM_ID`. Once a materialized `account.program_owner` is always inherited or overwritten (PDA grifting protection).
The `validate_execution` constraints can be reformulated in terms of `AccountDiff` as:

1. The output's `pre_states` contain unique account IDs. Each `AccountId` in the list is unique.
2. The output's `pre_states` and `post_diff` have the same length N.
3. Program can only decrease the native token balance for accounts that the program owns. For all i in 0..N, if `post_diff.account_diff.diff_balance = Sub(value)` for some `value > 0`, then `pre_states[i].account.program_owner == executing_program_id`.
4. Program can only change an account's data for accounts that the program owns (or if the account is default). For all i in 0..N, if `post_diff.diff_data.is_some()` then either `pre_states[i].account == Account::default()` or `pre_states[i].account.program_owner == executing_program_id`.
5. Across every diff produced by this one call, `sum(Add amounts) == sum(Sub amounts)`.


## 5 Fees

**Disclaimer**: This section makes minor assumptions concerning fees/collateral based on conversation with Sergio and Marvin. (TODO: link the appropriate thread)

We assume that a collateral account (independent of the message's intended privacy transaction). This ensures that fees can be collected from a failed privacy transaction.

### 5.1 Public transactions

Public transactions fees for incremental account updates are handled as expected. A transaction is executed and accounts are updated until the fees are exhausted (or the computation is finished). If insufficient fees are provided, then the transaction's updates are reverted.

### 5.2 Privacy transactions (add reference to Aztec)

Each privacy transaction emits a proof. This proof provides assurances that the provided `AccountDiff`s were generated correctly (based on some `pre_state`). Due to this a privacy transaction with a valid proof may fail. There are four possibilities for privacy transaction updating LEZ state in terms of proof validity and fees:
1. Provided proof is invalid.
2. Valid proof, but insufficient fees provided to update accounts.
3. Valid proof, but `update_from_diff` produces an error.
4. Valid proof, and sufficient fees provided to update accounts.

Every part of a message associated to an invalid proof cannot be trusted. E.g., sequencer cannot collect fees from such a transaction. Transactions with invalid proofs are simply discarded from mempool. The sequencer can collect fees from transactions from 2-4.

Given a valid proof, the sequencer has some assurance that the fees were generated using some `pre_state`. The `pre_state` could correspond with either public or private accounts
- Private accounts (with a valid proof) guarantee the integrity of the fees. The private account state corresponds with a valid account state commitment. As long as the provided nullifier is new, then fees can be collected.
- Fees from a public account must be checked to ensure that the fees amount can be deducted from this account. Given that the account's balance exceeds the fees amoutn, the sequencer can begin to proceed.
Once the integrity of the fees has been verified, then the sequencer can begin to apply `update_from_diff` logic to each account.

2 and 3 fails during the `update_from_diff` process. Either the fees are exhausted before accounts are updated or an update returns Error. In either case, account states are reverted to their pre-transaction state. Except for the fees should be collected/

**Open question/remarks**
- Private accounts that pay fees cannot be partially updated by the sequencer. E.g., either the private account is fully updated by the transaction (fees paid and message execution) or fully reverted. This resulted in the necessity of separate collateral account to pay the fees. Imo: collateral seems unnecessary. We can simply require private accounts used for fees are independent of the desired program's execution.

## 6 Collisions within mempool

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

This rule does not guarantee that 2-3 from Section 5 cannot occur. It guarantees that fees are payable.

**Remarks**
- Shared group accounts could face front-running with this rule. The ramifications of this are program specific.
- Multiple transactions that are submitted to mempool with a future public account nonce re-opens a grifting issue. A "future transaction" can either be (1) processed (at the appropriate time) or (2) replaced by another transaction (by the rules above). When the "future transaction" was appended to mempool, the payable fees passed the anti-grifting requirement. This may have change overtime (as nonces are incremented for the public accounts). Thus, an entity can submit a group of transactions to mempool that pass anti-grifting checks but lack fees.
    - A plausible remedy is to require public accounts `nonce` to match with the known state. E.g., only one transaction using a public account can exist in mempool at a time (by the rules above). This prevents violation of anti-grifting rules. This explicitly forces sequential transactions and disallows pre-queuing. Interestingly, this provides a unified workflow (from user's pov) between public and private states as privacy transactions cannot be pre-queued due to membership proof requirement.


## TODO


Incremental update to accounts fundamentally changes how developers think about program outputs. Instead of constructing the `post_state` account in its entirety, the developer defines how the account's `balance` and `data` entries are updated (and whether the account should be claimed). The updates can later be applied to any (valid) `pre_state` by the sequencer.

Each program define how `data` is handled for their accounts.
- `authenicated-transfer` program: `data` is always taken to be default.
- `Token` program: `data` either defined by Token holding or Token definition.
Due to this, incremental account update imposes a new requirement on developers. Each program must include a function `update_from_diff(pre_state: Account, diff_data: Vec<u8>) -> Result<Data, Error>`.

This isn't just a standalone function to bolt on — `main()` itself changes shape for *every*
program, not only ones with interesting `data`. A single guest ELF now serves two call kinds:
normal execution, and a request to run that program's `update_from_diff`, selected by what the
(trusted) orchestrator writes as input (`read_lee_call`; see "Public transaction workflow" →
"Dispatch: invoking `update_from_diff`" below for the mechanism). Every `main()` becomes a
`match` over `ProgramCall::Execute`/`ProgramCall::UpdateFromDiff` instead of a single unconditional
read — §3.1 shows this concretely, including for a program like `simple_balance_transfer` whose
`update_from_diff` is never actually dispatched to in practice.

Data encoded in `diff_data` is program dependent (and account-type dependent). E.g., Token holding and Token definition accounts hold different data. Thus, these accounts are updated differently. Moreover, certain program's functionalities may rely on auxiliary data (stored in `diff_data`) to guarantee integrity.
- Consider the AMM program. A shielded `swap` produces `AccountDiff`s for token accounts. `Token::update_from_diff` for the token accounts have no context of the AMM program. Thus, valid updates for the token accounts may be formed from an invalid AMM swap logic (based on the sequencer's state of the Pool definition). In this case, `AccountDiff.diff_data` stores auxiliary data concerning the privacy transaction's `pre_state` (of the Pool definition). This ensures that the `AMM::update_from_diff` can construct the values used to generate the swap and check it against the sequencer's provided `pre_state`.
  
If any of the accounts' `update_from_diff` fails, the account states are reverted. Failure can occur due to:
- Insufficient fees to cover the program's execution (function itself, and the `update_from_diff`s).
- Any of the `update_from_diff` returns an Error.

**Observations**
- `update_from_diff` only receives `AccountDiff.diff_data` and only updates the data entry. Protocol-level validation enforces updates to `Account.balance` with `AccountDiff.diff_balance`.
- This design strengthens LEZ security. Programs can no longer update `nonce` or `program_owner` within their execution. This behavior was explicitly blocked at the protocol-level by LEE's security constraints.
  - A benefit of this is a cleaner certain test-programs are no longer necessary (e.g., `nonce_changer`, `program_owner_changer`).

### 3.1 `simple_balance_transfer`

`main()` now has two paths, selected by `read_lee_call`'s `ProgramCall` (§ Public transaction
workflow → Dispatch): the normal `Execute` path (unchanged program logic), and an
`UpdateFromDiff` path that every program's `main()` must handle, even one like this whose own
`update_from_diff` never actually gets dispatched to in practice (see below).

```rust
fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: balance,
        },
        instruction_words,
    ) = match read_lee_call::<Instruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff { pre_state, diff_data } => {
            let data = update_from_diff(pre_state, diff_data)
                .expect("update_from_diff should not fail");
            write_update_from_diff_output(&data);
            return;
        }
    };

    if let Ok([account_pre]) = <[_; 1]>::try_from(pre_states.clone()) {
        let diff = AccountDiff {
            id: account_pre.account_id,
            diff_balance: BalanceDiff::Add(0),
            diff_data: None,
        };
        let account_post = AccountDiffOutput::new_claimed_if_default(
            diff,
            account_pre.account.program_owner,
            Claim::Authorized,
        );

        ProgramOutput::new(
            self_program_id,
            caller_program_id,
            instruction_words,
            pre_states,
            vec![account_post],
        )
        .write();
        return;
    }

    let Ok([sender_pre, receiver_pre]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let sender_diff = AccountDiff {
        id: sender_pre.account_id,
        diff_balance: BalanceDiff::Sub(balance),
        diff_data: None,
    };

    let receiver_diff = AccountDiff{
        id: receiver_pre.account_id,
        diff_balance: BalanceDiff::Add(balance),
        diff_data: None,
    };

    let sender_program_owner = sender_pre.account.program_owner;
    let receiver_program_owner = receiver_pre.account.program_owner;

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![sender_pre, receiver_pre],
        vec![
            AccountDiffOutput::new_claimed_if_default(sender_diff, sender_program_owner, Claim::Authorized),
            AccountDiffOutput::new_claimed_if_default(receiver_diff, receiver_program_owner, Claim::Authorized),
        ],
    )
    .write();
}
```

For `simple_balance_transfer`, the each program's account has `Data::default()`. To ensure this is maintained, the `update_from_diff` is given by:

```rust
fn update_from_diff(_pre_state: Account, _diff_data: Vec<u8>) -> Result<Data, Infallible> {
    Ok(Data::default())
}
```

`Infallible` rather than some opaque `Error`: the body is unconditional, so there's no failure
mode to name — this genuinely cannot fail, not just "hasn't been made to fail yet."

`diff_data = None` (always true for this program's own diffs — it never sets it) should
guarantee `update_from_diff` is never *dispatched to* by the orchestrator in practice. The
`UpdateFromDiff` branch in `main()` above is still real, reachable code, though — reachable by
construction (every `main()` handles both `ProgramCall` variants), just never reached at
runtime for this particular program.


## Public transaction workflow

### `validate_execution`, made diff-native

**Implemented.** `validate_execution` originally compared `pre_states` against a materialized
`post_states: &[Account]` — first a program's own `AccountPostState.account` (pre-`AccountDiff`),
later a `pre.account.clone()` with `apply_balance_diff` applied on top (the interim `AccountDiff`
version). Both required materializing a post-state *before* validation could even run.

`AccountDiff` has no `nonce` or `program_owner` field. A program cannot express a nonce or
ownership change through it — there's nothing to compare, because there's nothing a diff *could*
say about either field. The two rules that used to check `pre.account.nonce != post.nonce` and
`pre.account.program_owner != post.program_owner` are gone entirely, not just made to pass
automatically. Ownership is handled exclusively by the orchestrator's separate claim-eligibility
check; nonce is handled exclusively by the pre-existing replay-protection check on the
transaction itself (the signed `message.nonces` against the account's current on-chain nonce),
which never went through `AccountDiff`/`validate_execution` in the first place.

**Full constraint list**, as of the diff-native rewrite (`lee_core::program::validate_execution`,
checked in this order):

1. **Unique account ids** — `pre_states` can't reference the same account twice.
   (`PreStateAccountIdsNotUnique`)
2. **Matching lengths** — `pre_states.len() == post_diff.len()`.
   (`MismatchedPreStatePostStateLength`)
3. **Authorized balance decrease** — a diff can only carry a real (`amount > 0`) `Sub` on an
   account the executing program owns. (`UnauthorizedBalanceDecrease`)
4. **Authorized data modification** — `diff_data` can only be `Some` on an account the executing
   program owns, unless the account is still fully `Account::default()` (first write, no owner
   yet to be unauthorized against). (`UnauthorizedDataModification`)
5. **Conserved balance** — across every diff produced by this one call,
   `sum(Add amounts) == sum(Sub amounts)`. (`BalanceSumOverflow` on overflow while summing,
   `MismatchedTotalBalance` on a real mismatch)

Two more constraints used to be explicit runtime checks here and no longer are — not because
they're skipped, but because `AccountDiff` can't express the thing they used to guard against:
nonce can never change via a diff (no `nonce` field on `AccountDiff`), and ownership can never
change via a diff either (no `program_owner` field) — ownership moves exclusively through the
separate claim-eligibility check, covered below.

The remaining rules (3-5 above) are re-derived straight from `AccountDiff`, needing no
materialized post-state at all:

| Rule | Old (materialized) | New (diff-native) |
|---|---|---|
| Unauthorized balance decrease | `post.balance < pre.account.balance` | `matches!(diff.diff_balance, BalanceDiff::Sub(amount) if amount > 0)` |
| Unauthorized data modification | `pre.account.data != post.data` | `diff.diff_data.is_some()` |
| Total balance conserved | `sum(pre.balance) == sum(post.balance)` | `sum(Add amounts) == sum(Sub amounts)` across the call's diffs |

`validate_execution`'s signature changed from `(pre_states, post_states: &[Account],
executing_program_id)` to `(pre_states, post_states: &[AccountDiffOutput], executing_program_id)`
— it reads only `diff_output.diff()` per account, never a materialized `Account`.

**Payoff:** since neither `validate_execution` nor claim-eligibility need a materialized
post-state anymore, materialization can move to strictly *last* in the per-call loop — see
"Where dispatch happens in the pipeline" below. That's what lets the `update_from_diff` dispatch
target be resolved unambiguously: the account's final owner for the call, post-claim, is already
known by the time materialization runs.

Two existing tests (`insufficient_balance`,
`program_should_fail_if_modifies_data_of_non_owned_account`) had account setups baking in two
conditions at once (e.g. "unclaimed" *and* "insufficient balance"), relying on the old rule
*order* to pick out which one surfaced first. Making `validate_execution` diff-native exposed
this — reordering the checks changed which error fired even though neither test's actual target
condition changed. Fixed by rewriting each test's initial account state to isolate exactly the
one condition it's meant to exercise.

### Dispatch: invoking `update_from_diff`

**Implemented.** `update_from_diff` is not a separately-registered artifact. It lives in the
*same* guest ELF as the program's normal execution logic, and is invoked as a second
entrypoint within that same `main()`, selected by what the (trusted) orchestrator writes as
input. No second `Program`, no new registry — `V03State`'s existing
`programs: HashMap<ProgramId, Program>` is reused as-is; the orchestrator already looks a
program up by id to execute it. `simple_balance_transfer` and `data_changer` both dispatch
through this path today; `program_should_successfully_update_data_via_update_from_diff`
(`state/tests/public_program_rules.rs`) exercises it end to end.

```rust
// lee_core::program
enum CallKind {
    Execute,
    UpdateFromDiff,
}

enum ProgramCall<T> {
    Execute(ProgramInput<T>, InstructionData),
    UpdateFromDiff { pre_state: Account, diff_data: Vec<u8> },
}

fn read_lee_call<T: DeserializeOwned>() -> ProgramCall<T> {
    match env::read() {
        CallKind::Execute => { /* the old read_lee_inputs body */ }
        CallKind::UpdateFromDiff => {
            let pre_state: Account = env::read();
            let diff_data: Vec<u8> = env::read();
            ProgramCall::UpdateFromDiff { pre_state, diff_data }
        }
    }
}

fn write_update_from_diff_output(data: &Data) {
    env::commit(data);
}
```

Every guest `main()` becomes one match over the call kind, instead of two separately-callable
(and separately forgettable) read functions:

```rust
fn main() {
    match read_lee_call::<Instruction>() {
        ProgramCall::Execute(input, instruction_words) => {
            // existing logic, unchanged
        }
        ProgramCall::UpdateFromDiff { pre_state, diff_data } => {
            let data = update_from_diff(pre_state, diff_data)
                .expect("update_from_diff should not fail"); // guest failure = execution
                                                               // failure, same as today
            write_update_from_diff_output(&data);
        }
    }
}
```

No discriminant is needed on the *output* side — the host always knows which mode it
invoked (`Program::execute` vs. `Program::execute_update_from_diff`), so it decodes the
journal as the type it expects directly: `ProgramOutput` for `Execute`, `Data` for
`UpdateFromDiff`.

The mode is chosen exclusively by the orchestrator, never derived from a caller-supplied
`instruction_data`. This matters: conflating the two channels would let a malicious calling
program trick a callee into running its `update_from_diff` path instead of its real logic.

### Where dispatch happens in the pipeline

**Implemented**, in `ValidatedStateDiff::from_public_transaction`'s materialize step
(`validated_state_diff/mod.rs`). Materialization — where `update_from_diff` actually runs —
comes last in the per-call loop, strictly after both `validate_execution` (made diff-native
above) and claim-eligibility. Both of those are fully diff-native and never need a materialized
post-state, so there's no ordering hazard in leaving materialization for the end. By the time
it runs, the account's *final* owner for this call is already known — either its pre-existing
`program_owner` (if non-default), or the program that was just validated to claim it — so
dispatch never has to guess who to call.

```rust
let owner_id = owner.unwrap_or(pre.account.program_owner);
let owner_program = state.programs().get(&owner_id).ok_or(
    InvalidProgramBehaviorError::NoOwnerProgramForDataUpdate { account_id: pre.account_id },
)?;
post.data = owner_program.execute_update_from_diff(pre.account.clone(), diff_data)?;
```

One thing the earlier draft got wrong: a missing owner program isn't an `.expect()`-worthy
invariant — it's a reachable, adversary-controlled case (a diff can legally carry `diff_data`
on a still-`Account::default()` account without a claim; `validate_execution` rule 4 allows it,
and `DefaultAccountModifiedWithoutClaim` only catches it *after* this loop). It's handled as a
real error (`NoOwnerProgramForDataUpdate`), not a host panic.

## Privacy transaction workflow

## Dormant tests no longer needed for `AccountDiff`

Some dormant test programs in `test_methods/guest/src/dormant/` are not being migrated to
`AccountDiff`/`read_lee_call`, not because migration is deferred, but because what they tested is
no longer a meaningful, independent risk under this design. Tracked here rather than silently
dropped, so the reasoning survives even though the program stays dormant.

- **`malicious_authorization_changer`** — tried to forge `is_authorized: true` for an account it
  doesn't control. Not exploitable: a program can no longer output a `pre_state` at all, only an
  `AccountDiffOutput` (`diff_balance`, `diff_data`, `claim`), so there's no channel for a program
  to change an account's authorization.
- **`nonce_changer`** — directly incremented `account_post.nonce`. `AccountDiff` has no `nonce`
  field, so a program has no channel to change it.
- **`program_owner_changer`** — directly set `account_post.program_owner`. `AccountDiff` has no
  `program_owner` field either; ownership only ever moves through the claim mechanism now.
- **`modified_transfer_program`** — skipped its own balance check, relying on protocol-level
  conservation to catch the overflow. `apply_balance_diff` now applies checked arithmetic to
  every diff unconditionally, so this no longer depends on the program at all.

## Analysis

### Pros
- Incremental update approach reduces the surface of the account that a program can alter. Programs can directly manipulate an account's balance and data through `AccountDiff` (these updates are applied at the protocol-level with the assistance of `apply_balance_diff` and the program's `update_from_diff`). Additionally, the program can claim an account through the claiming mechanism; this is enforced at the protocol-level.
- Migitates the race condition that affects privacy transactions with respect to public accounts. Updates to a public account used by a privacy transaction (before the privacy transaction is processed) no longer invalidates the proof. Rather, the privacy transaction includes the `AccountDiff` for each public account and these are applied to their corresponding account. This does not guarantee that all such privacy transactions will succeed: a provided `AccountDiff` and current `pre_state` may produce an error when applied to the appropriate `update_from_diff`.
  - Incremental update approach does not address the analogue race condition for private accounts that are updated.

### Cons
- Privacy transaction fees are not constant (within a block). Under the current model, the sequencer validates privacy proofs, replaces the public account states (verbatim), and appends nullifiers and commitments to the appropriate digests. An incremental update to a public account is dependent on the account's `program_owner`'s `update_from_diff`. 
- A painful amount of refactoring of the current code base.