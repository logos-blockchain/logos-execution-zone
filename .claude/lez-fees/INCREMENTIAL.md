Privacy-preserving executions are executed and proven locally in Risc0. The proof is bundled in a privacy transaction (with the relevant data). The sequencer verifies the proof against the chain's state and the provided data. Specifically, the sequencer uses the current state of each public account used in the privacy transaction. Validation fails when any of the public accounts' states differ from the ones used during proof generation. Thus, inducing a **race condition** in LEZ for privacy transactions.

Consider the example:

- Bob initializes a deshielded transfer to send Alice 5 tokens from his private account to her public account with state (`pub_alice_0`) known to him.
- During either Bob's proving time or while Bob's privacy transaction is sitting in mempool, Alice submits a public transaction that updates her account state (`pub_alice_1`).
- Once the sequencer attempts to validate Bob's transaction, Alice's account state (in LEZ) is `pub_alice_1` and not `pub_alice_0`. The transaction's proof verification fails. Thus, the sequencer rejects Bob's transaction.

The race condition is a consequence of LEE transaction design. LEE transactions (public and privacy) "fully" replace account states rather than simply update the entries. This approach is acceptable for public-only and private-only transactions. However, this design is detrimental for hybrid transactions (as described above).

In this document, we propose account state diffs to facilitate incremental updates to account states.

## 1 Big idea: incremental account update

We propose change to LEZ program design. Instead of LEZ programs emitting new account states, LEZ programs emit the changes that should be applied to the account. This enables LEZ programs to output updates that are "independent" of the input account's `pre_state`. This is crucial for hybrid accounts.

LEZ programs consist of two modes:

- `Execute` is used for the usual program logic that is called by a transaction's execution.
- `UpdateFromDiff` consist of the program-specific logic to apply updates to a given account.

**How are updates to an account handled?**

- Desired balance changes are recorded; e.g., amount and operation (add or subtracted) from the account's balance.
- Desired changes to `data` field. The logic for updating `data` is program-defined.

**How is `UpdateFromDiff` handled by transaction types?**

- Public transactions. Sequencer executes both `Execute` (program call) and `UpdateFromDiff`. The sequencer applies updates for each account using `UpdateFromDiff` (for each program call).
- (Fully) Private transactions. `Execute` and `UpdateFromDiff` is handled entirely in Risc0.
- Privacy transactions. `Execute` and `UpdateFromDiff` is handled in Risc0. Additionally, for each public account (based on `InputAccountIdentity` in the `privacy_preserving_circuit`) the updates are accumulated (per account) and included in the transaction's reciept. The sequencer applies these updates to the public account's current state.

## 2 Core Types

### 2.1 `AccountDiff` and `AccountDiffOutput`

Programs produce updates to accounts as `AccountDiff`. This interface is defined:

`AccountDiff` is the common interface that LEZ emit.

```rust
pub struct AccountDiff {
    pub id: AccountId,
    pub diff_balance: BalanceDiff,
    pub diff_data: Option<Data>, // None signifies no change.
}
```

- `id` — `AccountId` of the account this `AccountDiff` corresponds to.
- `diff_balance` — the net change to `Account.balance`.
- `diff_data` — program specified encoding that describes how `Account.data` is updated.

`AccountDiffOutput` is the program output wrapper:

```rust
pub struct AccountDiffOutput {
    diff: AccountDiff,
    claim: Option<Claim>,
}
```

This wrapper is the replacement for `AccountPostState`; handles the claiming mechanism. As such the functions for `AccountDiffOutput` are adapted from `AccountPostState`:

- `new(diff)` — no claim.
- `new_claimed(diff, claim)` — unconditional claim request.
- `new_claimed_if_default(diff, pre_state_program_owner, claim)` — claims only if the account
is unowned.
- `diff()`/`diff_mut()` and `required_claim()` read the two fields back out.

### 2.2 `BalanceDiff`

Native token `Balance` has Protocol-level semantics that applies to all accounts (regardless of `program_owner`). Programs can only indicate the amount that an account is either increased or decrease. This is indicated with `BalanceDiff`:

```rust
enum BalanceDiff {
    Add(Balance),
    Sub(Balance),
}
```

At Protocol-level (either by the sequencer or in `privacy_preserving_circuit`) the `Account.balance` is updated with:

```rust
fn apply_balance_diff(current: Balance, diff: BalanceDiff) -> Result<Balance, BalanceDiffError> {
    match diff {
        BalanceDiff::Add(amount) => current.checked_add(amount).ok_or(BalanceDiffError::Overflow),
        BalanceDiff::Sub(amount) => current.checked_sub(amount).ok_or(BalanceDiffError::InsufficientBalance),
    }
}
```

## 3 Program design

Incremental account updates introduces a two-path execution flow to LEZ programs:

- `Execute` handles program logic to construct `AccountDiff`s.
- `UpdateFromDiff` specifies how program owned accounts are updated given a `pre_state: Account` and `diff_data: Data`. This function outputs `Data`.
This design ensures that the same program ELF can be used for both program calls and updates. See
Appendix A.1 (`simple_balance_transfer`) and Appendix A.2 (`data_changer`) for examples of this design.

Program's `UpdateFromDiff` does not apply `account.balance` updates. `Balance` updates are handled at the protocol-level. This restricts a program's ability for direct manipulation to only `account.data`; changes to `program_owner` and `balance` are requested through the program's `Execute` logic but are handled at the protocol-level.

Each program defines how `data` is handled for their accounts.

- `authenticated-transfer` program: `data` is always taken to be default.
- `Token` program: `data` either defined by Token holding or Token definition.
Due to this, incremental account update imposes a new requirement on developers. Each program must include a function `update_from_diff(pre_state: Account, diff_data: Data) -> Result<Data, Error>`.

Programs no longer output the accounts' `pre_states`. This was used for consistency checks by the privacy preserving circuit. However, with `AccountDiff`, the difference is applied to any `pre_state` of the account. Due to this, the program's logic `UpdateFromDiff` defines and enforces rules for updates. At the program level, `diff_data: Data` can serialize a different struct than used by the `account.data: Data`. E.g., AMM  style account may include values or computations from the prover's `pre_state` for threshold enforcement.

### 3.1 Unneeded tests with `AccountDiff`

Tests in LEZ that are no longer needed in `test-methods`:

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

## 4 Protocol-level changes

### 4.1 Current `validate_execution` (public transaction)

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

### 4.2 Proposal changes to `validate_execution` (public transaction)

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

These approaches differ for 3, 4 and 5 as follows:

| Rule | Old (current) | New (diff-native) |
| --- | --- | --- |
| Unauthorized balance decrease | `post.balance < pre.account.balance` | `matches!(diff.diff_balance, BalanceDiff::Sub(amount) if amount > 0)` |
| Unauthorized data modification | `pre.account.data != post.data` | `diff.diff_data.is_some()` |
| Total balance conserved | `sum(pre.balance) == sum(post.balance)` | `sum(Add amounts) == sum(Sub amounts)` across the call's diffs |

## 5 Privacy transaction changes

### 5.1 Account generation in circuit

- Private accounts are fully materialized within the privacy preserving circuit. E.g., updates are performed within the circuit for each iteration. The final private account states is committed to (and initial state nullified). From the observer's perspective, this version of the privacy preserving circuit behaves the same as the current version. `AccountDiff`s are not committed to.
- Public accounts are materialized within the privacy preserving circuit so that `post_state`s can be used as the `pre_state` for consecutive chain calls. The `AccountDiff`s for each update is saved and included in the privacy preserving circuit's journal; the sequencer uses this to replay the executions.

**Optimization**: Compress `AccountDiff`s for a given account into a single `AccountDiff`. This guarantees that each public account requires only a single update from the sequencer.

- This saves on transaction size due to `Data` field used in `AccountDiff`.
- Program design pattern for privacy execution is leaked by observing the number of updates to a specific `program_owner`'s account.

### 5.2 Privacy transaction processing by sequencer

1. Proof verification. If proof fails, then the sequencer aborts.
2. Sequencer replays public accounts with `message.public_diffs` in order for each entry. This derives the public account states based on the account's current state on-chain. If any any update fails (program emits an error or balance update error), then the sequencer reverts the account states and aborts.
3. Provided no errors, the sequencer appends new nullifiers and commitments to the private state, and updates the public accounts.

## 6 Fees

**Disclaimer**: This section makes minor assumptions concerning fees/collateral based on conversation with Sergio and Marvin.

We assume that a collateral account (independent of the message's intended privacy transaction). This ensures that fees can be collected from a failed privacy transaction.

### 6.1 Public transactions

Public transactions fees for incremental account updates are handled as expected. A transaction is executed and accounts are updated until the fees are exhausted (or the computation is finished). If insufficient fees are provided, then the transaction's updates are reverted.

### 6.2 Privacy transactions

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

This rule does not guarantee that 2-3 from Section 5 cannot occur. It guarantees that fees are payable.

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

## Appendix

## A.1 `simple_balance_transfer`

```rust
use std::convert::Infallible;

use lee_core::{account::{Account, AccountDiff, BalanceDiff, data::Data}, program::{AccountDiffOutput, Claim, ProgramCall, ProgramInput, ProgramOutput, read_lee_call, write_update_from_diff_output}};

type Instruction = u128;

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
        ProgramCall::UpdateFromDiff {
            pre_state,
            diff_data,
        } => {
            let data = update_from_diff(pre_state.clone(), diff_data.clone())
                .expect("update_from_diff should not fail");
            write_update_from_diff_output(&pre_state, &diff_data, &data);
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

fn update_from_diff(_pre_state: Account, _diff_data: Data) -> Result<Data, Infallible> {
    Ok(Data::default())
}
```

`update_from_diff` here is an unconditional no-op — this program's own diffs never set
`diff_data`, so this branch is reachable by construction (every `main()` handles both
`ProgramCall` variants) but never actually dispatched to in practice.

## A.2 `data_changer`

```rust
use std::convert::Infallible;

use lee_core::{
    account::{Account, AccountDiff, BalanceDiff, data::Data},
    program::{
        AccountDiffOutput, Claim, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        write_update_from_diff_output,
    },
};

type Instruction = Vec<u8>;

/// A program that modifies the account data by setting bytes sent in instruction.
fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: data,
        },
        instruction_words,
    ) = match read_lee_call::<Instruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff {
            pre_state,
            diff_data,
        } => {
            let data = update_from_diff(pre_state.clone(), diff_data.clone())
                .expect("update_from_diff should not fail");
            write_update_from_diff_output(&pre_state, &diff_data, &data);
            return;
        }
    };

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    // `Data`'s own fallible `TryFrom<Vec<u8>>` enforces the account data size limit here, at
    // diff-construction time, rather than deferring it to `update_from_diff`.
    let data: Data = data
        .try_into()
        .expect("provided data should fit into data limit");

    let diff = AccountDiff {
        id: pre.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: Some(data),
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![pre],
        vec![AccountDiffOutput::new_claimed(diff, Claim::Authorized)],
    )
    .write();
}

fn update_from_diff(_pre_state: Account, diff_data: Data) -> Result<Data, Infallible> {
    Ok(diff_data)
}
```

Unlike `simple_balance_transfer`, this one's `update_from_diff` *is* dispatched to in
practice — it's the only currently-migrated program whose `diff_data` is ever `Some`. The
size-limit check happens once, in `main()`, at diff-construction time; by the time
`update_from_diff` runs, `diff_data` is already a validated `Data`, so returning it directly
is infallible.