# Program updates in LEZ
## Big idea

In LEZ, programs in LEZ are stored as:
```rust
pub struct Program {
    id: ProgramId,
    elf: Cow<'static, [u8]>,
}
```

This design assumes that `id` is directly linked to the program's `elf`. Crucially, this provides a guard against malicious activity in privacy executions; the privacy preserving circuit checks the provided `elf` with the account's `program_owner`. This guarantees that privacy circuits are executed on the legimate program.

This design does not support upgrades. We modify `Program` struct and Protocol-level logic to support upgrades.


## Core type

### Program account

`Program` account is expanded, but remains distinct from `Account`.

```rust struct Program {
  id: ProgramId,
  upgrade_auth: Option<AccountId>, // `None` if program is not upgradeable.
  version: u64, // Number of patches/upgrades to the program that has been deployed.
  elf: Cow<`static, [u8]>, // The most recent elf. 
}
```
- `id` is immutable label. `id` is the `image_id` of the initial `elf` deployed for this program. 
- `upgrade_auth` is the `AccountId` that can submit transactions to upgrade the program's `elf`. `AccountId` must authorize the program update.
- Public transactions use the `elf` included in the Program account. Privacy transactions require additional safe guards introduced in the next section.

### Program commitments

Upgradeability delinks `elf` from `program_id` (for upgraded versions). This introduces an attack vector for privacy execution: a malicious entity can claim an `elf` is an upgraded version of the program. To close this loop, we introduce a `ProgramCommitmentDigest` to LEZ. `ProgramCommitmentDigest` is a Merkle tree that stores "commitments" to each program update.

**`ProgramCommitment`**
```rust
struct ProgramCommitment {
  [u8; 32]
}
```

ProgramCommitments are generated (and appended to the `ProgramCommitmentDigest`) when a program is updated. A program commitment is generated using the `program_id`, `version` and `update_id`:
```rust
Sha256(domain|| program_id || version || update_id)
```
where `domain` is a domain separator.

The privacy preserving circuit adds a check to verify that a membership proof for each `program_commitment` of each program called, and that the `program_commitment` is correctly computed using the `program_id` (from provided accounts) and `update_id` is the new `elf`'s `image_id`.

### Account

```rust
pub struct Account {
    pub program_owner: ProgramId,
    pub program_ver: u64, // New field: stores the program version number.
    pub balance: Balance,
    pub data: Data,
    pub nonce: Nonce,
}
```
We introduce `program_ver` to indicate what program version this `Account` has been used with for the `program_owner`. This ensures that `program_owner` remains a fixed look up for the `elf` in public transactions.

This modifies Protocol-level checks:
- Restricts program interaction with `Accounts` with an "out-of-date" version of the program. Accounts must be updated to the currently known version of the program before execution is permitted. This can be treated as a front-running chain-call for the execution. E.g., public accounts are automatically updated to the most recent version of the program during a transaction. Private accounts are dependent on provided `elf` and `version` provided to the privacy preserving circuit; privacy transaction may use an older version of the program.
- `program_ver` is used along with `program_owner` to restrict manipulation of account data. This prevents mixture of accounts being used in a program execution that are on a program version.
- The sequencer enforces hybrid transactions to use the most up to date version of the program version due to updates to the program state.

## Privacy execution of program version

Privacy granted to users through privacy execution also grants users freedom on `elf` used (without imposing requirements that leak program data). To combat this, we introduce `ProgramCommitmentDigest` to guarantee that the program's `elf` has been deployed to LEZ (for the given `program_id`). However, this does not restrict privacy executions from using a previous version. To address this we introduce additional guards to the protocol:
- `Account.program_ver` provides context to the version of the program that can be used with an account; `version = Account.program_ver` (except for upgrading an account to the new version). Upgrades are performed as a front-running chain call for executions in which `version > Account.program_ver`.

Consequences of this:
- All public accounts are updated to the current version of programs whenever used in a public transaction.
- Privacy executions are rejected by the sequencer if an old version of the program is used with a public account.
- Fully private transactions may use an old version of the program.

## Remarks
- Different programs on LEZ can use the same `elf`. Two programs can be upgraded to use the same `elf` on LEZ. E.g., two programs with different `program_id`s are upgraded to a new version using the same `elf`.

## Anti-grifting
`ProgramId` generated using the initial program `elf` enables a grift attack. A popular program on one instance of LEZ can be deployed on another. However, a different `upgrade_auth` can be used. Unclear the precise ramifications of this. This is a consequence of the `elf` determining the `ProgramId`.

To prevent this grift attack, `ProgramId` can be generated using `elf` (the `image_id`) and the `upgrade_auth`. This ensures that the same program authority has control over their program account on each instance of LEZ.
```rust
program_id = Sha256(image_id || upgrade_auth)
```
## Deploy program transaction

Upgradeable programs proposal requires an overhaul of program deployment transactions. Currently, a deployment transaction's message only consists of the program's bytecode. This is sufficient, under the current design, as `program_id` is generated directly from the `elf`.

Program transactions handle both deployment and upgrade. To distinguish these, we introduce different message types:
```rust
enum ProgramTransactionType {
	Init,
	Upgrade,
}
```


### Initialization
The new design for `Program` accounts requires additional information: `upgrade_auth` and `version`. Hence, the message becomes:
```rust
struct Message {
	pub elf: bytecode,
	pub upgrade_auth: Option<AccountId>
}
```
For initializing a program, we can set `version = 1`. Thus saving the transmission of a `u64`. Additionally, `Program.program_id` is generated using `elf` and, potentially, `upgrade_auth`.

The `upgrade_auth` (if one is provided) must provide authorization for this transaction.

### Upgrade

Programs are updated with a transaction using `Upgrade`'s message:

```rust
struct Message {
	pub program_id: ProgramId,
	pub auth_withdraw: Bool,
	pub elf: bytecode
}
```

The transaction must include the program's `upgrade_auth`'s authorization.

Sequencer workflow:
- `upgrade_auth`'s provided signature is verified.
- Sequencer updates `Program` account:
	- Increment `version`
	- If `auth_withdraw = true` then `upgrade_auth = None`.
	- `Program.elf = elf`.
- Sequencer appends `Sha256(domain || program_id || version || update_id)` to the `ProgramCommitmentDigest`.

**Remark**
- Plausibly, we can allow `upgrade_auth` transfers to another `Account`. Unclear whether this is crucial when the program can simply be redeployed using the alternate account. Withdrawing `upgrade_auth` may be desirable by certain communities to ensure that a program cannot be modified (once it is stable).