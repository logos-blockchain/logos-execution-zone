# Accounts and shards

Everything a program can read or write lives in an account. There is no program-private storage, no global variables, no heap that survives a call. A program is a pure function from its inputs to a set of proposed shard writes, and the accounts are the only inputs.

## The account

```rust
pub struct Account {
    pub nonce: Nonce,          // u128
    pub data: AccountData,     // BTreeMap<AccountId, ShardData>
}
```

Source: `lee/state_machine/core/src/account.rs`.

- **`nonce`** is a replay counter. For a public account it increments by one each time the account signs a transaction. For a private account it is a hash chain advanced by the owner's nullifier secret key; see [Private accounts in depth](private-accounts.md). Programs never touch the nonce.
- **`data.shards`** maps a *program account id* to a byte string. The entry under program `P` is "`P`'s shard on this account". A missing entry reads as empty bytes, and writing empty bytes deletes the entry, so a program never has to distinguish "absent" from "empty".

A shard is at most `DATA_MAX_LENGTH` = 100 KiB (`lee/state_machine/core/src/account/data.rs`). `ShardData` derefs to `[u8]`; programs decode it with borsh or any fixed layout they choose.

## The native balance is a shard

There is no balance field. The native token balance is the shard under `NATIVE_TOKEN_PROGRAM_ID`, the all-zero account id, encoded as a 16-byte little-endian `u128` and absent when zero (`lee/state_machine/core/src/native_token.rs`). Only the native token program writes that shard, through the same effect mechanism every other program uses. `Account::funded(n)` and `AccountData::native_balance()` are conveniences over this encoding.

This matters for design: "credit an account" is not a special operation. It is a chained call into the native token program, and the ownership rule below applies to it like to everything else.

## The ownership rule

A program may **write** only the shards keyed by its own account id. It may **inspect** any shard it is handed, meaning run a check against its bytes without changing them. The state machine enforces this in `validate_apply_output`: an `ApplyOutput` with `post_data: Some(..)` whose selector names another program's shard is rejected as `ForeignShardWrite`.

Consequences worth internalizing:

- A token balance is data in the token program's shard on the holder's account. Only the token program can move it. A wallet, an AMM, a multisig, none of them can touch it except by chaining a call into the token program and getting that program to agree.
- Two programs never fight over the same bytes. Program `A`'s shard and program `B`'s shard on the same account are independent.
- "Who owns this account" is not a protocol concept. Authorization (a signature, a private key proof, or a program-derived-account grant) decides whether an account is *authorized* in a call; the program decides what that lets the caller do with the program's own shard on that account.

## Selecting a shard

A transaction does not name accounts; it names **shard selectors**:

```rust
pub struct ProgramShardSelector {
    pub account_id: AccountId,
    pub program_account_id: AccountId,
}
```

`ProgramShardSelector::native_balance(id)` selects the native shard. A transaction may select several shards of one account (say the token shard and the native shard), but never the same selector twice. The program receives one `AccountMeta` per selector, in order:

```rust
pub struct AccountMeta {
    pub account_id: AccountId,
    pub is_authorized: bool,
    pub program_account_id: AccountId,
}
```

`AccountMeta` deliberately carries no data. `plan` never sees shard contents; only `apply` does, one shard at a time. This is the single most important fact about the model and the next chapter is about it.

## Account ids

An `AccountId` is 32 bytes, printed as base58. How an id is derived tells you what kind of account it is and who can authorize it. The full list with prefixes is in [Account-id derivations](../reference/derivations.md); the short version:

| Kind | Derivation | Authorized by |
|---|---|---|
| Public, key-held | `H("…/Public/" ‖ schnorr_pubkey)` | a BIP-340 signature on the transaction |
| Private, regular | `H("…/Private/" ‖ npk ‖ vpk ‖ identifier)`, identifier 32 bytes | knowledge of the authorization secret key `ask` |
| Public PDA | `H("…/PDA/" ‖ program ‖ seed)` | the program passing `seed` in a chained call |
| Private PDA | `H("…/PrivatePDA/" ‖ program ‖ seed ‖ npk ‖ vpk ‖ identifier)` | the program passing `seed` in a chained call |
| Builtin program | `H("/LEE-BuiltinProgram/v1/AccountId" ‖ name)`, e.g. `token_account_id()` | n/a (dispatch address) |
| Shadow program | `H("…/Shadow/" ‖ image id)` | n/a (dispatch address, never deployed) |

Public and private ids live in the same 32-byte space and the same `BTreeMap` keys, which is why a program cannot tell them apart. There is no bit that says "private".

## Public and private state

The chain state (`V03State`, `lee/state_machine/src/state/mod.rs`) holds:

- a public map `AccountId → Account`, updated in place;
- a **commitment set** (an append-only Merkle tree) and a **nullifier set** for private accounts.

A private account is never stored. What the chain holds is `Commitment::new(account_id, account)` = `H(account_id ‖ H(borsh(account)))`, plus an encrypted note the owner can decrypt. Each update appends a new commitment and inserts a nullifier that marks the previous commitment spent. The account's history is a chain of commitments that only the owner can link.

The account *structure* is identical on both sides. The private `Account` has the same nonce and the same shard map. When a program's `apply` runs on a private account's shard, it sees exactly the bytes it would see on a public one.

## What an account is not

- Not a contract. Accounts have no code. Code is in programs; programs are stateless.
- Not owned. Nothing in the account says who may write it. Each program decides for its own shard, usually by checking `is_authorized`.
- Not created. An account "exists" the moment something writes a shard on it or credits its balance. Sending native tokens to a fresh id works with no setup. A private account is different in one respect: its first write initializes it, and initialization can happen exactly once (see [Private accounts in depth](private-accounts.md)).
