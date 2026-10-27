# Private accounts in depth

A private account is a normal account whose current value is known only to holders of its viewing key, whose existence on chain is a commitment, and whose every update is proven rather than executed by the sequencer. This chapter covers the keys, the lifecycle of a private account, what a note is, how the wallet finds notes, and the two families of private program-derived accounts.

Sources: `lee/state_machine/core/src/{nullifier,commitment,circuit_io}.rs`, `lee/state_machine/core/src/encryption/mod.rs`, `lee/privacy_preserving_circuit/src/output.rs`, `lee/key_protocol/src/key_management/`, `lez/wallet/src/account_manager.rs`.

## Keys

```text
secret spending key (32 bytes, from mnemonic)
 ├─ ask  authorization secret key  = H("/LEE-Keys/v1/Authorization/Secret" ‖ ssk ‖ index)
 │   └─ nsk  nullifier secret key   = H("/LEE-Keys/v1/Nullifier/Secret" ‖ ask)
 │        └─ npk  nullifier public key = H("/LEE-Keys/v1/Nullifier/Public" ‖ nsk)
 └─ vsk  viewing secret key (d, z)  = HMAC-derived ML-KEM-768 seed
      └─ vpk  viewing public key     = ML-KEM-768 encapsulation key (1184 bytes)
```

Three capabilities fall out of the chain, and they separate cleanly:

| Holding | Lets you |
|---|---|
| `vsk` | decrypt notes addressed to the key: **see** the account |
| `nsk` | compute nullifiers and build `Update` witnesses: **advance** the account, unauthorized |
| `ask` | prove authorization: **spend** from the account, in the program's sense |

A wallet's "private accounts key" is `(npk, vpk)`. Publishing that pair is how you receive. It is what `wallet account show-keys` exports and what `--to-keys` consumes.

## Account ids and identifiers

```rust
AccountId::for_regular_private_account(&npk, &vpk, identifier)   // identifier: lee_core::Identifier, 32 bytes
```

One key pair controls 2^256 accounts, one per identifier. An `Identifier` is an opaque 32-byte value (`Identifier::new([u8; 32])`, `Identifier::ZERO`, printed as base58 by the CLI). Identifiers are not sequential and not secret in any protocol sense; they are a namespace the sender picks. Two senders who both send to your key with identifier 7 collide (only the first initialization succeeds), so the convention is: the receiver publishes the key, each sender picks a fresh random identifier, the receiver discovers whatever arrives. The wallet does this by default.

## Lifecycle: Init, then Update

A private account's on-chain life is a sequence of commitments. The witness a transaction supplies decides which step it takes:

```rust
pub enum NullifierWitness {
    Init   { npk, commitment_root },
    Update { account, view_tag, nsk, membership_proof },
}
```

**Init** creates the account. The nullifier is `H("…/Nullifier/Initialize/" ‖ account_id)`, deterministic, so an account id can be initialized exactly once in the chain's life. Anyone who knows `(npk, vpk, identifier)` can initialize the account: no secret is needed, the pre-state is empty, and the transaction's program decides what the first value is. This is how a stranger sends you tokens: they initialize a fresh account of yours with a balance.

**Update** replaces the current value. The witness carries the current plaintext, the `nsk`, and a Merkle membership proof of the current commitment. The nullifier is `H("…/Nullifier/Update/" ‖ commitment_pre ‖ nsk)`: unlinkable to the account, to the previous nullifier, and to the new commitment. Only an `nsk` holder can update, so **nobody but the owner can send to an initialized private account**. Every design in the catalog that receives privately is built around that fact.

After either step the circuit emits one `PrivateAction` per private account:

```rust
pub struct PrivateAction {
    pub nullifier: Nullifier,
    pub root: CommitmentSetDigest,      // the root the membership proof was against
    pub commitment: Commitment,         // H(account_id ‖ H(borsh(post_account)))
    pub encrypted_post_state: EncryptedAccountData,
}
```

and the account's nonce advances: to `H(account_id)`-derived on Init, to `H(nsk ‖ nonce)`-derived on Update. The nonce is inside the commitment, so even an unchanged account gets a fresh commitment.

## Notes

The `encrypted_post_state` is the **note**: the whole post-state `Account` (all its shards) borsh-encoded behind a 97-byte header that says which kind of account it is (regular with its identifier, or PDA with authority, seed and identifier), encrypted with ChaCha20 under a key derived from an ML-KEM-768 shared secret and the nullifier. Alongside it travel the KEM ciphertext (`epk`, 1088 bytes) and a one-byte **view tag** `H("…/ViewTag/" ‖ npk ‖ vpk)[0]`.

Padding: the prover asks for a minimum plaintext length (`ciphertext_padding`, at most 8 KiB); the wallet uses 512 bytes. An account whose encoded state outgrows the pad ships a longer note, and the wallet warns that the note is identifiable by length.

Ordering: the circuit sorts private actions by nullifier bytes and independently sorts the commitments, so the position of an action says nothing about which witness produced it.

Dummies: the wallet pads every private transaction to `MAX_PRIVATE_ACCOUNTS` = 7 private actions with dummy nullifiers, dummy commitments and random notes, so the count of real private accounts is hidden up to that bound. Dummy nullifiers enter the nullifier set like real ones, which incidentally makes any private transaction replay-proof even when its real private actions are all `Init`s of fresh accounts.

## Discovery

`wallet account sync-private` walks the chain's private actions. For each key it holds it computes the view tag once and skips every action whose tag differs (255 of 256 on average); for the rest it decapsulates `epk` with `vsk`, decrypts, and if the note decodes to an account whose header names one of its keys, stores the account and its commitment. A recipient sees a payment only after syncing; nothing pushes notes to wallets. Syncing is also how a wallet learns of private PDAs created for it by a program: the note header carries the authority and seed.

## Kinds of private accounts

```rust
pub enum PrivateAccountKind {
    Regular(Identifier),
    Pda { account_id: AccountId, seed: PdaSeed, identifier: Identifier },
}
```

A **regular** private account is authorized by `ask`. A **private PDA** is authorized by its authority program delegating its seed, exactly like a public PDA. Its id also includes the holder's `(npk, vpk)` and an identifier, so a program's PDA is not one account but a **family**: one per key pair and identifier. `AccountId::for_private_pda(&program, &seed, &npk, &vpk, identifier)`.

That is the private counterpart of "a vault per user". A public program keeps per-user vaults at `for_public_pda(program, H(user))`. A private program keeps them at `for_private_pda(program, seed, user_npk, user_vpk, id)`: the user's wallet can see and discover them, the program alone can authorize them.

### Shared private accounts

Several parties can hold one private account by sharing key material. The key protocol provides a **group key holder** (`GroupKeyHolder`, `lee/key_protocol/src/key_management/group_key_holder.rs`): a 32-byte group master secret, sealed to each member under their sealing key, from which every member derives the same `ask`/`nsk`/`vsk` for a given `(program, seed)` or shared-account identifier. The wallet exposes it as `wallet group new`, `wallet group join`, and `wallet account new private-gms`. Every member then sees and can advance the account. What the group **cannot** do is act concurrently: two updates against the same commitment spend the same nullifier and the second is refused. Shared private state is single-writer per block, in practice single-writer per proving round. This constraint drives most of the multisig and voting designs.

## Deposit keys: sharing `nsk` and `vsk` without `ask`

The three keys separate cleanly, and the runtime honours the separation: a witness of kind `Regular { ask: None }` with an `Update { nsk, .. }` is accepted, the circuit checks the `ask`-to-`nsk` link only when `ask` is present, and `authorize` marks such an account **unauthorized** in every call. So a party who holds a private account's `nsk` and viewing seed, but not its `ask`, can do exactly two things: read it, and build transactions that update it as an unauthorized input.

That is a **deposit key**. Give it to a payroll processor, an exchange, a merchant terminal, a back office, and they can:

- see the account's balance and shards (they decrypt its notes and sync it like you do);
- **credit it repeatedly**, as the recipient of a native `Transfer`, a `token::Deposit`, a credential issue, or any program effect that does not require the account to be authorized, instead of initializing a fresh slot per payment;
- do nothing that requires authorization: every debit path in the shipped programs asserts `is_authorized`, which only `ask` or a seed grant can set. `nsk` is `H(ask)`, so the deposit key does not leak the spending key.

Two caveats, both structural:

1. **Griefing, not theft.** An `nsk` holder can advance the account with any *unauthorized* program write (a no-op update, or a program like `hello_world` that writes its shard without checking authorization). Every update changes the commitment, so a transaction you prepared against the old commitment is refused. A deposit-key holder can deny you service until you re-sync; they cannot move value out.
2. **Wallet support is partial.** The wallet's `PrivatePdaShared { nsk, .. }` already carries an `nsk` without `ask` for PDAs, but there is no "regular account, `nsk` and viewing seed, no `ask`" identity, and sync decrypts only for key chains it holds in full. The protocol path exists; a wallet needs a small new identity and a sync entry to use it.

Compare with sharing only the viewing seed `(d, z)`: that gives **view-only** access (an auditor sees, cannot advance, cannot spend), and with a group key: that gives **full** access (every member spends). The deposit key sits between the two. See also [pattern 18](../patterns/index.md).

## What the owner must keep

To update a private account you need its current plaintext and a membership proof for its current commitment. The plaintext is in the note you decrypted (or the one you produced); the proof comes from the sequencer (`get_proofs_and_root`). Lose the plaintext and the account is frozen, not lost: its commitment stays on chain, but no one can build a witness for it. Wallet backups therefore need the account states, not only the keys, or a full re-sync from genesis.

## The identity model of the wallet

`AccountIdentity` (`lez/wallet/src/account_manager.rs`) is the vocabulary for listing accounts in a transaction:

| Identity | Meaning | Witness produced |
|---|---|---|
| `Public(id)` | public account; signed if the wallet holds the key | none |
| `PublicNoSign(id)` | public account, never signed (recipients) | none |
| `PrivateOwned(id)` | private account in the wallet's storage | `Update` with `ask` if initialized, else `Init` with `ask` |
| `PrivateForeign { npk, vpk, kind }` | someone else's key | `Init`, unauthorized |
| `PrivateShared { ask, vpk, identifier }` | group-held regular account | as owned |
| `PrivatePdaShared { authority, seed, nsk, vpk, identifier }` | group-held PDA | as owned, PDA kind |

Each identity is then narrowed to a shard with `.balance()` or `.select_program_shard(program)`. The four native-transfer facades (`lez/wallet/src/program_facades/native_token_transfer/`) are the smallest complete examples: public→public, public→private (shielded), private→public (deshielded), private→private, each a two-selector call into the native token program with the sender authorized and the recipient not.
