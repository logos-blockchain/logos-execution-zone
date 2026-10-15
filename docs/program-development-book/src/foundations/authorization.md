# Authorization and program-derived accounts

`AccountMeta::is_authorized` is a single bit per input account. The runtime computes it; the program decides what it means. This chapter is about how the bit gets set and how a program can pass it on.

Source: `ExecutionState::authorize` in `lee/state_machine/core/src/execution_state.rs`.

## Three sources of authorization

1. **A signature.** A public account is authorized in a transaction when a signature by its key is in the witness set. The account id is `H("…/Public/" ‖ pubkey)`, the scheme is BIP-340 Schnorr over secp256k1, and the message is the transaction's `Message` hash, which covers the instruction, the selectors, the nonces and the fee declaration. Every signer's nonce must match the chain and advances by one.
2. **A private key proof.** A private account is authorized when its witness carries the authorization secret key `ask` and the circuit checks that `ask` derives the account's nullifier key. Nobody sees `ask`; the proof is the authorization.
3. **A program-derived account grant.** A chained call may list PDA seeds. For each seed, the callee sees as authorized the account derived from `(caller_program_id, seed)`, public or private. The grant is scoped to that call and everything it chains into.

The three are uniform from the program's point of view. `token::Transfer` asserts `sender.is_authorized` and does not know, or care, which of the three set it.

## Program-derived accounts

A PDA is an account whose id is derived from a program's account id and a 32-byte seed. Nobody holds a key for it. Only the program can authorize it, and only by choosing to delegate the seed in a chained call.

Public:

```rust
let vault = AccountId::for_public_pda(&self_account_id, &seed);
```

Private (also needs the holder's keys and an identifier; see [Private accounts](private-accounts.md)):

```rust
let vault = AccountId::for_private_pda(&self_account_id, &seed, &npk, &vpk, identifier);
```

The runtime grants authorization like this, in `prepare_call` for the callee:

- for a **public** input account, if the caller listed a seed `s` such that `for_public_pda(caller, s) == account`, the account is authorized;
- for a **private** input account, if its witness is `WitnessKind::Pda { binding: (caller, s) }` and the caller listed `s`, the account is authorized.

Grants **propagate**: an account authorized by a grant in call `C` stays authorized in every call `C` chains into, without listing the seed again. And a `(program, seed)` pair may bind to one account per transaction (`FamilyBindingConflict`), so two private PDAs of the same family cannot both act in one transaction.

A PDA is only authorized in a chained call. At top level there is no caller, so `pda_seeds` are ignored and a PDA is never authorized. A program cannot spend from its own vault in its own root call; it chains into the program that owns the shard (usually the native token or `token`) and delegates the seed there.

## Custody

The idiom for "the program's vault pays" is a chained transfer with a seed:

```rust
use lee_core::native_token::custody_transfer;
plan.call(custody_transfer(vault_id, vault_seed, recipient_id, amount));
```

which expands to a native `Transfer` naming the vault as sender and `.with_pda_seeds(vec![vault_seed])`. For `token`, the AMM does the same with `transfer_call(..).with_pda_seeds(vec![compute_vault_pda_seed(..)])`.

Three things follow.

- **Custody is exactly as safe as the program's plan.** The program is the only party that can produce the seed in a call, and it does so only where its code says. Every check that guards a withdrawal has to sit in that program.
- **The seed is not a secret.** Vault seeds are derived from public data (pool id, token id). Knowing the seed gives nothing; only the program at the right address can delegate it. `ata_core::compute_ata_seed` (`logos-blockchain/lez-programs: programs/ata/core`) is public for exactly that reason.
- **Seeds are namespaces.** Different seeds give unrelated accounts. A program with per-user vaults derives the seed from the user's id.

## Restricting the caller

`caller_account_id` is the mirror of PDA grants: it lets a callee decide who may call it.

```rust
// only this program's own `Initiate` may reach `InvariantCheck`
assert_eq!(input.caller_account_id, Some(input.self_account_id));

// only a top-level, signed transaction may stake
assert!(input.caller_account_id.is_none());

// only the configured minter may call Mint
plan.effect(config, &Effect::Mint { caller_account_id: input.caller_account_id, .. });
// apply: assert_eq!(caller_account_id, Some(cfg.minter))
```

Note the third shape: the config holds the allowed caller, `plan` cannot read the config, so the caller id travels in the effect and the check happens in `apply`.

A program that does **not** check its caller is callable by any program with any accounts the transaction listed. That is usually what you want for "library" programs like `token`, and usually not what you want for anything with a privileged instruction. The cross-zone inbox's documentation (`lez/programs/cross_zone_inbox/src/main.rs`) spells out the consequences: any deployed program is a possible target of a peer zone's message unless it authenticates its caller.

## Authorizing a public account inside a private transaction

A private transaction may include public accounts, and they can be authorized the ordinary way: the account's key signs the private transaction's message. The circuit is given the set of signers up front (`ProvingInput::signers`), the sequencer recomputes the `is_authorized` bits from the actual signatures, and a mismatch makes the proof fail to verify. The public account's nonce advances as in a public transaction.

This is how a public account can pay into a private one (a shielded transfer) with no extra machinery. It also links the signer to the transaction on chain; see [What a private transaction reveals](../privacy/what-leaks.md).

## What `is_authorized` does not mean

- It does not mean "owner". It means "this transaction carries authority over this account". A program may let unauthorized accounts be written (credits, initialization, public bulletin boards) and many do.
- It does not transfer across programs by default. If program `A` is called with an authorized account and chains into `B` without a seed grant, `B` sees the account as authorized only if the original authorization (signature or `ask`) applies, which it does: root-level authorization is a property of the account for the whole transaction. What does not transfer is PDA authority, which needs the seed at each delegating call (and then propagates downward).
- It is not checked for you. A program that forgets `assert!(meta.is_authorized)` before debiting has a bug the runtime will not catch. The `hello_world` example writes without checking, on purpose, to show the difference.
