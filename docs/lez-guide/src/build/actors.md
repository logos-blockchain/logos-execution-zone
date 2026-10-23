# Accounts, actors and state

## The account

An account is a nonce and a map (`lee/state_machine/core/src/account.rs`):

```rust
pub struct Account {
    pub nonce: Nonce,
    pub data: AccountData,
}

pub struct AccountData {
    pub actor_states: BTreeMap<AccountId, ActorState>,
}
```

The key of the map is a program's account id. The value is a byte string that only that program reads and writes. An account that three programs have touched has three entries.

There is no balance field. The native balance of an account is the entry under the native token program (`NATIVE_TOKEN_PROGRAM_ID`). Money is ordinary actor state.

## The actor

An actor is one entry of one account:

```rust
pub struct Actor {
    pub account_id: AccountId,
    pub program_account_id: AccountId,
}
```

Read it as "this program, on this account". Some examples:

| Actor | Meaning |
|---|---|
| `(alice, native token)` | Alice's native balance. `Actor::native_balance(alice)` builds it. |
| `(alice, token)` | Alice's holding in the token program. |
| `(vault_pda, multisig)` | A multisig's configuration, on an account the multisig program controls. |
| `(CLOCK_01, clock)` | The every-block clock. |

Every message in the system is addressed to an actor. The program id says which code runs. The account id says which state it runs on.

## The one rule

**A handler reads and writes the state of the actor it is running for, and nothing else.**

It does not see the account's other entries. It does not see other accounts. It cannot be handed someone else's state as an input. If the token program needs Bob's holding to grow, Alice's token actor sends a message to Bob's token actor, and Bob's actor updates itself.

This rule is what makes programs small. A handler has one state to validate and one state to produce.

> **Improvement over plan/apply.** One call used to list several accounts, and the program emitted an effect for each. Every program had to reason about accounts it did not own: which were authorized, which belonged together, whether the caller had listed the right ones. Here a run has one actor, and there is nothing to cross-check.

## Account ids

An account id is 32 bytes. Where it comes from decides who controls the account.

| Kind | Derived from | Controlled by |
|---|---|---|
| Public, key-owned | a public key | a signature |
| Public PDA | a program's id and a seed | that program, by granting the seed |
| Private, regular | a nullifier public key and a viewing public key | the holder of the secret keys |
| Private PDA | a program's id, a seed, and the two public keys | the program for spending, the key holder for operating |
| Builtin program | a fixed name | the protocol |

The exact derivations are in [Account-id derivations](../reference/derivations.md). PDAs are explained in [Authorization](authorization.md).

A private account can also be named by a **blinded address**: a hash of the account id and a secret factor. Nobody without the factor can link the address to the account. Blinded addresses are how a private actor uses pseudonyms, and they are covered in [Private accounts](private-accounts.md).

## Public and private state

The two kinds of account hold the same `Account` structure. They differ in where it is kept.

- **Public.** The chain stores the account in the clear. Anyone can read every actor state on it.
- **Private.** The chain stores only a commitment to the account. The owner keeps the contents. Each update publishes a nullifier for the old commitment and a new commitment, and nobody can link the two.

A program does not choose which kind it runs on. The user who builds the transaction decides, by using a public or a private account. The same handler code handles both.

## What an account is not

- **Not owned by a program.** An account is a container. Many programs keep state on the same account.
- **Not a balance.** The balance is one actor among several.
- **Not readable by other programs.** A program that wants a value from another actor asks for it with a message and receives a reply. See [Handlers and messages](messages.md).
