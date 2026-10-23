# Private accounts, addresses and the mailbox

## What is on chain

For a private account the chain holds no contents. It holds:

- **commitments**: one per version of the account, a hash of the account id and its contents;
- **nullifiers**: one per version that has been replaced;
- **encrypted notes**: the new contents, encrypted to the owner's viewing key.

An update spends the old version (publishing its nullifier) and creates a new one (publishing a commitment and a note). An observer cannot link a nullifier to the commitment it spends.

## Keys

| Key | Lets the holder |
|---|---|
| Nullifier secret key (`nsk`) | spend a version, so update the account and collect messages |
| Viewing key | decrypt notes, so read the account and find incoming messages |
| Authorization secret key (`ask`) | make handlers see `is_authorized == true` |

The witness a user supplies for a regular private account comes in two strengths (`lee/state_machine/core/src/circuit_io.rs`):

```rust
pub enum RegularKey {
    Authorized(AuthorizationSecretKey),  // can spend
    Nullifying(NullifierSecretKey),      // can only receive and update
}
```

This split is the consent mechanism for incoming messages. Receiving needs only the weaker form.

## Kinds of private account

- **Regular.** Id derived from the public keys. Authorized by `ask`.
- **Private PDA.** Id derived from a program, a seed and the holder's public keys. It has no `ask`. Only a seed grant from the program authorizes it. The holder can operate it but cannot spend from it alone.

## Addresses and pseudonyms

A private account does not have to be known by its account id. It can receive at a **blinded address**:

```rust
account_id.blinded(&factor)   // a hash of the id and a 32-byte secret factor
```

Each factor gives a different address. An observer cannot link two addresses of one account to each other or to the account. The owner proves in zero knowledge that an address opens to their account.

Blinded addresses work in both directions:

- **Receiving.** An async message sent to the address is collected by the account behind it.
- **Sending.** A private actor can present an address instead of its account id as the sender. The receiver sees a stable pseudonym and can reply to it.

Use a fresh address per counterparty, per campaign or per conversation.

**Who a blinded address hides you from.** It depends on who writes to it.

- **Observers and public senders** see only the address. A public sender needs nothing else.
- **A private sender** seals the message to you, and for that it needs your public keys and the factor (`seal_message`, `lee/state_machine/core/src/sealing.rs`). Those keys give your account id. So a private counterparty you hand an address to knows which account it is, and can link every address of yours it was given.

A blinded address is a pseudonym toward the public, not toward the private parties who write to it. The reference wallet currently sends private-to-private only to the plain account id.

> **Improvement over plan/apply.** Pseudonyms used to be built inside each program, as hashes of secrets stored in public state. Blinded addresses come from the protocol and work for every program, both as a sender and as a destination.

## Recovery bindings

An address can receive stored messages **from public senders** only once a recovery binding for it is on chain, or is introduced by the same privacy-preserving transaction. Registration publishes a recovery binding (`lee/state_machine/core/src/recovery.rs`):

```rust
pub struct RecoveryBinding {
    pub address: AccountId,
    pub note: EncryptedNote,
}
```

The note is encrypted to the owner's viewing key. It tells the owner which of their accounts the address belongs to and with which factor. This is how a wallet restored from a seed finds the messages sent to its addresses.

The binding is created from the recipient's public keys and factor, so the recipient or anyone who holds those can publish it, in a private transaction. Once on chain it is reused. A binding published by the same transaction also counts, so a sender holding the recipient's keys needs no prior registration, but that transaction has to be a privacy-preserving one. An AsyncMessage from a public actor to an address with no binding, and none introduced alongside it, fails with `UnboundAsyncDestination`. A sealed message from a private sender needs no binding, because its own note tells the recipient which address it was for.

## The mailbox

An AsyncMessage that is not delivered in its own transaction becomes a **publication**:

```rust
pub enum Publication {
    Clear { body: MessageBody, recovery: EncryptedNote },
    Sealed(SealedMessage),
}
```

- **Clear.** The sender was a public actor. Sender, destination address and message bytes are readable by everyone.
- **Sealed.** The sender was a private actor. The chain holds a commitment and an encrypted note. Only the recipient can read it.

Every publication is added to the chain's commitment tree.

### Collecting

The owner's wallet scans publications, decrypts what it can, and lists what belongs to it:

```text
wallet pending list
wallet pending receive --position <n>
```

Collecting is a private transaction whose root is the stored message. The handler of the receiving actor runs with `from` set to the original sender. The proof publishes a nullifier for the message, so it cannot be collected twice.

Things to know:

- **Collection is voluntary.** A message that is never collected has no effect.
- **One message per transaction.**
- **The owner sees the message first.** The wallet decodes it before deciding. The reference wallet collects only native and token credits.
- **Collecting without `ask` is the default.** See [Authorization](authorization.md) for why that matters.

> **Improvement over plan/apply.** A private balance used to be a set of single-use accounts, one per incoming payment, that the owner swept together a few at a time. A private account is now long-lived: it has addresses, receives any number of messages, and stays one account.

## Shared private accounts

A group can own private accounts together (`lee/key_protocol/src/key_management/group_key_holder.rs`). The group shares one 32-byte secret, the Group Master Secret. From it every member derives the same keys for:

- a shared regular account, which every member can spend;
- a private PDA of a given program and seed, which every member can operate and only the program can authorize. The keys are derived from the program's **image id**, so they stay the same wherever that program is deployed.

The secret is passed to a new member encrypted to their sealing key (`wallet group` commands). The second form is the basis of hidden shared vaults: see [Multisig](../catalog/multisig.md).

Two limits: every member sees everything in a shared account, and a member cannot be removed without moving to a new group secret.

## What the owner must keep

The chain has the notes, so a wallet restored from its seed can find its accounts and its mailbox again by scanning. What cannot be recovered is the seed itself.
