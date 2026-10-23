# Transactions, public and private

A transaction delivers one root message and runs everything that message triggers. There are two forms. A public transaction is signed and executed by the sequencer. A private transaction carries a proof that the private handlers ran correctly, and the sequencer executes only the public handlers.

## Public transactions

A public transaction contains:

| Part | Content |
|---|---|
| Root | the actor to deliver to, and the message bytes |
| Declared actors | every public actor the execution may reach |
| Authorized accounts | the accounts that sign |
| Nonces | one per signer |
| Fee declaration | payer, gas limit, tip, maximum fee |
| Admission evidence | proof that a not-yet-existing account id is a real public address |
| Signatures | one per authorized account |

The sequencer checks the signatures and nonces, reserves the fee, runs the root and everything it triggers, and applies the result. If execution fails, the state changes are dropped, but the payer still pays and the nonce still advances.

### Declaring actors

The engine runs a public handler only for an actor the transaction declared. A SyncMessage to an undeclared actor fails the transaction. An AsyncMessage to an undeclared **private** address is stored for later. An AsyncMessage to an undeclared public account fails, since there is nowhere to store it.

This is why an AsyncMessage "just works" in both worlds: the builder of the transaction decides, by declaring or not, whether the destination is handled now.

### Admission

Before any public actor receives a message, its account must be **admitted**. An account passes if one of these is true:

- it already exists on chain;
- it signed the transaction;
- the transaction carries evidence for it: the public key or the program-and-seed that hashes to its id;
- the sender granted a seed that derives it.

Admission stops messages from creating state at ids nobody can ever control. Its practical effect: **the first payment to a fresh public account must carry that account's public key.** Without it, the transaction fails and the payer is charged.

### Fees

A public transaction pays for execution and for the bytes it adds to the block. The fee is reserved before execution and the unused part refunded after. Sequencer-injected system transactions (clock, fee distribution, bridge deposits) are exempt.

## Private transactions

A private transaction involves at least one private account. Its public part is:

| Part | Content |
|---|---|
| Proof | one receipt of the privacy circuit |
| Private actions | per private account touched: a nullifier, a new commitment, an encrypted note |
| Boundary | the messages that crossed between private and public actors, in order |
| Sealed async messages | encrypted stored messages sent by private actors |
| Recovery bindings | newly registered receive addresses |
| Public root | the root message, if it targets a public actor |
| Validity windows | the intersection of all handlers' windows |
| Program claims | which program images the proof relied on |

It may also carry signatures, when a public account in it must be authorized.

### Three runs of one engine

The same execution engine runs three times, each with a different job.

1. **Dry run**, on the user's machine. All handlers run, public and private. The wallet learns which messages will cross from public to private.
2. **Private part**, on the user's machine and inside the circuit. Only private handlers run. Each message that crosses to the public side is written to the **boundary** instead of being executed.
3. **Public part**, on the sequencer. Only public handlers run. Each time a message crosses, the sequencer compares it with the next boundary entry. A mismatch fails the transaction.

The two halves check each other:

- A message from private to public is a **demand**. The proof says "my handler sent exactly this", and the sequencer carries it out.
- A message from public to private is an **assumption**. The proof says "I assumed the public side would send exactly this", and the sequencer confirms it did.

### An example

Alice pays 10 from her private balance to Bob's public balance.

1. Root: `Transfer { to: bob, amount: 10 }` to `(alice_private, native)`. This actor is private, so the root is not published.
2. In the proof: Alice's handler debits her and sends `Credit(10)` to `(bob, native)` as an async message. Bob's actor is public and declared, so the message crosses.
3. Boundary: one private-to-public entry holding the credit.
4. On the sequencer: the proof verifies. Bob's handler runs with `Credit(10)` from the boundary and his balance grows.

An observer sees Bob receive 10 from "some private balance actor" and a new commitment. They do not see Alice's account, her balance or her other activity.

### Collecting a stored message

A stored message is collected by a private transaction whose root is that message. The proof shows that the message is in the chain's message tree and has not been collected before. Nothing crosses to the public side unless the handler sends something there.

### Proving cost

The user's machine produces one inner proof per message delivered to a private actor, and one proof for the circuit that checks them all. Two things reduce the count:

- **Public handlers are never proven.** The sequencer runs them.
- **The native token needs no inner proof.** The circuit computes it directly.

So collecting a native credit is one proof. A token transfer between two of your own private accounts is three: two handler runs and the circuit.

> **Improvement over plan/apply.** During review of the pull request, a reviewer counted receipts in both models: a private token transfer went from three to two, and a swap between a private trader and a public pool from five to two. The old model proved a plan for every call, including calls into public programs. This one proves only private handlers. These are counts, not timings, and the author noted that some cases grow, since there is one proof per message a private actor handles.

### Fees, today

Private transactions are currently exempt from fees. This is an interim choice and will change.

## Choosing the form

You do not choose it in the program. The wallet builds a public transaction when every account involved is public, and a private one otherwise. A program written with AsyncMessages for payouts and SyncMessages for atomic steps works in both without changes.
