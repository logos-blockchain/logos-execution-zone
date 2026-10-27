# What a private transaction reveals

A private transaction hides what happens inside private actors. It does not hide everything. This chapter goes through each published field and says what an observer learns from it. The fields are those of `ProvenExecution` in `lee/state_machine/core/src/circuit_io.rs`.

## The boundary

The boundary is the list of messages that crossed between private and public actors. **Every entry is in the clear.** For each crossing an observer sees:

- the destination actor;
- the sender, at the address it presented;
- the full message bytes;
- the grants that came with it.

This is the main leak, and it is by design: the sequencer has to run the public handler, so it has to see the message.

What you control is the **sender address**. A private sender can present a blinded address. The public side then sees a pseudonym, not the account.

**Rule of thumb:** anything a private actor says to a public actor is public. Only who said it can be hidden.

Each entry also shows the PDA seeds attached to the message.

## The public context

Published in full: the list of public actors the transaction declares, the accounts it authorizes, and which AsyncMessages it asked to deliver in the transaction. An observer learns which public actors a private transaction was prepared to touch, even if some were never reached.

## The public root

If the root message targets a public actor, it is published. If it targets a private actor, it is not.

## Private actions

For each private account the transaction touched, one entry:

- a **nullifier**, which marks an old version as spent;
- a **commitment** to the new version;
- an **encrypted note** with the new contents.

None of the three can be linked to an account or to earlier entries.

The wallet pads every private transaction to seven private actions and pads notes to a fixed size (`lez/wallet/src/account_manager.rs`). An observer cannot count how many private accounts really took part, up to seven.

## Sealed async messages

A stored message sent by a private actor is published as a commitment and an encrypted note. Sender, destination and contents are hidden. An observer learns that this transaction sent a sealed message, and its padded size.

## Clear publications

A stored message sent by a **public** actor is published in full: sender, destination address and bytes. Only the link between the destination address and the account behind it is hidden.

So when a public account pays a private one, everyone sees the amount and the destination address. If the recipient gave a fresh blinded address, that address says nothing about them.

## Recovery bindings

A newly registered receive address is published with its encrypted note. An observer learns that an address was registered, and by which transaction.

## Validity windows

Published. A tight window narrows down when the transaction was built and can hint at what it does (a deadline, a vote period).

## Program claims

A disclosed claim names the program and its image. An undisclosed claim only says "some immutable program". See [Program identity](../build/programs.md).

## Signatures and nonces

If a public account in the transaction is authorized by signature, its id and nonce are published. That account is then linked to everything else the transaction shows.

## What is not published

- The contents and ids of private accounts.
- Messages between private actors that were delivered inside the transaction.
- The inputs and responses of private handlers.
- Events emitted by private handlers. They are dropped.

## Metadata outside the transaction

- **Timing.** When a transaction lands, and how it correlates with others.
- **Network.** Who submitted it, unless the user takes care.
- **Patterns.** A pseudonym used twice is linkable to itself.
- **Fees.** Private transactions are currently exempt. When they are not, the payer will be a new thing to hide.

## Worked example: a private voter

Dana holds a ballot in a private actor and votes in a public election.

| Field | What an observer sees |
|---|---|
| Boundary | one message to the public tally: `Vote { proposal: 7, choice: Yes }`, from a blinded address of the voting program |
| Private actions | seven unlinkable entries |
| Program claim | the voting program, disclosed |
| Signatures | none |

They learn that a valid ballot voted Yes on proposal 7. They do not learn that it was Dana's.

## Worked example: a public salary to a private employee

A public company account sends a native credit of 3,000 to an employee's address as an async message.

| Field | What an observer sees |
|---|---|
| The public transaction | the company's account, the amount, the destination address |
| The publication | the same, stored |
| Later, a private transaction | seven unlinkable entries; nothing linking it to the publication |

They learn that the company paid 3,000 to an address. They do not learn who owns the address, or when or whether it was collected. To hide the amount too, the company pays from a private account, which seals the message.
