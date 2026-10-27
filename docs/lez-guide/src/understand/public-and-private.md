# Public and private, in plain terms

Every account on LEZ is one or the other, chosen when it is created. The difference is not what a program can do with it. The difference is what everyone else can see.

## A public account

Its contents are on chain in the clear, readable by anyone, forever. Its balance, every program's state on it, its nonce. Reading one is a query:

```
wallet account get --scope all --account-id Public/<id>
```

Transactions touching it are executed by the sequencer and land in one block. The fee is charged per transaction rather than per account: a user public transaction must declare one, while a privacy-preserving transaction pays nothing even when it touches a public account (`lez/chain_state/src/classify.rs`). That exemption is interim and a change is in flight to end it: a private transaction will reserve its fee inside its own proof and be refunded the unused part, so the sequencer charges it without learning more than the reserve.

## A private account

The chain does not hold its contents. It holds a commitment, which is a hash, and an encrypted note that only the owner's keys can open.

Nobody can read it, including the sequencer. That has a consequence people find surprising: you cannot read it either, not directly. Your wallet has to scan the chain for notes it can decrypt and build a local picture. That is what this does:

```
wallet account sync-private
wallet account get --scope all --account-id Private/<id>
```

Run them the other way round and the account looks uninitialized, because the wallet has not looked yet.

Transactions touching a private account are executed on your own machine and proved there. The sequencer verifies the proof without learning what it proved.

## What a private transaction still shows

Private does not mean invisible. A short and honest list of what an observer gets:

That a transaction happened, and when.

Roughly how many private accounts it touched. The wallet pads every private transaction to seven private actions, which is the accounts it touches plus one for a message being collected, so one private action and six are indistinguishable, but more than seven cannot be padded and reveals its exact count.

Every effect it had on a public account, in full. If your private transaction pays a public address, the amount and the recipient are public. This is the single largest source of leaks in practice, and the designs in Part III are mostly about managing it.

Not which private accounts, in the normal case. A private action's nullifier, commitment and note carry no account id and cannot be linked to an account or to each other. An id becomes public only if the transaction puts it there: a private sender that presents canonically instead of blinded, or a public payer that addresses the account at its canonical id rather than at a blinded receive address. The wallet blinds every private sender with a fresh factor per message.

Which programs it used. Each program a private handler ran is named in the clear, by account id and image id, because the sequencer has to resolve the image to check the proof. A program whose header is immutable can instead be proven undisclosed, but that is a choice the prover makes per transaction and `Disclosed` is the default, the anonymity set is only the immutable programs on chain, and one transaction that takes the default publishes the id for good. [Program identity](../build/programs.md) has the detail.

The fact of the proof, which is a fixed size and so says nothing about how much work it covered.

[What a private transaction reveals](../privacy/what-leaks.md) is the exhaustive version, written from the published object field by field.

## The thing to take away

"Is this program private?" is not a question with an answer. The same program serves both kinds of account, so privacy is decided per transaction, by which accounts it touches, and by the client that builds it.

A design can hold all its state privately and still leak everything through its shape. If an address is derived deterministically from something an observer already knows, watching that address is as good as reading the state. That mistake, in several forms, is the most common one in the catalog, and it is why the privacy chapters come before the designs.
