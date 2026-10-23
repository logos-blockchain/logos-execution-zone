# Public and private, in plain terms

Every account on LEZ is one or the other, chosen when it is created. The difference is not what a program can do with it. The difference is what everyone else can see.

## A public account

Its contents are on chain in the clear, readable by anyone, forever. Its balance, every program's state on it, its nonce. Reading one is a query:

```
wallet account get --scope all --account-id Public/<id>
```

Transactions touching it are executed by the sequencer, land in one block, and cost a fee.

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

Which programs it used, unless they were deployed immutably and run undisclosed.

The fact of the proof, which is a fixed size and so says nothing about how much work it covered.

[What a private transaction reveals](../privacy/what-leaks.md) is the exhaustive version, written from the published object field by field.

## The thing to take away

"Is this program private?" is not a question with an answer. The same program serves both kinds of account, so privacy is decided per transaction, by which accounts it touches, and by the client that builds it.

A design can hold all its state privately and still leak everything through its shape. If an address is derived deterministically from something an observer already knows, watching that address is as good as reading the state. That mistake, in several forms, is the most common one in the catalog, and it is why the privacy chapters come before the designs.
