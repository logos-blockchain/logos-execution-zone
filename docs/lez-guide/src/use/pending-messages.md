# Pending messages

A program cannot pay you. It can only offer, and wait for you to take it.

That sounds like a limitation and it is the direct consequence of privacy working. Advancing a private account requires a proof, and only you can produce one. So when a program or another person sends something to your private account, it cannot be written there. It is stored on chain, addressed to you, and waits.

That store is the mailbox.

## Using it

```bash
wallet pending list
wallet pending receive --position <n>
```

`list` shows the messages waiting for accounts this wallet owns. `receive` collects one, which means running its handler on your machine, proving it, and submitting the result as your own transaction.

The `--position` is the message's position in the commitment tree, and `list` is where you get it.

## What to expect

Collecting costs a proof, so it takes from tens of seconds to a few minutes.

One transaction collects one message. A mailbox with ten messages in it costs ten collections. There is no batch.

An uncollected message is not in your balance. This is the part that confuses people: `wallet account get` will not show money that has been sent to you but not collected, because it is not in your account yet. `wallet pending list` is where it is. If a balance looks wrong, check the mailbox before anything else.

A stored message cannot bounce. If you never collect it, the protocol does not return it to the sender. Whoever sent it has to live with that, which is a thing to know if you are the sender rather than the recipient.

## Why the sender cannot just write to you

Because then anyone could. The property that makes a private account private is that only its owner can produce a valid transition for it. If a program could advance your account without your proof, it could also drain it, and the privacy would be decorative.

So the asymmetry is deliberate: anyone can address you, nobody can act as you. [Private accounts, addresses and the mailbox](../build/private-accounts.md) has the mechanism, including how a sender addresses you without learning your account id.

## Public accounts do not have this

If the recipient is a public account, the sequencer can run its handler, so delivery happens inside the sender's transaction and nothing waits. The mailbox exists only because private recipients cannot be executed by anyone but themselves.

This is why a program written to pay people with async messages works for both: public recipients are paid immediately, private ones are paid when they collect, and the program is identical either way.
