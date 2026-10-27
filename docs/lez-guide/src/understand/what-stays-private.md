# What stays private, and what does not

A summary for deciding whether LEZ fits a problem. The exhaustive versions are [What a private transaction reveals](../privacy/what-leaks.md) and [What you cannot do privately](../privacy/limits.md).

## The two columns

| Hidden | Published |
|---|---|
| the contents of a private account | that a transaction happened, and when |
| the ids of private accounts, unless a sender presents canonically or a payer is handed a canonical address | every effect on a public account, in full: amounts, recipients, the lot |
| which accounts a private transaction touched | the number of private actions, which is accounts touched plus one for a collected message, padded to seven |
| the inputs and responses of private handlers | which programs ran. Undisclosed needs an immutable header and is a per-transaction choice, and `Disclosed` is the default |
| messages between private actors delivered inside the transaction | the validity window the handler set |
| events emitted by private handlers, which are dropped entirely | a stored message's destination binding, so it can be collected |

Outside the transaction itself: timing, how a transaction correlates with others, who submitted it at the network level, and any pseudonym reused twice.

## The structural limits

These are not missing features. They follow from the model, and no amount of implementation work removes them.

Nobody can make a private actor act. Advancing a private account needs a proof, and only the owner can produce one. A program cannot reach into a private account on a schedule, on a trigger, or on anyone else's transaction.

A message to a stranger's private actor must be stored rather than delivered. The sender cannot run the recipient's handler, so the message waits on chain until the owner collects it, in their own transaction, with their own proof.

A stored message cannot bounce. If the recipient never collects, the protocol does not return it. A design that sends value this way has to accept that it may sit uncollected.

One transaction collects one stored message. Draining a full mailbox costs one proof per message.

Events from private handlers are dropped, so if anything off chain must learn a fact, a public actor has to announce it.

## The mistake to avoid

Confidential state and a watchable structure are different things. The common failure is deriving an address deterministically from a value that some specific party already knows, then treating the address as private. The issuer of a credential knows which accounts it issued to. The organizer of a vote knows the option keys they published. In both cases a deterministic derivation turns "private" into "readable by exactly the party the design was hiding from".

The catalog works through several of these, including ones that do not work and why.
