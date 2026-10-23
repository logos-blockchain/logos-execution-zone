# What you cannot do privately

Every design in the catalog is shaped by the limits below. Each one is stated with its reason and with the usual way around it.

> **Trade-off.** Three things were easier under plan/apply.
>
> - **Reading.** A program could inspect another program's state directly. A handler must ask and wait for a reply.
> - **Staying valid.** A private transaction never read public state. Its public effects were evaluated at settlement, so it stayed valid while that state changed. Here that still holds for a message from private to public, and it is lost for a reply coming back.
> - **Receiving.** Received funds needed no second step. A stored message must be collected, one per transaction.

## Nobody can make a private actor act

A private handler runs only inside a proof made by the account's owner. A stored message that the owner never collects never runs.

**Consequence.** You cannot build "anyone can trigger this" on private state. A liquidation, a timeout or a penalty cannot reach into a private account.

**Way around.** Put what must be enforceable in a public actor. Let a private participant post a bond there, and let the public actor act on a deadline: answer in time, or lose the bond. See the public referee pattern in [The pattern language](../patterns/index.md).

## One owner's private accounts per transaction

A transaction can run private handlers only for accounts whose keys the submitter holds. Two different people's private accounts cannot both act in one transaction.

**Consequence.** No atomic private-to-private exchange between two parties.

**Way around.** A public escrow actor in the middle, with a timeout. Or a group-owned private account, when the parties trust each other with visibility.

## A SyncMessage cannot reach a stranger's private actor

Only an AsyncMessage can, and an AsyncMessage waits.

**Consequence.** No synchronous question to someone else's private state. You cannot ask "does Bob's private account hold a badge?" and get an answer in the same transaction.

**Way around.** Bob proves it himself, in his own transaction, to a public actor.

## Private state belongs to one key holder

There is no private state that two mutually distrusting parties can both update.

**Way around.** A group secret gives shared private accounts, with three costs: every member sees everything, membership cannot shrink without moving to a new secret, and any member can stall the others. Each update replaces the account's commitment, so a member who keeps updating the account makes everyone else's pending transactions stale.

## Whatever crosses to public is public

A private actor's message to a public actor is published in full. See [What a private transaction reveals](what-leaks.md).

**Consequence.** A private bidder's bid to a public auction is visible, unless the message carries only a commitment to it.

**Way around.** Commit now, reveal later. Hide the sender behind a blinded address.

## A public sender's stored message is in the clear

A public actor that sends an async message to a private address publishes it.

**Way around.** Route value through a private actor first, so the async message is sealed.

## A reply from public to private is fixed at proving time

When a public actor replies to a private one inside a private transaction, the proof commits to the exact reply. If the public state changes before the transaction lands, the reply differs and the transaction fails.

**Consequence.** A private actor cannot reliably read fast-changing public state, such as the every-block clock or a busy pool's reserves.

**Way around.** Read coarse or slow-moving values. Or do not read: assert a range and let the transaction fail if the range no longer holds.

## One collected message per transaction

Draining a mailbox of N messages takes N private transactions and N proofs.

**Consequence.** Designs that send many small messages to a private actor are expensive for the receiver.

**Way around.** Accumulate on the public side and send one message. Or let the sender batch.

## A stored message cannot bounce

If the receiving handler refuses a stored message, nothing returns to the sender.

**Way around.** Receiving handlers for value must accept every legitimate message, or offer the owner a repair path, as the token program does with `EnsureHolding`.

## Events are dropped privately

A private handler's events are not published.

**Way around.** If an indexer must see something, send it to a public actor that emits the event.

## No randomness, no oracles

A handler is deterministic and sees only its input. There is no beacon and no price feed.

**Way around.** Commit-reveal between participants for randomness. A public actor fed by a trusted signer for external data.

## Linkability is the user's job

- A blinded address reused is linkable to itself.
- A signature links its account to the whole transaction.
- Timing links transactions that look related.

## Things that are fine

- Paying a private account you know nothing about, while it is offline.
- A private actor acting on a public program under a pseudonym.
- A public program trusting a statement about private state, when the statement comes from its own code.
- Mixing public and private actors of the same program in one transaction, when you own the private ones.
- Keeping a whole application's state in a group-owned private account.
