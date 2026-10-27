# The pattern language

These are the recurring moves of actor programs on LEZ. The catalog refers to them by number. Patterns 1 to 6 are about writing a correct handler. Patterns 7 to 12 are where public and private actors meet. Patterns 13 to 18 are about time, custody and exactly-once.

## 1. Tell, do not write

A handler changes only its own actor. To change another actor, send it a message and let its handler decide.

*Example.* The every-block clock does not write the slower clocks. It sends them `Record`.

## 2. Route on the sender first

Before decoding a message, look at `input.from`. Decide which messages this sender is allowed to send, then decode with that type.

*Why.* Messages are untyped bytes. A reply format and a request format can collide. The sender is the one field a program cannot forge.

## 3. Internal messages

A message that only the program's own actors may send is guarded with `input.from_own_program()`.

*Example.* `Credit` in the native token. Without the guard, anyone could mint.

## 4. Know who is speaking: the owner, or a seat

**The owner.** An operation that only the account's owner may start checks two things: `input.is_authorized` and `input.from.is_none()`. The flag alone says the owner's credential is in the transaction. It does not say the owner sent this message. See [Authorization](../build/authorization.md).

**A seat.** When a shared actor needs to know *which participant* is speaking, each participant gets an actor of the same program on their own account. The participant talks to their seat, which does the owner check above. The seat talks to the shared actor, which checks `input.from_own_program()` and the seat's account id.

*Why a seat.* A sender's account id proves nothing by itself: any program can be run on any public account without its owner. A seat is a sender whose code you wrote.

## 5. Reply with an echo

To read another actor's value, send a request that carries your own context, and have the other actor reply with the value and the context back.

```rust
// request
Stamp { payload: Vec<u8> }
// reply, sent to input.from
Stamped { block_id: u64, timestamp: u64, payload: Vec<u8> }
```

The asking handler runs twice: once to ask, once to continue. The echoed payload saves it from storing intermediate state. Always check that the reply's sender is the actor you asked.

## 6. Receive without failing

A handler that receives value by AsyncMessage must accept every legitimate message. A stored message cannot bounce.

*Example.* The token program's `Credit` creates the holding if it is missing. For the one case it cannot handle (a holding of another kind), the owner has `EnsureHolding` to repair it.

## 7. The proof-carrying message

A private actor of program P sends a message to a public actor of P. The public actor checks `input.from_own_program()`.

Because the private handler ran inside the proof, the public actor now knows a fact about hidden state: "an actor running my code, in a state my code allowed, decided to send this". It does not know which account.

This is the most productive pattern in the model. Anonymous votes, hidden multisig members, credentials and honest hidden-information games are all this pattern.

## 8. Pseudonym

A private actor presents a blinded address as its sender. The public side sees a stable name it can store, count and reply to, and nothing else.

- One address per relationship: linkable inside it, unlinkable across.
- A fresh address per action: fully unlinkable.

Pattern 7 says *what kind of actor* spoke. Pattern 8 says *which one, under a name of its choosing*.

The name hides the account from observers and from public actors. It does not hide it from a **private** party who sends to that address: sealing a message needs the recipient's keys and blinding factor, which reveal the account. See [Private accounts](../build/private-accounts.md).

## 9. Async message for strangers

Send value and notifications to other people with an AsyncMessage, never a SyncMessage. The same code then serves public recipients (delivered at once) and private ones (stored).

## 10. Accept by collecting

A request is an AsyncMessage that asks for something: pay this, sign that, swap these. The recipient accepts by collecting it **with** their spending key. Collecting it without the key, or not at all, declines.

The handler must be written for this: on a collected message it treats `is_authorized` as the owner's consent to that message.

## 11. Anyone may poke

A public actor exposes a message that anyone can send and that only moves the actor forward by its own rules: release what is due, close what has expired, pay what is owed.

*Why.* Nothing runs by itself. Poke messages let any interested party, or a paid keeper, supply the transaction.

## 12. The public referee

A private participant cannot be forced to act. So a public actor holds a bond and a deadline. The participant answers the challenge in time, with a proof-carrying message, or the referee pays the bond to the other side.

Use it for games, disputes, and any protocol with a "your move" step.

## 13. Seed-authorized custody

Funds live in the balance actor of a PDA. Only the program can move them, by granting the seed on a SyncMessage. Derive the seed from the instance's identity so instances cannot spend each other's funds. If the seed is supplied by a caller and stored, check on that first write that it derives the actor's own account. A stored seed that does not is a permanent lock on the funds.

## 14. The receipt actor

To make something happen exactly once, address it to an actor whose account is derived from the thing's unique id. The handler requires an empty state and writes a marker.

*Example.* The bridge's deposit receipt.

## 15. Write once

Configuration that must never change is written with `write_once`, which accepts the first value and any identical repeat, and refuses anything else.

## 16. Windows for expiry

A handler that must not run after a deadline returns a validity window. No message, no clock, no state.

## 17. Clock assertion

A handler that depends on time passing sends `AssertTimestamp` to a clock actor. Use the coarsest clock that is precise enough: a transaction that depends on a slow clock stays valid longer.

## 18. Group-owned private PDA

Shared hidden state: a private PDA whose keys come from a group secret. Any member can operate it. Only the program can authorize spending from it. Combine with pattern 13 for a hidden vault.

## 19. The notify hook

A payment that should trigger something at the destination carries a small instruction for the receiver to forward.

*Example.* The token's `Credit` takes an optional `notify { to, payload }`. After depositing, the holding actor SyncMessages `to` with a notification. "Pay and tell" becomes one message.

## Anti-patterns

- **Trusting `is_authorized` alone** for an operation only the owner should start.
- **Collecting with the spending key by default.**
- **A SyncMessage to a stranger's private actor.** It fails. Use an AsyncMessage.
- **A reply with fast-changing data to a private actor.** The proof goes stale in one block.
- **One enum for everything a program sends and receives.** It forces handlers for messages that should never arrive.
- **A receiving handler that can refuse value.** The value is stranded.
- **State that grows without bound.** Nothing prunes it, and every later run pays to load it.
- **Identifying a person by the sender's account id alone.** Any program can run on any public account without its owner. Check the sending program too: see the seat in [Multisig](../catalog/multisig.md).
- **Deriving meaning from an address.** An address is a name. Check the sender and the state.
