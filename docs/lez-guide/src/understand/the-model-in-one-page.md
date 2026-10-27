# The model in one page

An account is a nonce plus a map from program ids to byte strings. Each entry in that map is the state of one **actor**: a pair of an account and a program. "Alice's token actor" means the token program's state on Alice's account.

A transaction delivers one root message to one actor. The program's handler runs with that actor's state and the message, and returns a new state, a list of synchronous messages and a list of asynchronous messages.

A handler can only ever reason about itself. It sees its own state on one account and nothing else. To affect another actor it sends a message, and the receiver decides what to do with it.

A `SyncMessage` is delivered at once, inside the same transaction, and if anything in the chain fails the whole transaction fails. An `AsyncMessage` to an actor the transaction can already run is also delivered at once. An `AsyncMessage` to anyone else is stored on chain for its recipient to collect later, in their own transaction, with their own proof.

Handlers of public actors run on the sequencer. Handlers of private actors run on the owner's machine inside a zero-knowledge proof, and the sequencer checks only the proof and the messages that crossed between the two sides.

A program never learns whether the accounts it was given are public or private. The same bytecode runs either way. Privacy is a property of the transaction, not of the program, and every privacy limit in this guide follows from that one sentence.

## Why this shape

Three properties fall out of it, and they are what make the designs in [the catalog](../catalog/index.md) possible.

A program only reasons about itself, so you can audit a handler without reading the rest of the system.

A message can wait. An `AsyncMessage` addressed to a stranger's private account sits on chain like a letter until its owner collects it, so a public program can pay a private person who is offline.

A private actor cannot lie. When a private actor sends a message, the proof covers the handler that produced it, so a public actor of the same program can trust that message as a true statement about state it cannot see.

## Where to go from here

[Build on LEZ](../build/quickstart.md) starts from an empty shell and ends with a program you wrote running on chain. [Accounts, actors and state](../build/actors.md) is the same material as this page at full depth.
