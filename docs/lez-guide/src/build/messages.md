# Handlers and messages: SyncMessage and AsyncMessage

## A program is one function

```rust
use lee_core::program::{ReceiveInput, Response};

lee_core::actor_entrypoint!(handle_message);

fn handle_message(input: &ReceiveInput, greeting: Vec<u8>) -> Response {
    let mut bytes = input.pre_state.to_vec();
    bytes.extend(greeting);
    Response::set_state(bytes)
}
```

This is the whole hello-world program from `examples/program_deployment/methods/guest/src/bin/hello_world.rs`. It appends the message to its own state.

`actor_entrypoint!` only writes the guest's `main`. It reads the input, decodes the message with Borsh into the handler's second parameter, calls the handler, and commits the result. The form `actor_entrypoint!(raw handler)` skips the decoding and gives the handler only the input, for programs that decode differently depending on the sender.

> **Improvement over plan/apply.** A program used to have two entry points. `plan` decided what to do without seeing any state, and `apply` saw one piece of state without knowing why. Every decision that depended on state was made twice: proposed by the caller, then checked. A handler sees its state and decides once. Compare the payment channel in both books: the old `Redeem` takes the amount due as a parameter and verifies it, and the new one computes it.

## What the handler receives

```rust
pub struct ReceiveInput {
    pub receiver: Actor,          // the actor this run is for
    pub from: Option<Actor>,      // the sending actor; None when the transaction's author sent it
    pub is_authorized: bool,      // see the Authorization chapter
    pub pre_state: ActorState,    // this actor's state before the message
    pub message: MessageData,     // the message bytes
}
```

Three points to remember:

- `receiver` tells the handler which actor it is. One program serves many accounts, and some programs behave differently per account (the clock accepts `Tick` only at one fixed account).
- `from` is filled in by the system. A program cannot forge it. A stored message keeps its original sender when it is collected.
- `pre_state` is empty for an actor that has never been written.

## What the handler returns

```rust
pub struct Response {
    pub post_state: Option<ActorState>,
    pub sync_messages: Vec<SyncMessage>,
    pub async_messages: Vec<AsyncMessage>,
    pub events: Vec<ProgramEvent>,
    pub validity: ValidityWindows,
}
```

It is built with a small chain of methods:

```rust
Response::set_state(new_bytes)      // or Response::keep_state()
    .send_sync(other_actor, &message)    // deliver now
    .send_async(some_actor, &message)     // deliver now if possible, otherwise store
    .event(event)
    .block_window(100..)            // only valid from block 100 on
```

To refuse a message, the handler panics. A panic fails the whole transaction.

## SyncMessage

A SyncMessage is a message delivered immediately, inside the same transaction.

- The receiver's handler runs before the transaction ends.
- If it fails, everything fails, including the sender's state change.
- A SyncMessage can carry PDA seeds, which authorize the receiver (see [Authorization](authorization.md)).

A SyncMessage does not return a value. The name suggests it does, and that is the most common misunderstanding of this model. If the sender needs an answer, the receiver sends a second message back, and the sender's handler runs again to receive it. See "Replies" below.

**Who can be reached by a SyncMessage:**

- any public actor the transaction declares;
- a private actor whose owner is building this transaction.

A SyncMessage to anyone else's private actor fails the transaction. Only the owner can run a private handler, and they are not here.

## AsyncMessage

An AsyncMessage is a message that is allowed to wait.

| Destination | What happens |
|---|---|
| a public actor the transaction declares | delivered in this transaction, like a SyncMessage |
| one of the submitter's own private actors, when the submitter asks for it | delivered in this transaction |
| any other address | **stored on chain** for its owner to collect later |

The third row is the new capability. The sender's transaction completes. The message stays in a global mailbox. The owner of the destination later builds a transaction whose root is that stored message, and their handler runs then.

Two rules for stored messages:

- **A public sender needs a registered address.** A stored message from a public actor is published in the clear with a recovery note that lets the owner recognise it. The note comes from a recovery binding, and a plain public transaction cannot carry one: `PublicExecution` is a root call and a fee, with nowhere to put it. A binding introduced alongside the message does count, but only a privacy-preserving transaction can introduce one. That is why a wallet sending to a key pair it has not sent to before escalates to the proven path and pays for a proof, rather than failing. A private sender does not need one: it seals the message to the recipient's keys. See [Private accounts](private-accounts.md).
- **Only private addresses can hold stored messages.** An AsyncMessage to a public account that the transaction did not declare cannot be stored and fails the transaction.
- **The sender cannot be told about failure.** If the receiver's handler later refuses the message, the sender's transaction is long finished. Design receiving handlers so that a legitimate message always succeeds.

An AsyncMessage carries no PDA seeds and passes on no grants.

> **Improvement over plan/apply.** There was no way to leave something for a private account. Paying one meant creating a new private account under the recipient's key, inside a privacy-preserving transaction with a proof, even when the payer was public. The recipient ended up with one account per payment. Now a public payer sends an ordinary signed transaction, and the credit is collected into the recipient's one account.

## Choosing between them

| You want | Use |
|---|---|
| all-or-nothing with the other actor | SyncMessage |
| to grant a PDA seed | SyncMessage |
| to reach a stranger's private account | AsyncMessage |
| the same code to work whether the receiver is public or private | AsyncMessage |
| the receiver to be free to act later, or never | AsyncMessage |

The native token is the model example. `Transfer` debits the sender and **sends** `Credit` to the recipient as an async message (`lee/state_machine/core/src/native_token.rs`). For a public recipient the credit lands in the same transaction. For a private recipient it waits in their mailbox. The transfer code does not know which.

## Order of execution

Messages are processed depth first. When a handler returns several messages, the first is delivered and everything it triggers completes before the second is delivered. SyncMessages go before the AsyncMessages of the same response.

A handler can therefore be entered more than once in a transaction. The second time, `pre_state` is the state its first run wrote.

## Replies

There is no read access to another actor's state, so reading is done with two messages. The native token shows the shape:

```rust
Message::ReadState => {
    let reader = input.from.ok_or(TransferError::UnroutableRead { account_id })?;
    Response::keep_state().send_sync(reader, &Message::StateReply(StateReply::from(input)))
}
```

The asking actor sends `ReadState`. The balance actor answers with its state. The asking program must handle the reply, and it must check who sent it. The fee program does it this way (`lez/programs/fee/src/main.rs`):

```rust
if input
    .from
    .is_some_and(|from| from.program_account_id == NATIVE_TOKEN_PROGRAM_ID)
{
    let NativeMessage::StateReply(reply) =
        borsh::from_slice(&input.message).expect("a native message must decode")
    else {
        panic!("The native program sends the fee program only state replies");
    };
    return pay_out(input, &reply);
}
```

It decodes with the native token's message type only when the sender is the native token program. Without the sender check anyone could send a forged reply.

A message submitted by the transaction's author has no sender, so nothing can reply to it. `ReadState` sent that way fails.

## Message types

Messages are bytes. The receiver's program defines the format, and the sender must encode in it. A program therefore needs a handler for every message it can **receive**, not for those it sends.

A layout that keeps handlers honest:

```rust
/// Anyone may send these.
enum Message { Transfer { .. }, ReadState }

/// Only actors of this same program may send these.
enum Internal { Credit(u128) }

/// Sent to other programs; never received.
enum Outbound { StateReply(..) }
```

The handler looks at `input.from` first, then decodes with the type that sender is allowed to use. This is a recommendation of this book. The shipped programs use one enum each and check the sender inside the match arm.

## Validity windows

A handler can limit when its transaction is valid:

```rust
Response::keep_state().timestamp_window(deadline..)
```

An open-ended range (`from..` or `..to`) goes to `block_window` or `timestamp_window`. A closed range can be empty, so it goes to `try_block_window` or `try_timestamp_window`, which return an error for an empty one.

The windows of all handlers in a transaction are intersected. The sequencer checks the result against the block being built. A lower bound is inclusive and an upper bound is exclusive. An empty intersection fails the transaction.

## Events

A handler can emit events: an 8-byte selector and data. Events from public handlers are attached to the transaction for indexers. Events from private handlers are dropped.

## Small helpers

- `input.from_own_program()`: true when the sender is an actor of the receiver's own program.
- `write_once(pre_state, data)`: returns `data`, and panics if the state already holds something different. Use it for values that must be set once.
