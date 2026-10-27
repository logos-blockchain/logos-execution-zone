# Guest API cheat sheet

Everything a handler uses is in `lee_core::program` and `lee_core::account` (`lee/state_machine/core/src/program/mod.rs`, `account.rs`).

## Entry

```rust
lee_core::actor_entrypoint!(handle_message);       // message decoded with Borsh
lee_core::actor_entrypoint!(raw handle_message);   // handler decodes it

fn handle_message(input: &ReceiveInput, message: MyMessage) -> Response { .. }
fn handle_message(input: &ReceiveInput) -> Response { .. }                    // raw form
```

A panic anywhere fails the whole transaction.

## Input

```rust
pub struct ReceiveInput {
    pub receiver: Actor,
    pub from: Option<Actor>,
    pub is_authorized: bool,
    pub pre_state: ActorState,
    pub message: MessageData,      // Vec<u8>
}

input.from_own_program()           // sender is an actor of the receiver's program
```

| Field | Value |
|---|---|
| `receiver` | the actor this run is for |
| `from` | the sending actor, at the address it presented. `None` when the transaction's author submitted the message. A collected stored message keeps its original sender. |
| `is_authorized` | the receiving account is authorized: signature, spending key, or seed grant |
| `pre_state` | the actor's state before this message; empty if never written |

## Actors and ids

```rust
Actor::new(account_id, program_account_id)
Actor::native_balance(account_id)

AccountId::for_public_pda(&program_account_id, &seed)
AccountId::from_builtin_program_name(b"clock")
account_id.blinded(&factor)

PdaSeed::new([u8; 32])
```

## Response

```rust
Response::keep_state()
Response::set_state(bytes)                 // anything Into<ActorState>

    .send_sync(to, &message)                    // SyncMessage, message Borsh-encoded
    .send_async(to, &message)                    // AsyncMessage, message Borsh-encoded
    .send(SyncMessage::new(to, &message).with_pda_seeds([seed]))
    .send(AsyncMessage { to, message: raw_bytes })

    .event(ProgramEvent { selector, data })

    .block_window(from..)                  // also ..to and ..
    .timestamp_window(from..)
    .try_block_window(from..to)?           // a closed range may be empty
    .try_timestamp_window(from..to)?
```

| Message | Delivered | Carries seeds | If the receiver fails |
|---|---|---|---|
| `SyncMessage` | now | yes | the whole transaction fails |
| `AsyncMessage` to a declared public actor | now | no | the whole transaction fails |
| `AsyncMessage` to one of the submitter's private actors, promoted | now | no | the whole transaction fails |
| `AsyncMessage` to any other address | stored | no | the sender is not affected |

Window bounds: the start is inclusive, the end is exclusive.

## Helpers

```rust
write_once(&pre_state, data)     // returns data; panics if the state holds something different
```

## Native token

```rust
use lee_core::native_token::{self, Message};

Message::Transfer { to, amount }        // needs is_authorized; sends Credit async
Message::Credit(amount)                 // only from the native token program
Message::ReadState                      // replies to the sender with StateReply

native_token::custody_transfer(from_pda, seed, to, amount)   // a SyncMessage with the seed attached
```

## Clock

```rust
use clock_core::{CLOCK_01_PROGRAM_ACCOUNT_ID, CLOCK_10_PROGRAM_ACCOUNT_ID,
                 CLOCK_50_PROGRAM_ACCOUNT_ID, Message};

let clock = Actor::new(CLOCK_10_PROGRAM_ACCOUNT_ID, clock_core::clock_account_id());
Response::keep_state().send_sync(clock, &Message::AssertTimestamp { at_least, at_most })
```

## Errors you can trigger

These fail the transaction. All but the last come from the engine (`ExecutionError`, `lee/state_machine/core/src/execution_state.rs`).

| Error | Cause |
|---|---|
| `UndeclaredActor` | a SyncMessage to an actor the transaction did not declare and cannot run |
| `UnadmittedPublicActor` | a message to a public account that does not exist and came with no evidence |
| `TransitionInputMismatch` | a handler's proof was made for a different input |
| `BoundaryMismatch`, `CrossMessageMismatch` | the public side did not do what the proof assumed |
| `LoaderOutsidePublicExecution` | a message to the program loader inside a private transaction |
| `EmptyValidityWindowIntersection` | two handlers' validity windows do not overlap |
| `UnboundAsyncDestination` | an AsyncMessage **from a public actor** to an address with no recovery binding, which includes any undeclared public account. Raised at settlement, so it is a `LeeError` (`lee/state_machine/src/error.rs`), not an `ExecutionError` |

## Testing

A handler is a function. Build a `ReceiveInput` and call it:

```rust
let input = ReceiveInput {
    receiver: Actor::new(account, PROGRAM),
    from: None,
    is_authorized: true,
    pre_state: ActorState::from(state_bytes),
    message: borsh::to_vec(&message).unwrap(),
};
let transition = handle_message(&input, message).into_transition(input);
assert_eq!(transition.response.post_state, Some(expected));
assert_eq!(transition.response.sync_messages, vec![..]);
```
