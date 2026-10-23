# The example programs

Five programs, each adding exactly one idea to the one before. The full source of each is here, so you can read this chapter without the repository open and type any of them into a crate of your own.

They live at `examples/program_deployment/methods/guest/src/bin/`, with a runner each under `src/bin/`. Run everything from `examples/program_deployment`, with `EXAMPLES` exported as in the [quickstart](quickstart.md).

Every runner takes the same last two arguments: the account to send to, and a funded account to pay the fee.

## 1. hello_world

Appends its message to its own state. The whole program:

```rust
use lee_core::program::{ReceiveInput, Response};

lee_core::actor_entrypoint!(handle_message);

fn handle_message(input: &ReceiveInput, greeting: Vec<u8>) -> Response {
    let mut bytes = input.pre_state.to_vec();
    bytes.extend(greeting);
    Response::set_state(bytes)
}
```

```bash
cargo run --bin run_hello_world $EXAMPLES/hello_world.bin <account> <payer>
```

The handler contract, and nothing else: one message in, one actor's state in, a new state out. Covered by [Accounts, actors and state](actors.md).

## 2. hello_world_with_authorization

One line more:

```rust
fn handle_message(input: &ReceiveInput, greeting: Vec<u8>) -> Response {
    // `is_authorized` is set by the protocol: from the account's signature, or from a
    // PDA seed the sending program granted.
    assert!(input.is_authorized, "Missing required authorization");

    let mut bytes = input.pre_state.to_vec();
    bytes.extend(greeting);
    Response::set_state(bytes)
}
```

```bash
cargo run --bin run_hello_world_with_authorization \
  $EXAMPLES/hello_world_with_authorization.bin <account> <payer>
```

Authorization comes from a transaction signature for a public account, or from knowledge of `ask` for a private one. Covered by [Authorization](authorization.md).

Do this next, deliberately: point the *unauthorized* runner at this program.

```bash
cargo run --bin run_hello_world $EXAMPLES/hello_world_with_authorization.bin <account> <payer>
```

The sequencer logs `ProgramExecutionFailed("Guest panicked: Missing required authorization")`. Seeing your own assertion message come back as a transaction failure, once, early, teaches more than the chapter does.

## 3. hello_world_with_move_function

A message enum instead of raw bytes, and the first program that touches two accounts.

```rust
use lee_core::{
    account::{AccountId, Actor},
    program::{ReceiveInput, Response},
};

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum Message {
    Write(Vec<u8>),
    MoveData { data: Vec<u8>, to: AccountId },
    Append(Vec<u8>),
}

lee_core::actor_entrypoint!(handle_message);

fn handle_message(input: &ReceiveInput, message: Message) -> Response {
    match message {
        Message::Write(data) => append(input, &data),
        Message::MoveData { data, to } => {
            assert_eq!(
                input.pre_state.as_ref(),
                data.as_slice(),
                "the source account does not hold the bytes the instruction moves out of it"
            );
            Response::set_state(Vec::new()).send_sync(
                Actor::new(to, input.receiver.program_account_id),
                &Message::Append(data),
            )
        }
        Message::Append(data) => {
            assert!(
                input.from_own_program(),
                "only a move of this program appends to its destination"
            );
            append(input, &data)
        }
    }
}

fn append(input: &ReceiveInput, data: &[u8]) -> Response {
    Response::set_state([input.pre_state.as_ref(), data].concat())
}
```

```bash
cargo run --bin run_hello_world_with_move_function $EXAMPLES/hello_world_with_move_function.bin \
  <payer> write-public <account> mundo!
cargo run --bin run_hello_world_with_move_function $EXAMPLES/hello_world_with_move_function.bin \
  <payer> write-private <private account> Hola
cargo run --bin run_hello_world_with_move_function $EXAMPLES/hello_world_with_move_function.bin \
  <payer> move-data-public-to-private <public account> <private account>
```

Three things are worth seeing in those twenty lines.

The program is identical in all three runs and never learns which accounts are public. The runner decides that when it builds the transaction. This is the property the whole privacy model rests on, and it is in [Transactions, public and private](transactions.md).

`MoveData` carries the data the caller claims the source holds, and the source refuses unless its state is exactly that. The caller's claim is pinned against the state that knows the truth, rather than trusted. That is the single most repeated idea in [the pattern language](../patterns/index.md).

`Append` guards with `input.from_own_program()`, so only this program's own move can append to a destination. Without that line anyone could append to anyone's state by sending `Append` directly. Routing on the sender is pattern 2.

## 4. simple_tail_call

The first program that talks to another program.

```rust
use lee_core::{
    account::Actor,
    program::{ReceiveInput, Response},
};

lee_core::actor_entrypoint!(handle_message);

fn handle_message(_input: &ReceiveInput, callee: Actor) -> Response {
    let greeting: Vec<u8> = b"Hello from tail call".to_vec();

    Response::keep_state().send_sync(callee, &greeting)
}
```

```bash
cargo run --bin run_hello_world_through_tail_call \
  $EXAMPLES/simple_tail_call.bin $EXAMPLES/hello_world.bin <account> <payer>
```

`keep_state()` because it changes nothing of its own; it exists only to send. The callee arrives in the message rather than being a constant, because a program's address is not known until it is deployed, which is a practical constraint worth internalising early.

The private form needs both binaries, because your machine executes and proves both programs:

```bash
cargo run --bin run_hello_world_through_tail_call_private \
  $EXAMPLES/simple_tail_call.bin $EXAMPLES/hello_world.bin <private account> <payer>
```

Covered by [Handlers and messages](messages.md).

## 5. tail_call_with_pda

A program authorizing an account that no key controls.

```rust
use lee_core::{
    account::{AccountId, Actor},
    program::{PdaSeed, ReceiveInput, Response, SyncMessage},
};

const PDA_SEED: PdaSeed = PdaSeed::new([37; 32]);

lee_core::actor_entrypoint!(handle_message);

fn handle_message(input: &ReceiveInput, callee_account_id: AccountId) -> Response {
    let greeting: Vec<u8> = b"Hello from tail call with Program Derived Account ID".to_vec();

    Response::keep_state().send(
        SyncMessage::new(
            Actor::new(input.receiver.account_id, callee_account_id),
            &greeting,
        )
        .with_pda_seeds(vec![PDA_SEED]),
    )
}
```

```bash
cargo run --bin run_hello_world_with_authorization_through_tail_call_with_pda \
  $EXAMPLES/tail_call_with_pda.bin $EXAMPLES/hello_world_with_authorization.bin <payer>
```

It prints the derived account id, which you can then read like any other account.

The program expects to receive at an account derived from its own deployed address and `PDA_SEED`, via `AccountId::for_public_pda`. By attaching that seed with `with_pda_seeds`, it tells the protocol to treat the account as authorized for the message it is sending. Note the callee here is `hello_world_with_authorization`, the program that refuses without authorization: the seed grant is what makes it succeed.

That is the whole mechanism behind program-controlled funds. A vault is an account whose authority is a program and a seed rather than a key. Covered by [Authorization](authorization.md).

## The protocol's own test programs

Smaller and sharper, under `test_programs/guest/src/bin/`. They are built with `risc0_build::embed_methods()` in a `build.rs` rather than the Docker builder, so they are not reproducible but need no Docker.

| Program | Mechanism | Chapter |
|---|---|---|
| `cooldown.rs` | refuses to run until a cooldown has elapsed, by sending an assertion to the clock rather than reading time | [System programs](system-programs.md) |
| `time_locked_transfer.rs` | the deadline travels in the message and an `AssertTimestamp` to the clock compares it; the transfer settles only once the clock passes it, otherwise the whole transaction rolls back | [System programs](system-programs.md) |
| `live_payout.rs` | reads another actor's live native balance by asking for it and handling the reply, then pays a tenth of it | pattern 5, [The pattern language](../patterns/index.md) |
| `listener.rs` | the `raw` form of `actor_entrypoint!`, where the handler takes only `ReceiveInput` and decodes nothing | [Toolchain](toolchain.md) |
| `scripted.rs` | a handler driven by a `Script` value, used to drive arbitrary sequences in protocol tests | [Toolchain](toolchain.md) |

`cooldown.rs` and `time_locked_transfer.rs` are the two to read. Between them they show the whole approach to time: a program never reads the clock, it asserts against it, and the assertion is evaluated where the clock is authoritative.

## What no example covers yet

None of these sends an async message, collects a stored one from a mailbox, has a private actor send to a public one, or uses a group-held account. Those are the mechanisms in [Handlers and messages](messages.md) and [Private accounts](private-accounts.md) with no runnable counterpart, and they are the most valuable examples still missing.
