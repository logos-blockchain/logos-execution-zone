# Toolchain: build, deploy, test

The repository has a complete worked example in `examples/program_deployment`. This chapter follows it.

## A program crate

A guest program is a binary crate that depends on `lee_core`. Its source is a handler and one macro line:

```rust
use lee_core::program::{ReceiveInput, Response};

lee_core::actor_entrypoint!(handle_message);

fn handle_message(input: &ReceiveInput, greeting: Vec<u8>) -> Response {
    assert!(input.is_authorized, "Missing required authorization");
    let mut bytes = input.pre_state.to_vec();
    bytes.extend(greeting);
    Response::set_state(bytes)
}
```

The second parameter can be any type that implements `BorshDeserialize`. In practice it is an enum of the messages the program accepts.

Put the message types in a separate `core` crate, as the shipped programs do (`lez/programs/clock/core`, or `logos-blockchain/lez-programs: programs/token/core`). Wallets, tests and other programs need the types without the guest code.

## Building

```text
cargo risczero build --manifest-path examples/program_deployment/methods/guest/Cargo.toml
```

The output is one `.bin` file per binary in the guest crate.

## Deploying

```text
wallet account new public --label hello-header
wallet account new public --label hello-seg-0   # and seg-1, seg-2, ...
wallet program-loader deploy --elf path/to/hello_world.bin \
  --header hello-header --segments hello-seg-0 hello-seg-1 hello-seg-2 --immutable
```

`deploy` takes no positional path. The accounts must exist already with an empty `program_loader` state, and the wallet chunks the ELF but never creates accounts. You need one segment account per 96 KiB of the user ELF (`MAX_SEGMENT_DATA_LEN`), so a typical program takes several; a wrong count fails with `SegmentCountMismatch`, which reports the number expected. A deploy that fails partway cannot currently be resumed over the same accounts. The example's README still writes `wallet deploy-program`, which no longer exists; run `wallet program-loader --help` to confirm the arguments.

## Accounts

```text
wallet account new public  --label my-account
wallet account new private --label my-private-account
wallet account get --scope all --account-id Public/<id>
wallet account get --scope all --account-id Private/<id>
```

The `Public/` or `Private/` prefix tells the wallet which state to query. Without `--raw`, the wallet prints each actor state on the account separately.

## Sending a message

There is no generic "send these bytes" command. Each example has a small runner that loads the wallet, selects the program's actor on an account, and submits a transaction:

```text
cargo run --bin run_hello_world -- ...
cargo run --bin run_hello_world_private -- ...
```

The two runners differ only in the account they are given. The program is the same. Read `examples/program_deployment/src/bin/` for the code; it is the template for your own client.

## Receiving stored messages

```text
wallet pending list
wallet pending receive --position <n>
```

## Testing a handler

A handler is an ordinary function. Test it without a prover, a chain or a wallet by building the input by hand. The clock program's tests show the shape (`lez/programs/clock/src/main.rs`):

```rust
fn run(account_id: AccountId, origin: Option<AccountId>, pre: ClockAccountData, message: Message)
    -> Transition
{
    let receiver = Actor::new(account_id, CLOCK);
    let input = ReceiveInput {
        receiver,
        from: origin.map(|sender| Actor::new(sender, sender)),
        is_authorized: false,
        pre_state: ActorState::from(pre.to_bytes()),
        message: borsh::to_vec(&message).unwrap(),
    };
    handle_message(&input, message).into_transition(input)
}

#[test]
#[should_panic(expected = "Clock records are only sent by the every-block clock account")]
fn a_record_from_another_program_is_refused() {
    let _ = run(CLOCK_50_PROGRAM_ACCOUNT_ID, Some(AccountId::new([3; 32])), data(40),
                Message::Record(data(50)));
}
```

Test each message as three questions:

1. With an honest sender and authorization, is the new state right and are the right messages sent?
2. With the wrong sender, is it refused?
3. Without authorization, is it refused?

Because a handler sees only its own state, these tests cover the program. What they do not cover is the conversation between actors. For that, run a local sequencer and the wallet, as the integration tests under `integration_tests/` do.

## Proving in development

Set `RISC0_DEV_MODE=1` to skip real proving while developing. Private transactions then build in seconds. Never use it on a real network.

## Versioning

Decide on the first day how your actor state and your messages are versioned. Both outlive the code: state stays on accounts, and async messages stay in mailboxes. See [Upgrades](programs.md).
