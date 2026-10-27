# Quickstart: your first program on LEZ

The shortest path from an empty shell to a program you wrote running on chain and changing an account. It takes about half an hour, most of it waiting for builds.

Everything here runs against a local sequencer. Nothing touches a public network.

## What you need

Rust (the workspace pins a toolchain in `rust-toolchain.toml`), the RISC Zero toolchain (`rzup install`), and Docker for reproducible guest builds.

Install the wallet from the repository root:

```bash
cargo install --path lez/wallet --force
```

Now start the stack. It is three processes, each in its own terminal, and they must start in this order.

The Logos L1 node, from Docker:

```bash
just run-bedrock
```

The indexer, which answers questions about what happened:

```bash
RUST_LOG=info cargo run -p indexer_service lez/indexer/service/configs/debug/indexer_config.json
```

The sequencer, which produces blocks. Set it up once, then start it:

```bash
cargo run -p sequencer_service -- setup lez/sequencer/service/sequencer_home \
  --config lez/sequencer/service/configs/debug/sequencer_config.json \
  --funding-public-key 2e03b2eff5a45478e7e79668d2a146cf2c5c7925bce927f2b1c67f2ab4fc0d26 \
  --create-channel

RUST_LOG=info cargo run -p sequencer_service -- start lez/sequencer/service/sequencer_home
```

That public key is the local Bedrock node's funded key, fixed for the debug configuration. `--create-channel` is the step that brings the zone into existence: a zone is a channel on the L1, and every block the sequencer later produces is written into it. You only do it once.

Then check the wallet can reach the sequencer:

```bash
wallet check-health
```

On first run the wallet asks for a password twice. Set one, even on a devnet: on the current `dev` tree an unencrypted store cannot be read back once it holds a synced private account, and every later command fails with `Failed to parse storage file`. A non-empty password is then required by every later command, or read from `LEE_WALLET_PASSWORD`.

You should see `✅All looks good!`.

## Build the example programs

```bash
cargo risczero build --manifest-path examples/program_deployment/methods/guest/Cargo.toml
export EXAMPLES=$(pwd)/target/riscv32im-risc0-zkvm-elf/docker
```

The workspace writes guest artifacts to the shared `target/` at the repository root, so each program lands at `$EXAMPLES/<name>.bin`. The rest of this chapter runs from `examples/program_deployment`.

## Two accounts

You need an account for the program to write to, and a funded account to pay the fees.

```bash
wallet account new public --label first
```

The payer has to hold native tokens already: a fresh account cannot pay for its own claim. On a local devnet use a genesis-funded account, or transfer to your new account from one (see [Accounts and transfers](../use/accounts-and-transfers.md)).

New accounts start uninitialized. Confirm it:

```bash
wallet account get --scope all --account-id Public/<first account id>
```

It prints `Account is Uninitialized`. The `Public/` prefix tells the wallet which state to query.

## Run it

```bash
cargo run --bin run_hello_world $EXAMPLES/hello_world.bin <first account id> <payer account id>
```

The runner deploys the program and then sends it a message, in that order, so there is no separate deploy step. Watch the sequencer's terminal to see the transaction land.

Then read the account back:

```bash
wallet account get --raw --scope all --account-id Public/<first account id>
```

```json
{
  "actor_states": {
    "<hello_world program account id>": "486f6c61206d756e646f21"
  },
  "nonce": 0
}
```

`actor_states` maps a program account id to that program's state on this account. Decode it:

```bash
echo 486f6c61206d756e646f21 | xxd -r -p
```

`Hola mundo!`. You have deployed a program and changed an account with it.

Without `--raw` the wallet prints each actor state separately and decodes the state of programs it recognizes.

## The same program, privately

```bash
wallet account new private --label first-private
cargo run --bin run_hello_world_private $EXAMPLES/hello_world.bin <private account id> <payer account id>
```

This one takes from thirty seconds to a few minutes: your machine is executing the program and proving it, rather than the sequencer executing it. Expect no change to the program. The bytecode is identical, and the only difference is the privacy of the account it was pointed at.

Reading it back needs one extra step, because the chain holds only a commitment and an encrypted note:

```bash
wallet account sync-private
wallet account get --raw --scope all --account-id Private/<private account id>
```

Before the sync the wallet still reports the account uninitialized, because it has not yet scanned the chain for notes it can decrypt. After it, the state reads the same `Hola mundo!` as the public run, and the nonce is a large number rather than 0: a private account's nonce is a hash chain, not a counter.

## What just happened

The program is fourteen lines, at `examples/program_deployment/methods/guest/src/bin/hello_world.rs`:

```rust
use lee_core::program::{ReceiveInput, Response};

lee_core::actor_entrypoint!(handle_message);

fn handle_message(input: &ReceiveInput, greeting: Vec<u8>) -> Response {
    let mut bytes = input.pre_state.to_vec();
    bytes.extend(greeting);
    Response::set_state(bytes)
}
```

That is the whole programming model in one function. The handler receives one message addressed to one actor, sees that actor's current state in `input.pre_state`, and returns a new state. It cannot read or write anything else. [Accounts, actors and state](actors.md) explains what an actor is, and [Handlers and messages](messages.md) explains what else a handler may return.

`actor_entrypoint!` is the macro that decodes the message, calls the handler and commits the result. The same binary served both the public and the private run, because a program never learns whether its account is public or private. That property is the reason the privacy model works, and its limits are in [What a private transaction reveals](../privacy/what-leaks.md).

## Deploying without a runner

The runners deploy for you by calling `deploy_program` (`examples/program_deployment/src/lib.rs`), which creates the header and segment accounts, chunks the ELF, and marks the program immutable. To do it yourself, create the accounts first and use the loader directly:

```bash
wallet account new public --label my-header
wallet account new public --label my-seg-0   # and seg-1, seg-2, ...
wallet program-loader deploy \
  --elf $EXAMPLES/hello_world.bin \
  --header my-header \
  --segments my-seg-0 my-seg-1 my-seg-2 \
  --immutable
```

The CLI chunks the ELF but does not create accounts: you need one segment account per `MAX_SEGMENT_DATA_LEN` of 96 KiB, and a wrong count fails with `SegmentCountMismatch`, which reports the number expected. A deploy that fails partway cannot currently be resumed over the same accounts.

## Next

[The example programs](examples.md) walks the rest of the examples in the repository, each one adding a single idea: authorization, a message enum, sending to another actor, program-derived accounts, and gating on time.
