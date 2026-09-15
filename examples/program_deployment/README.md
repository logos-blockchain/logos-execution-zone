# Program deployment tutorial

This guide walks you through running the sequencer, compiling example programs, deploying a Hello World program, and interacting with accounts.

You'll find:
- Programs: example LEZ programs under `methods/guest/src/bin`.
- Runners: scripts to create and submit transactions to invoke these programs publicly and privately under `src/bin`.

# 0. Install the wallet
From the project’s root directory:
```bash
cargo install --path wallet --force
```

# 1. Run the sequencer
From the project’s root directory, start the sequencer by following [these instructions](https://github.com/logos-blockchain/logos-execution-zone#run-the-sequencer-and-node).

## Checking and setting up the wallet
For sanity let's check that the wallet can connect to it.

```bash
wallet check-health
```

If this is your first time, the wallet will ask for a password. This is used as seed to deterministically generate all account keys (public and private).
For this tutorial, use: `program-tutorial`

You should see `✅All looks good!` if everything went well.

# 2. Compile the example programs
In a second terminal, from the `logos-execution-zone` root directory, compile the example Risc0 programs:
```bash
cargo risczero build --manifest-path examples/program_deployment/methods/guest/Cargo.toml
```
Because this repository is organized as a Cargo workspace, build artifacts are written to the
shared `target/` directory at the workspace root by default. The compiled `.bin` files will
appear under:
```
target/riscv32im-risc0-zkvm-elf/docker/
```
For convenience, export this path:
```bash
export EXAMPLE_PROGRAMS_BUILD_DIR=$(pwd)/target/riscv32im-risc0-zkvm-elf/docker
```

> [!IMPORTANT]
> **All remaining commands must be run from the `examples/program_deployment` directory.**

# 3. Hello world example

The Hello world program appends its instruction bytes to its own shard on the input account.

## Navigate to the example directory
All remaining commands must be run from:
```bash
cd examples/program_deployment
```

## Deploy the Program

Use the wallet’s built-in program deployment command:
```bash
wallet deploy-program $EXAMPLE_PROGRAMS_BUILD_DIR/hello_world.bin
```

# 4. Public execution of the Hello world example

## Create a Public Account

Generate a new public account:
```bash
wallet account new public
```

You'll see an output similar to:
```bash
Generated new account with account_id Public/BzdBoL4JRa5M873cuWb9rbYgASr1pXyaAZ1YW9ertWH9 at path /0
```
The relevant part is the account id `BzdBoL4JRa5M873cuWb9rbYgASr1pXyaAZ1YW9ertWH9`

> [!NOTE]
> You can optionally assign a label to the account for easier identification using the `--label` option: `wallet account new public --label "my-account"`. Labels must be unique across all accounts.

## Check the account state
New accounts are always Uninitialized. Verify:
```bash
wallet account get --account-id Public/BzdBoL4JRa5M873cuWb9rbYgASr1pXyaAZ1YW9ertWH9
```
Expected output:
```
Account is Uninitialized
```
The `Public/` prefix tells the wallet to query the public state.

## Execute the Hello world program
Run the example:
```bash
cargo run --bin run_hello_world \
    $EXAMPLE_PROGRAMS_BUILD_DIR/hello_world.bin \
    BzdBoL4JRa5M873cuWb9rbYgASr1pXyaAZ1YW9ertWH9
```
> [!NOTE]
> - Passing the `.bin` lets the script compute the program ID and build the transaction.
> - Because this program executes publicly, the node performs the execution.
> - The program will write data into the account.

Monitor the sequencer terminal to confirm execution.

## Inspect the updated account
After the transaction is processed, check the new state:
```bash
wallet account get --raw --account-id Public/BzdBoL4JRa5M873cuWb9rbYgASr1pXyaAZ1YW9ertWH9
```
Example output:
```json
{
  "balance": 0,
  "shards": {
    "<hello_world program account ID>": "486f6c61206d756e646f21"
  },
  "nonce": 0
}
```
The `shards` map contains hex-encoded data, keyed by program account ID. Decode the Hello World shard:
```bash
echo 486f6c61206d756e646f21 | xxd -r -p
```
You should see `Hola mundo!`.

Without `--raw`, the wallet prints each shard separately and decodes recognized token data as JSON.

# 5. Understanding `hello_world.rs`

[hello_world.rs](methods/guest/src/bin/hello_world.rs) handles an execution call with one input account. It appends the greeting to its own shard and leaves the balance unchanged:

```rust
let mut bytes = pre_state.shard_of(self_account_id).clone().into_inner();
bytes.extend_from_slice(&greeting);
let new_data = bytes.try_into().expect("Data should fit within the allowed limits");
let post_state = AccountStateDiff::new(pre_state, BalanceDiff::Add(0), new_data);
```

It returns the proposed change with:

```rust
ProgramOutput::new(
    self_account_id,
    caller_account_id,
    instruction_data,
    vec![post_state],
)
.write();
```

# 6. Understanding `run_hello_world.rs`

The [public runner](src/bin/run_hello_world.rs) loads the wallet and guest binary, selects the program's shard on the supplied account, and submits a public transaction:

```rust
let message = Message::try_new(
    program.id().into(),
    vec![ProgramShardSelector::new(account_id, program.id().into())],
    vec![],
    greeting,
)
.unwrap();
let witness_set = WitnessSet::for_message(&message, &[]);
let tx = PublicTransaction::new(message, witness_set);
```

The runner supplies no signatures or nonces. Hello World writes its own shard without checking account authorization.

# 7. Private execution of the Hello world example

This section is very similar to the previous case:

## Create a private account

Generate a new private account:
```bash
wallet account new private
```

You'll see an output similar to:
```bash
Generated new account with account_id Private/7EDHyxejuynBpmbLuiEym9HMUyCYxZDuF8X3B89ADeMr at path /0
```
The relevant part for this tutorial is the account id `7EDHyxejuynBpmbLuiEym9HMUyCYxZDuF8X3B89ADeMr`

> [!NOTE]
> As with public accounts, you can use the `--label` option to assign a label: `wallet account new private --label "my-private-account"`.

You can check it's uninitialized with

```bash
wallet account get --account-id Private/7EDHyxejuynBpmbLuiEym9HMUyCYxZDuF8X3B89ADeMr
```

## Privately executing the Hello world program

### Execute the Hello world program
Run the example:
```bash
cargo run --bin run_hello_world_private \
    $EXAMPLE_PROGRAMS_BUILD_DIR/hello_world.bin \
    7EDHyxejuynBpmbLuiEym9HMUyCYxZDuF8X3B89ADeMr
```
> [!NOTE]
> - This command may take a few minutes to complete. A ZK proof of the Hello world program execution and the privacy preserving circuit are being generated. Depending on the machine this can take from 30 seconds to 4 minutes.
> - We are passing the same `hello_world.bin` binary as in the previous case with public executions. This is because the program is the same, it is the privacy context of the input account that's different.
> - Because this program executes privately, the local machine runs the program and generate the proof of execution.
> - The program writes to its own shard on the private account.

### Syncing the new private account values
The `run_hello_world` script submitted a transaction and it was (hopefully) accepted by the node. On chain there is now a commitment to the new private account values, and the account data is stored encrypted. However, the local client hasn’t updated its private state yet. That’s why, if you try to get the private account values now, it still reads the old values from local storage instead.

```bash
wallet account get --account-id Private/7EDHyxejuynBpmbLuiEym9HMUyCYxZDuF8X3B89ADeMr
```

This will still show `Account is Uninitialized`. To see the new values locally, you need to run the wallet sync command. Once the client syncs, the local store will reflect the updated account data.

To sync private accounts run:
```bash
wallet account sync-private
```
> [!NOTE]
> - This queries the node for transactions and goes throught the encrypted accounts. Whenever a new value is found for one of the owned private accounts, the local storage is updated.

After this completes, running
```bash
wallet account get --raw --account-id Private/7EDHyxejuynBpmbLuiEym9HMUyCYxZDuF8X3B89ADeMr
```
should show something similar to
```json
{
  "balance": 0,
  "shards": {
    "<hello_world program account ID>": "486f6c61206d756e646f21"
  },
  "nonce": 236788677072686551559312843688143377080
}
```

## The `run_hello_world_private.rs` runner

The [private runner](src/bin/run_hello_world_private.rs) selects the same program shard. The wallet prepares the private account witnesses, executes the program, generates proofs, and submits the transaction:

```rust
let accounts = vec![
    AccountIdentity::PrivateOwned(account_id).select_program_shard(program.id().into()),
];

wallet_core
    .send_privacy_preserving_tx(
        accounts,
        Program::serialize_instruction(greeting).unwrap(),
        &program.into(),
    )
    .await
    .unwrap();
```

# 8. Account authorization mechanism
The Hello World program does not check `is_authorized` before writing its shard.
For regular accounts, authorization comes from:

- a transaction signature for a public account;
- knowledge of the authorization secret key (`ask`) for a private account.

Programs receive the result in `AccountInput::is_authorized`. The authorized Hello World example checks it before writing:

```rust
if !pre_state.is_authorized {
    panic!("Missing required authorization");
}
```

# 9. Public execution of the Hello world with authorization example
The workflow to execute it publicly is very similar:

### Deploy the program
```bash
wallet deploy-program $EXAMPLE_PROGRAMS_BUILD_DIR/hello_world_with_authorization.bin
```

### Create a new public account
Create a new account for this example. You can also reuse the previous account: each program writes its own shard.
```bash
wallet account new public
```

Outupt:
```
Generated new account with account_id Public/9Ppqqf8NeCX58pnr8ZqKoHvSoYGqH79dSikZAtLxKgXE at path /1
```

### Run the program

```bash
cargo run --bin run_hello_world_with_authorization \
    $EXAMPLE_PROGRAMS_BUILD_DIR/hello_world_with_authorization.bin \
    9Ppqqf8NeCX58pnr8ZqKoHvSoYGqH79dSikZAtLxKgXE
```

# 10. Understanding `run_hello_world_with_authorization.rs`

The [authorized runner](src/bin/run_hello_world_with_authorization.rs) selects the program's shard as before. It also:

- loads the account's signing key;
- includes the account's current nonce in the message;
- passes the key to `WitnessSet::for_message` to sign the transaction.

## Seeing the mechanism in action
If everything went well you won't notice any difference with the first Hello world, because the runner takes care of signing the transaction to provide authorization and the program just succeeds.
Try using the `run_hello_world.rs` runner with the `hello_world_with_authorization.bin` program. This will fail because the runner will submit the transaction without the corresponding signature.
```bash
cargo run --bin run_hello_world \
    $EXAMPLE_PROGRAMS_BUILD_DIR/hello_world_with_authorization.bin \
    9Ppqqf8NeCX58pnr8ZqKoHvSoYGqH79dSikZAtLxKgXE
```

You should see something like the following **on the node logs**.
```bash
[2025-12-11T13:43:22Z WARN  sequencer_core] Error at transition ProgramExecutionFailed(
        "Guest panicked: Missing required authorization",
    )
```

# 11. Public and private account interaction example
Previous examples only operated on public or private accounts independently. Those minimal programs were useful to introduce basic concepts, but they couldn't demonstrate how different types of accounts interact within a single program invocation.
The "Hello world with move function" introduces two operations that require one or two input accounts:
- `write`: appends bytes to the program's shard on one account.
- `move_data`: moves all bytes from the program's shard on one account to its shard on another.
This example moves data between the program's shards on public and private accounts.

> [!NOTE]
> The program logic is completely agnostic to whether input accounts are public or private. It always executes the same way.
> See `methods/guest/src/bin/hello_world_with_move_function.rs`. The program just reads the instruction bytes and updates the accounts state.
> All privacy handling happens on the runner side. When constructing the transaction, the runner decides which accounts are public or private and prepares the appropriate proofs. The program itself can't differentiate between privacy modes.

Let's start by deploying the program
```bash
wallet deploy-program $EXAMPLE_PROGRAMS_BUILD_DIR/hello_world_with_move_function.bin
```

Let's also create a new public account
```bash
wallet account new public
```

Output:
```
Generated new account with account_id Public/95iNQMbmxMRY6jULiHYkCzCkYKPEuysvBh5kEHayDxLs at path /0/0
```

Let's execute the write function

```bash
cargo run --bin run_hello_world_with_move_function \
    $EXAMPLE_PROGRAMS_BUILD_DIR/hello_world_with_move_function.bin \
    write-public 95iNQMbmxMRY6jULiHYkCzCkYKPEuysvBh5kEHayDxLs mundo!
```

Let's crate a new private account.

```bash
wallet account new private
```

Output:
```
Generated new account with account_id Private/8vzkK7vsdrS2gdPhLk72La8X4FJkgJ5kJLUBRbEVkReU at path /1
```

Let's execute the write function

```bash
cargo run --bin run_hello_world_with_move_function \
    $EXAMPLE_PROGRAMS_BUILD_DIR/hello_world_with_move_function.bin \
    write-private 8vzkK7vsdrS2gdPhLk72La8X4FJkgJ5kJLUBRbEVkReU Hola
```

To check the values of the accounts are as expected run:
```bash
wallet account get --account-id Public/95iNQMbmxMRY6jULiHYkCzCkYKPEuysvBh5kEHayDxLs
```
and

```bash
wallet account sync-private
wallet account get --account-id Private/8vzkK7vsdrS2gdPhLk72La8X4FJkgJ5kJLUBRbEVkReU
```

and check that the shard data decodes to `mundo!` and `Hola` respectively.

Now move the program's shard data from the public account to the private account.

```bash
cargo run --bin run_hello_world_with_move_function \
    $EXAMPLE_PROGRAMS_BUILD_DIR/hello_world_with_move_function.bin \
    move-data-public-to-private 95iNQMbmxMRY6jULiHYkCzCkYKPEuysvBh5kEHayDxLs 8vzkK7vsdrS2gdPhLk72La8X4FJkgJ5kJLUBRbEVkReU
```

After succeeding, repeat the get and sync commands. The program's shard should be empty on the public account and contain `Holamundo!` on the private account.

# 12. Program composition: tail calls
Programs can chain calls to other programs when they return. This is the tail call or chained call mechanism. It is used by programs that depend on other programs.

The examples include a `guest/src/bin/simple_tail_call.rs` program that shows how to trigger this mechanism. It internally calls the first Hello World program with a fixed greeting: `Hello from tail call`.

> [!NOTE]
> This program hardcodes the ID of the Hello World program. If something fails, check that this ID matches the one produced when building the Hello World program. You can see it in the output of `cargo risczero build` from the earlier sections of this tutorial. If it differs, update the ID in `simple_tail_call.rs` and build again.

As before, let's start by deploying the program

```bash
wallet deploy-program $EXAMPLE_PROGRAMS_BUILD_DIR/simple_tail_call.bin
```

We'll reuse public account `BzdBoL4JRa5M873cuWb9rbYgASr1pXyaAZ1YW9ertWH9`; its Hello World shard contains `Hola mundo!`.

Let's run the tail call program

```bash
cargo run --bin run_hello_world_through_tail_call \
    $EXAMPLE_PROGRAMS_BUILD_DIR/simple_tail_call.bin \
    BzdBoL4JRa5M873cuWb9rbYgASr1pXyaAZ1YW9ertWH9
```

Once the transaction is processed, query the account values with:

```bash
wallet account get --raw --account-id Public/BzdBoL4JRa5M873cuWb9rbYgASr1pXyaAZ1YW9ertWH9
```

You should se an output similar to

```json
{
  "balance": 0,
  "shards": {
    "<hello_world program account ID>": "486f6c61206d756e646f2148656c6c6f2066726f6d207461696c2063616c6c"
  },
  "nonce": 0
}
```

Decoding the data
```bash
echo 486f6c61206d756e646f2148656c6c6f2066726f6d207461696c2063616c6c | xxd -r -p
```

Output:
```
Hola mundo!Hello from tail call
```
## Private tail-calls
There's support for tail calls in privacy preserving executions too. The `run_hello_world_through_tail_call_private.rs` runner walks you through the process of invoking such an execution.
The only difference is that, since the execution is local, the runner will need both programs: the `simple_tail_call` and it's dependency `hello_world`.

Use the private account `8vzkK7vsdrS2gdPhLk72La8X4FJkgJ5kJLUBRbEVkReU` created in the previous example. This call writes its `hello_world` shard.

You can test the privacy tail calls with
```bash
cargo run --bin run_hello_world_through_tail_call_private \
    $EXAMPLE_PROGRAMS_BUILD_DIR/simple_tail_call.bin \
    $EXAMPLE_PROGRAMS_BUILD_DIR/hello_world.bin \
    8vzkK7vsdrS2gdPhLk72La8X4FJkgJ5kJLUBRbEVkReU
```

>[!NOTE]
> The above command may take longer than the previous privacy executions because needs to generate proofs of execution of both the `simple_tail_call` and the `hello_world` programs.

Once finished run the following to see the changes
```bash
wallet account sync-private
wallet account get --account-id Private/8vzkK7vsdrS2gdPhLk72La8X4FJkgJ5kJLUBRbEVkReU
```

# 13. Program derived accounts: authorizing accounts through tail calls

## Program shards and account authorization

Each account has a balance, a nonce, and program shards. A program can modify its own shard on any account. It can read another program's shard when that shard is selected as an input.

A `ProgramShardSelector` identifies an account and optionally a program shard. Omitting the program selects the balance without shard data.

Account authorization allows a program to debit the balance. Programs may also require authorization before changing their own shard.

Regular public accounts are authorized by a signature; regular private accounts by knowledge of `ask`.

Public and private PDAs are bound to an authority account and a seed. During a chained call, the authority program supplies the seed to authorize its PDAs for that call and its descendants.

## Running the example
[tail_call_with_pda.rs](methods/guest/src/bin/tail_call_with_pda.rs) calls Hello World with Authorization on its PDA, passing the seed to authorize the account. The callee writes its own shard; `tail_call_with_pda` remains the PDA's authority.

Deploy the program:
```bash
wallet deploy-program $EXAMPLE_PROGRAMS_BUILD_DIR/tail_call_with_pda.bin
```

There is no need to create a new account for this example, because we simply use one of the PDA accounts belonging to the `tail_call_with_pda` program.

Execute the program
```bash
cargo run --bin run_hello_world_with_authorization_through_tail_call_with_pda $EXAMPLE_PROGRAMS_BUILD_DIR/tail_call_with_pda.bin
```

You'll see an output like the following:

```bash
The program derived account ID is: 3tfTPPuxj3eSE1cLVuNBEk8eSHzpnYS1oqEdeH3Nfsks
```

Then check the status of that account

```bash
wallet account get --raw --account-id Public/3tfTPPuxj3eSE1cLVuNBEk8eSHzpnYS1oqEdeH3Nfsks
```

Output:
```json
{
  "balance": 0,
  "shards": {
    "<hello_world_with_authorization program account ID>": "48656c6c6f2066726f6d207461696c2063616c6c20776974682050726f6772616d2044657269766564204163636f756e74204944"
  },
  "nonce": 0
}
```



