# Program deployment tutorial

This guide walks you through running the sequencer, compiling example programs, deploying a Hello World program, and interacting with accounts.

You'll find:
- Programs: example LEZ programs under `methods/guest/src/bin`.
- Runners: scripts under `src/bin` that deploy these programs, then create and submit transactions to invoke them publicly and privately.

# 0. Install the wallet
From the project’s root directory:
```bash
cargo install --path lez/wallet --force
```

# 1. Run the sequencer
From the project’s root directory, start the sequencer by following [these instructions](https://github.com/logos-blockchain/logos-execution-zone#run-the-sequencer-and-node).

## Checking and setting up the wallet
A new wallet points at the public testnet, so switch it to your local sequencer:

```bash
wallet change-network local
```

If this is your first time, the wallet will ask for a password, twice; leave it empty to keep the wallet storage unencrypted. A non-empty password encrypts it, and every later wallet command then asks for it (or reads it from `LEE_WALLET_PASSWORD`). The runners in this tutorial load the same wallet, so they ask for it too.
For this tutorial, use: `program-tutorial`

The wallet then prints a recovery phrase.

For sanity let's check that the wallet can connect to the sequencer.

```bash
wallet check-health
```

You should see `✅All looks good!` if everything went well.

## Import a funded account
Deploying a program and sending a transaction both cost fees, and a new account has no balance to pay them. The local network's genesis funds a test account, so import it:

```bash
wallet account import public --private-key 7f273098f25b71e6c005a9519f2678da8d1c7f01f6a27778e2d9948abdf901fb
```

Output:
```
Imported public account Public/CbgR6tj5kWx5oziiFptM7jMvrQeYY3Mzaao6ciuhSr2r
```

Every runner takes this account as its fee payer. For convenience, export it:
```bash
export PAYER=CbgR6tj5kWx5oziiFptM7jMvrQeYY3Mzaao6ciuhSr2r
```

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

> [!NOTE]
> `cargo risczero build` needs access to Docker. Without it, build the programs with the local Risc0 toolchain instead:
> ```bash
> cargo build --release -p example_program_deployment_methods
> export EXAMPLE_PROGRAMS_BUILD_DIR=$(pwd)/target/riscv-guest/example_program_deployment_methods/example_program_deployment_programs/riscv32im-risc0-zkvm-elf/release
> ```

> [!IMPORTANT]
> **All remaining commands must be run from the `examples/program_deployment` directory.**
> Run them in a terminal that has both `PAYER` and `EXAMPLE_PROGRAMS_BUILD_DIR` exported, and stay in it: later sections export more IDs there.

# 3. Hello world example

The Hello world program appends its instruction bytes to its own actor state on the input account.

## Navigate to the example directory
All remaining commands must be run from:
```bash
cd examples/program_deployment
```

## How programs get deployed

You don't deploy the programs by hand in this tutorial: each runner deploys the `.bin` files it is given, paying with `$PAYER`, and then calls the program.

A deployed program is addressed by its program account ID, which is the account holding its header. Each runner prints that ID for every program it deploys, in deploy order:
```
Deployed Program with {"program_id":"2SY3RTDvAST1Zkt92QZaDSDYtJUoLztxmTeYbdeyB9Wh"}
```

> [!IMPORTANT]
> By default every run deploys a **new instance** of the program, with a new program account ID, even from the same `.bin`. An actor state belongs to one instance, so such a run can't see what an earlier run wrote. To carry on from an earlier run, pass its program account ID to a runner that accepts one, as sections 11 and 12 do.

> [!NOTE]
> A deployment sends one transaction per bytecode segment plus one for the header, and waits for each to be included. Expect each deployed program to take a couple of minutes.

# 4. Public execution of the Hello world example

## Create a Public Account

Generate a new public account:
```bash
wallet account new public
```

You'll see an output similar to:
```bash
Generated new account with account_id Public/BzdBoL4JRa5M873cuWb9rbYgASr1pXyaAZ1YW9ertWH9 at path /0
With pk c6a806f0ad22491add5befe1c46dea33499528cf7663b7204bc1d802cab7ca35
```
The relevant part is the account id `BzdBoL4JRa5M873cuWb9rbYgASr1pXyaAZ1YW9ertWH9`

> [!NOTE]
> You can optionally assign a label to the account for easier identification using the `--label` option: `wallet account new public --label "my-account"`. Labels must be unique across all accounts.

## Check the account state
New accounts are always Uninitialized. Verify:
```bash
wallet account get --scope all --account-id Public/BzdBoL4JRa5M873cuWb9rbYgASr1pXyaAZ1YW9ertWH9
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
    BzdBoL4JRa5M873cuWb9rbYgASr1pXyaAZ1YW9ertWH9 \
    $PAYER
```
> [!NOTE]
> - Passing the `.bin` lets the script deploy the program and build the transaction.
> - Because this program executes publicly, the node performs the execution.
> - The program will write data into the account.

Monitor the sequencer terminal to confirm execution.

## Inspect the updated account
After the transaction is processed, check the new state:
```bash
wallet account get --raw --scope all --account-id Public/BzdBoL4JRa5M873cuWb9rbYgASr1pXyaAZ1YW9ertWH9
```
Example output:
```json
{
  "actor_states": {
    "<hello_world program account ID>": "486f6c61206d756e646f21"
  },
  "nonce": 0
}
```
The `actor_states` map contains hex-encoded data, keyed by program account ID. Decode the Hello World actor state:
```bash
echo 486f6c61206d756e646f21 | xxd -r -p
```
You should see `Hola mundo!`.

Section 12 calls this same instance again, so export the program account ID the runner printed:
```bash
export HELLO_WORLD_ID=<hello_world program account ID>
```

Without `--raw`, the wallet prints the balance and nonce, then each program's actor state in hex.

# 5. Understanding `hello_world.rs`

[hello_world.rs](methods/guest/src/bin/hello_world.rs) handles a message sent to one actor: an account paired with this program. It appends the greeting to its own actor state and leaves the balance unchanged:

```rust
fn handle_message(input: &ReceiveInput, greeting: Vec<u8>) -> Response {
    let mut bytes = input.pre_state.to_vec();
    bytes.extend(greeting);
    Response::set_state(bytes)
}
```

`actor_entrypoint!` decodes the greeting, calls the handler and writes the returned `Response`:

```rust
lee_core::actor_entrypoint!(handle_message);
```

# 6. Understanding `run_hello_world.rs`

The [public runner](src/bin/run_hello_world.rs) loads the wallet and guest binary, deploys the program, selects its actor state on the supplied account, and submits a public transaction:

```rust
let (fee, payer_nonce, payer_key) = fee_paid_by(&wallet_core, payer).await.unwrap();
let nonces = BTreeMap::from([(payer, payer_nonce)]);
let signing_keys = [payer_key];
let hello = Actor::new(account_id, program_account_id);
let message = Message {
    admission_evidence: admission_evidence(&wallet_core, account_id)
        .into_iter()
        .collect(),
    ..Message::try_new_with_fees(hello, vec![hello], nonces, greeting, fee).unwrap()
};
let witness_set = WitnessSet::sign(&message, &signing_keys);
let tx = PublicTransaction::new(message, witness_set);
```

Only the fee payer signs, and only its nonce is listed. The input account doesn't sign, because Hello World writes its own actor state without checking account authorization.

The input account may not exist on chain yet, so the sequencer only admits it as a public actor with evidence. `admission_evidence` (in [`lib.rs`](src/lib.rs)) supplies its initial key, which gives the account ID, when this wallet holds the account. Without evidence, a call on a fresh account reverts with `UnadmittedPublicActor` but is still charged.

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
followed by the account's keys. The relevant part for this tutorial is the account id `7EDHyxejuynBpmbLuiEym9HMUyCYxZDuF8X3B89ADeMr`

> [!NOTE]
> As with public accounts, you can use the `--label` option to assign a label: `wallet account new private --label "my-private-account"`.

You can check it's uninitialized with

```bash
wallet account get --scope all --account-id Private/7EDHyxejuynBpmbLuiEym9HMUyCYxZDuF8X3B89ADeMr
```

## Funding the private account
`$PAYER` pays for the public deployment, but a private execution pays its fee from a private account, inside the proof. Without one the runner fails with a `Fee reserve of ... fails` error, so move some balance to the new account:

```bash
wallet auth-transfer send \
    --from Public/$PAYER \
    --to Private/7EDHyxejuynBpmbLuiEym9HMUyCYxZDuF8X3B89ADeMr \
    --amount 1000000000
```

This is enough for every private execution in this tutorial.

## Privately executing the Hello world program

### Execute the Hello world program
Run the example:
```bash
cargo run --bin run_hello_world_private \
    $EXAMPLE_PROGRAMS_BUILD_DIR/hello_world.bin \
    7EDHyxejuynBpmbLuiEym9HMUyCYxZDuF8X3B89ADeMr \
    $PAYER
```
> [!NOTE]
> - This command may take a few minutes to complete. After the deployment, a ZK proof of the Hello world program execution and the privacy preserving circuit are being generated. Depending on the machine this can take from 30 seconds to 4 minutes.
> - We are passing the same `hello_world.bin` binary as in the previous case with public executions. This is because the program is the same, it is the privacy context of the input account that's different.
> - Because this program executes privately, the local machine runs the program and generate the proof of execution.
> - The program writes to its own actor state on the private account.

### Syncing the new private account values
The `run_hello_world_private` script submitted a transaction and it was (hopefully) accepted by the node. On chain there is now a commitment to the new private account values, and the account data is stored encrypted. However, the local client hasn’t updated its private state yet. That’s why, if you try to get the private account values now, it still reads the old values from local storage instead.

```bash
wallet account get --scope all --account-id Private/7EDHyxejuynBpmbLuiEym9HMUyCYxZDuF8X3B89ADeMr
```

This will still show only the balance from the funding transfer, with no Hello World actor state. To see the new values locally, you need to run the wallet sync command. Once the client syncs, the local store will reflect the updated account data.

To sync private accounts run:
```bash
wallet account sync-private
```
> [!NOTE]
> - This queries the node for transactions and goes throught the encrypted accounts. Whenever a new value is found for one of the owned private accounts, the local storage is updated.

After this completes, running
```bash
wallet account get --raw --scope all --account-id Private/7EDHyxejuynBpmbLuiEym9HMUyCYxZDuF8X3B89ADeMr
```
should show something similar to
```json
{
  "actor_states": {
    "11111111111111111111111111111111": "61b0cf3a000000000000000000000000",
    "<hello_world program account ID>": "486f6c61206d756e646f21"
  },
  "nonce": 90418918597888966381046669601944046620
}
```
The `11111111111111111111111111111111` entry is the account's balance: the native token program's actor state. It is lower than the amount you sent because the private transactions paid their fees from it.

## The `run_hello_world_private.rs` runner

The [private runner](src/bin/run_hello_world_private.rs) deploys the program and selects its actor state as before. The wallet prepares the private account witnesses, executes the program, generates proofs, and submits the transaction:

```rust
let account =
    AccountIdentity::PrivateOwned(account_id).select_program_actor_state(program_account_id);

wallet_core
    .send_privacy_preserving_tx(
        vec![account],
        0,
        Program::serialize_message(greeting).unwrap(),
        &programs,
    )
    .await
    .unwrap();
```

# 8. Account authorization mechanism
The Hello World program does not check `is_authorized` before writing its actor state.
For regular accounts, authorization comes from:

- a transaction signature for a public account;
- knowledge of the authorization secret key (`ask`) for a private account.

Programs receive the result in `ReceiveInput::is_authorized`. The authorized Hello World example checks it before writing:

```rust
assert!(input.is_authorized, "Missing required authorization");
```

# 9. Public execution of the Hello world with authorization example
The workflow to execute it publicly is very similar:

### Create a new public account
Create a new account for this example. You can also reuse the previous account: each program writes its own actor state.
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
    9Ppqqf8NeCX58pnr8ZqKoHvSoYGqH79dSikZAtLxKgXE \
    $PAYER
```

# 10. Understanding `run_hello_world_with_authorization.rs`

The [authorized runner](src/bin/run_hello_world_with_authorization.rs) selects the program's actor state as before. It also:

- loads the secret the account's signing keys derive from;
- includes the account's current nonce in the message, next to the fee payer's;
- passes its key at that nonce, with the key state at the next nonce, to `WitnessSet::sign`,
  next to the fee payer's, to sign the transaction and rotate both accounts to their next keys.

The account's signature is what authorizes it. The fee payer's signature only covers the fee.

## Seeing the mechanism in action
If everything went well you won't notice any difference with the first Hello world, because the runner takes care of signing the transaction to provide authorization and the program just succeeds. The account's nonce goes up by one, because it signed.
Try using the `run_hello_world.rs` runner with the `hello_world_with_authorization.bin` program. This will fail because the runner will submit the transaction without the account's signature.
```bash
cargo run --bin run_hello_world \
    $EXAMPLE_PROGRAMS_BUILD_DIR/hello_world_with_authorization.bin \
    9Ppqqf8NeCX58pnr8ZqKoHvSoYGqH79dSikZAtLxKgXE \
    $PAYER
```

The runner itself still finishes without an error, and the account gets no new actor state. You should see something like the following **on the node logs**.
```bash
thread 'main' (1) panicked at examples/program_deployment/methods/guest/src/bin/hello_world_with_authorization.rs:17:5:
Missing required authorization
```

# 11. Public and private account interaction example
Previous examples only operated on public or private accounts independently. Those minimal programs were useful to introduce basic concepts, but they couldn't demonstrate how different types of accounts interact within a single program invocation.
The "Hello world with move function" handles three messages:
- `Write(data)`: appends bytes to the program's actor state on the receiving account.
- `MoveData { data, to }`: clears the program's actor state on the receiving account and sends its bytes to the program's actor state on `to`. The caller states the bytes in `data`, and the program refuses unless the actor state holds exactly those bytes.
- `Append(data)`: appends bytes to the program's actor state on the destination of a move. Only this program can send it.

The runner's subcommands use these messages on public and private accounts.

> [!NOTE]
> The program logic is completely agnostic to whether input accounts are public or private. It always executes the same way.
> See `methods/guest/src/bin/hello_world_with_move_function.rs`. The program just reads the instruction bytes and updates the accounts state.
> All privacy handling happens on the runner side. When constructing the transaction, the runner decides which accounts are public or private and prepares the appropriate proofs. The program itself can't differentiate between privacy modes.

Let's start by creating a new public account
```bash
wallet account new public
```

Output:
```
Generated new account with account_id Public/95iNQMbmxMRY6jULiHYkCzCkYKPEuysvBh5kEHayDxLs at path /0/0
```

Let's execute the write function. This first run deploys the program:

```bash
cargo run --bin run_hello_world_with_move_function \
    $EXAMPLE_PROGRAMS_BUILD_DIR/hello_world_with_move_function.bin \
    $PAYER \
    write-public 95iNQMbmxMRY6jULiHYkCzCkYKPEuysvBh5kEHayDxLs mundo!
```

The next runs must use this same instance, so export the program account ID it printed:
```bash
export MOVE_PROGRAM_ID=<hello_world_with_move_function program account ID>
```

Let's crate a new private account.

```bash
wallet account new private
```

Output:
```
Generated new account with account_id Private/8vzkK7vsdrS2gdPhLk72La8X4FJkgJ5kJLUBRbEVkReU at path /1
```

Let's execute the write function. The new account doesn't need any funds: the wallet pays the fee from the private account you funded in section 7.

```bash
cargo run --bin run_hello_world_with_move_function \
    $EXAMPLE_PROGRAMS_BUILD_DIR/hello_world_with_move_function.bin \
    $PAYER \
    --program-id $MOVE_PROGRAM_ID \
    write-private 8vzkK7vsdrS2gdPhLk72La8X4FJkgJ5kJLUBRbEVkReU Hola
```

To check the values of the accounts are as expected run:
```bash
wallet account get --raw --scope all --account-id Public/95iNQMbmxMRY6jULiHYkCzCkYKPEuysvBh5kEHayDxLs
```
and

```bash
wallet account sync-private
wallet account get --raw --scope all --account-id Private/8vzkK7vsdrS2gdPhLk72La8X4FJkgJ5kJLUBRbEVkReU
```

and check that the actor state data decodes to `mundo!` and `Hola` respectively. The sync also matters for the next step, which builds on the private account's local state.

Now move the program's actor state data from the public account to the private account.

```bash
cargo run --bin run_hello_world_with_move_function \
    $EXAMPLE_PROGRAMS_BUILD_DIR/hello_world_with_move_function.bin \
    $PAYER \
    --program-id $MOVE_PROGRAM_ID \
    move-data-public-to-private 95iNQMbmxMRY6jULiHYkCzCkYKPEuysvBh5kEHayDxLs 8vzkK7vsdrS2gdPhLk72La8X4FJkgJ5kJLUBRbEVkReU
```

After succeeding, repeat the get and sync commands. The program's actor state should be empty on the public account and contain `Holamundo!` on the private account.

# 12. Program composition: tail calls
Programs can chain calls to other programs when they return. This is the tail call or chained call mechanism. It is used by programs that depend on other programs.

The examples include a `guest/src/bin/simple_tail_call.rs` program that shows how to trigger this mechanism. It keeps its own actor state unchanged and internally calls the first Hello World program with a fixed greeting: `Hello from tail call`.

The callee is named in the message rather than in the program, because a deployed program's address isn't known until deploy time. The runner deploys `simple_tail_call` and passes the callee actor as the message.

> [!NOTE]
> The last argument is the Hello World instance to call, `$HELLO_WORLD_ID` from section 4. Without it the runner deploys a new `hello_world` from the `.bin`, and the greeting lands in that instance's actor state instead.

We'll reuse public account `BzdBoL4JRa5M873cuWb9rbYgASr1pXyaAZ1YW9ertWH9`; its Hello World actor state contains `Hola mundo!`. Like `run_hello_world`, the runner admits it with evidence, so a fresh account held by this wallet works too.

Let's run the tail call program

```bash
cargo run --bin run_hello_world_through_tail_call \
    $EXAMPLE_PROGRAMS_BUILD_DIR/simple_tail_call.bin \
    $EXAMPLE_PROGRAMS_BUILD_DIR/hello_world.bin \
    BzdBoL4JRa5M873cuWb9rbYgASr1pXyaAZ1YW9ertWH9 \
    $PAYER \
    $HELLO_WORLD_ID
```

Once the transaction is processed, query the account values with:

```bash
wallet account get --raw --scope all --account-id Public/BzdBoL4JRa5M873cuWb9rbYgASr1pXyaAZ1YW9ertWH9
```

You should se an output similar to

```json
{
  "actor_states": {
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
It takes the same arguments, and the local execution uses both programs: the `simple_tail_call` and its dependency `hello_world`.

Use the private account `8vzkK7vsdrS2gdPhLk72La8X4FJkgJ5kJLUBRbEVkReU` created in the previous example. This call writes its `hello_world` actor state.

You can test the privacy tail calls with
```bash
cargo run --bin run_hello_world_through_tail_call_private \
    $EXAMPLE_PROGRAMS_BUILD_DIR/simple_tail_call.bin \
    $EXAMPLE_PROGRAMS_BUILD_DIR/hello_world.bin \
    8vzkK7vsdrS2gdPhLk72La8X4FJkgJ5kJLUBRbEVkReU \
    $PAYER \
    $HELLO_WORLD_ID
```

>[!NOTE]
> The above command may take longer than the previous privacy executions because needs to generate proofs of execution of both the `simple_tail_call` and the `hello_world` programs.

Once finished run the following to see the changes
```bash
wallet account sync-private
wallet account get --raw --scope all --account-id Private/8vzkK7vsdrS2gdPhLk72La8X4FJkgJ5kJLUBRbEVkReU
```

The `hello_world` actor state should decode to `Hello from tail call`.

# 13. Program derived accounts: authorizing accounts through tail calls

## Program actor states and account authorization

Each account has a nonce and program actor states; its balance is the native token program's actor state. A program can modify its own actor state on any account.

An `Actor` pairs an account with a program and addresses that program's actor state on the account. `Actor::native_balance` addresses the balance.

Account authorization allows a program to debit the balance. Programs may also require authorization before changing their own actor state.

Regular public accounts are authorized by a signature; regular private accounts by knowledge of `ask`.

Public and private PDAs are bound to an authority account and a seed. During a chained call, the authority program supplies the seed to authorize its PDAs for that call and its descendants.

## Running the example
[tail_call_with_pda.rs](methods/guest/src/bin/tail_call_with_pda.rs) calls Hello World with Authorization on its PDA, passing the seed to authorize the account. The callee writes its own actor state; `tail_call_with_pda` remains the PDA's authority.

There is no need to create a new account for this example, because we simply use one of the PDA accounts belonging to the `tail_call_with_pda` program. The PDA is derived from the program's address, so each run uses a different one.

Execute the program. The runner deploys both programs, `tail_call_with_pda` first:
```bash
cargo run --bin run_hello_world_with_authorization_through_tail_call_with_pda \
    $EXAMPLE_PROGRAMS_BUILD_DIR/tail_call_with_pda.bin \
    $EXAMPLE_PROGRAMS_BUILD_DIR/hello_world_with_authorization.bin \
    $PAYER
```

You'll see an output like the following:

```bash
The program derived account id is: 3tfTPPuxj3eSE1cLVuNBEk8eSHzpnYS1oqEdeH3Nfsks
```

Then check the status of that account

```bash
wallet account get --raw --scope all --account-id Public/3tfTPPuxj3eSE1cLVuNBEk8eSHzpnYS1oqEdeH3Nfsks
```

Output:
```json
{
  "actor_states": {
    "<hello_world_with_authorization program account ID>": "48656c6c6f2066726f6d207461696c2063616c6c20776974682050726f6772616d2044657269766564204163636f756e74204944"
  },
  "nonce": 0
}
```



