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

The Hello world program reads an arbitrary sequence of bytes from its instruction and appends them to the data field of the input account.
Execution succeeds only if the account is:

- Uninitialized, or
- Already owned by this program

If uninitialized, the program will claim the account and emit the updated state.

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
> - The program will claim the account and write data into it.

Monitor the sequencer terminal to confirm execution.

## Inspect the updated account
After the transaction is processed, check the new state:
```bash
wallet account get --account-id Public/BzdBoL4JRa5M873cuWb9rbYgASr1pXyaAZ1YW9ertWH9
```
Example output:
```json
{
  "balance": 0,
  "program_owner_b64": "o6C6/bbjDmN9VUC51McBpPrta8lxrx2X0iHExhX0yNU=",
  "data_b64": "SG9sYSBtdW5kbyE=",
  "nonce": 0
}
```
The `data_b64` field contains de data in Base64.
Decode it:
```bash
echo -n SG9sYSBtdW5kbyE= | base64 -d
```
You should see `Hola mundo!`.

# 5. Understanding the code in `hello_world.rs`.
The Hello world example demonstrates the minimal structure of a LEE program.
Its purpose is very simple: append the instruction bytes to the data field of a single account.

### What this program does in a nutshell
1. Reads the program inputs
  - The list of pre-state accounts (`pre_states`)
  - The instruction bytes (`instruction`)
  - The raw instruction data (used again when writing outputs)
2. Checks that there is exactly one input account: this example operates on a single account, so it expects `pre_states` to contain exactly one entry.
3. Builds the post-state: It clones the input account and appends the instruction bytes to its data field.
4. Handles account claiming logic: If the account is uninitialized (i.e. not yet claimed by any program), its program_owner will equal `DEFAULT_PROGRAM_ID`. In that case, the program issues a claim request, meaning: "This program now owns this account."
5. Outputs the proposed state transition: `write_lee_outputs` emits:
  - The original instruction data
  - The original pre-states
  - The new post-states

## Code walkthrough
1. Reading inputs:
```rust
let (ProgramInput { pre_states, instruction: greeting }, instruction_data)
    = read_lee_inputs::<Instruction>();
```
2. Extracting the single account:
```rust
let [pre_state] = pre_states
    .try_into()
    .unwrap_or_else(|_| panic!("Input pre states should consist of a single account"));
```
3. Constructing the updated account post state
```rust
let mut this = pre_state.account.clone();
let mut bytes = this.data.into_inner();
bytes.extend_from_slice(&greeting);
this.data = bytes.try_into().expect("Data should fit within the allowed limits");
```
4. Instantiating the `AccountPostState` with a claiming request only if the account pre state is uninitialized:
```rust
let post_state = if post_account.program_owner == DEFAULT_PROGRAM_ID {
    AccountPostState::new_claimed(post_account)
} else {
    AccountPostState::new(post_account)
};
```
5. Emmiting the output
```rust
write_lee_outputs(instruction_data, vec![pre_state], vec![post_state]);
```

# 6. Understanding the runner script `run_hello_world.rs`
The `run_hello_world.rs` example demonstrates how to construct and submit a public transaction that executes the `hello_world` program. Below is a breakdown of what the file does and how the pieces fit together.

### 1. Wallet initialization
```rust
let wallet_config = fetch_config().await.unwrap();
let wallet_core = WalletCore::start_from_config_update_chain(wallet_config)
    .await
    .unwrap();
```
The example loads the wallet configuration and initializes `WalletCore`.
This gives access to:
- the sequencer client,
- the wallet’s account storage.

### 2. Parsing inputs
```rust
let program_path = std::env::args_os().nth(1).unwrap().into_string().unwrap();
let account_id: AccountId = std::env::args_os().nth(2).unwrap().into_string().unwrap().parse().unwrap();
```
The program expects two arguments:
- Path to the guest binary
- AccountId of the public account to operate on

This is the account that the program will claim and write data into.

### 3. Loading the program bytecode
```rust
let bytecode: Vec<u8> = std::fs::read(program_path).unwrap();
let program = Program::new(bytecode).unwrap();
```
The Risc0 ELF is read from disk and wrapped in a Program object, which can be used to compute the program ID. The ID is used by the node to identify which program is invoked by the transaction.


### 4. Preparing the instruction data
```rust
let greeting: Vec<u8> = vec![72,111,108,97,32,109,117,110,100,111,33];
```
The example hardcodes the ASCII bytes for `Hola mundo!`. These bytes are passed to the program as its “instruction,” which the Hello World program simply appends to the account’s data field.

### 5. Creating the public transaction

```rust
let nonces = vec![];
let signing_keys = [];
let message = Message::try_new(program.id(), vec![account_id], nonces, greeting).unwrap();
let witness_set = WitnessSet::for_message(&message, &signing_keys);
let tx = PublicTransaction::new(message, witness_set);
```

A public transaction consists of:
- a `Message`
- a corresponding `WitnessSet`

For this simple example, no signing or nonces are required. The transaction includes only the program ID, the target account, and the instruction bytes. The Hello World program allows this because it does not explicitly require authorization. In the next example, we’ll see how authorization requirements are enforced and how to construct a transaction that includes signatures and nonces.

### 6. Submitting the transaction
```rust
let response = wallet_core.sequencer_client.send_tx_public(tx).await.unwrap();
```
The transaction is sent to the sequencer, which processes it and updates the public state accordingly.

Once executed, you’ll be able to query the updated account to see the newly written "Hola mundo!" data.

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
> - The program will claim the private account and write data into it.

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
wallet account get --account-id Private/7EDHyxejuynBpmbLuiEym9HMUyCYxZDuF8X3B89ADeMr
```
should show something similar to
```json
{
  "balance":0,
  "program_owner_b64":"dWgtNRixwjC0C8aA0NL0Iuss3Q26Dw6ECk7bzExW4bI=",
  "data_b64":"SG9sYSBtdW5kbyE=",
  "nonce":236788677072686551559312843688143377080
}
```

## The `run_hello_world_private.rs` runner
This example extends the public `run_hello_world.rs` flow by constructing a privacy-preserving transaction instead of a public one.
Both runners load a guest program, prepare a transaction, and submit it. But the private version handles encrypted account data, nullifiers, ephemeral keys, and zk proofs.

Unlike the public version, `run_hello_world_private.rs` must:
- prepare the private account pre-state (nullifier keys, membership proof, encrypted values)
- derive a shared secret to encrypt the post-state
- compute the correct visibility mask (initialized vs. uninitialized private account)
- execute the guest program inside the zkVM and produce a proof
- build a PrivacyPreservingTransaction composed of:
- a Message encoding commitments + encrypted post-state
- a WitnessSet embedding the zk proof

Luckily all that complexity is hidden behind the `wallet_core.send_privacy_preserving_tx` function:
```rust
    let accounts = vec![AccountIdentity::PrivateOwned(account_id)];

    // Construct and submit the privacy-preserving transaction
    wallet_core
        .send_privacy_preserving_tx(
            accounts,
            &Program::serialize_instruction(greeting).unwrap(),
            &program.into(),
        )
        .await
        .unwrap();
```
Check the `run_hello_world_private.rs` file to see how it is used.

# 8. Account authorization mechanism
The Hello world example does not enforce any authorization on the input account. This means any user can execute it on any account, regardless of ownership.
LEE provides a mechanism for programs to enforce proper authorization before an execution can succeed. The meaning of authorization differs between public and private accounts:
- Public accounts: authorization requires that the transaction is signed with the account’s signing key.
- Private accounts: authorization requires that the circuit verifies knowledge of the account’s nullifier secret key.

From the program development perspective it is very simple: input accounts come with a flag indicating whether they has been properly authorized. And so, the only difference between the program `hello_world.rs` and `hello_world_with_authorization.rs` is in the lines

```rust
    // #### Difference with `hello_world` example here:
    // Fail if the input account is not authorized
    // The `is_authorized` field will be correctly populated or verified by the system if
    // authorization is provided.
    if !pre_state.is_authorized {
        panic!("Missing required authorization");
    }
    // ####
```

Which just checks the `is_authorized` flag and fails if it is set to false.

# 9. Public execution of the Hello world with authorization example
The workflow to execute it publicly is very similar:

### Deploy the program
```bash
wallet deploy-program $EXAMPLE_PROGRAMS_BUILD_DIR/hello_world_with_authorization.bin
```

### Create a new public account
Our previous public account is already claimed by the simple Hello world program. So we need a new one to work with this other version of the hello program
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
From the runner script perspective, the only difference is that the signing keys are passed to the `WitnessSet` constructor for it to sign it. You  can see this in the following parts of the code:

1. Loading the sigining keys from the wallet storage
```rust
    // Load signing keys to provide authorization
    let signing_key = wallet_core
        .storage
        .user_data
        .get_pub_account_signing_key(&account_id)
        .expect("Input account should be a self owned public account");
```
2. Fetching the current public nonce.
```rust
    // Construct the public transaction
    // Query the current nonce from the node
    let nonces = wallet_core
        .get_accounts_nonces(vec![account_id])
        .await
        .expect("Node should be reachable to query account data");
```
2. Instantiate the witness set using the signing keys
```rust
    let signing_keys = [signing_key];
    let message = Message::try_new(program.id(), vec![account_id], nonces, greeting).unwrap();
    // Pass the signing key to sign the message. This will be used by the node
    // to flag the pre_state as `is_authorized` when executing the program
    let witness_set = WitnessSet::for_message(&message, &signing_keys);
```

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
- `write`: appends arbitrary bytes to a single account. This is what we already had.
- `move_data`: reads all bytes from one account, clears it, and appends those bytes to another account.
Because these operations may involve multiple accounts, we'll see how public and private accounts can participate together in one execution. It highlights how ownership checks work, when an account needs to be claimed, and how multiple post-states are emitted when several accounts are modified.

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

and check the (base64 encoded) data values are `mundo!` and `Hola` respectively.

Now we can execute the move function to clear the data on the public account and move it to the private account.

```bash
cargo run --bin run_hello_world_with_move_function \
    $EXAMPLE_PROGRAMS_BUILD_DIR/hello_world_with_move_function.bin \
    move-data-public-to-private 95iNQMbmxMRY6jULiHYkCzCkYKPEuysvBh5kEHayDxLs 8vzkK7vsdrS2gdPhLk72La8X4FJkgJ5kJLUBRbEVkReU
```

After succeeding, re run the get and sync commands and check that the public account has empty data and the private account data is `Holamundo!`.

# 12. Program composition: tail calls
Programs can chain calls to other programs when they return. This is the tail call or chained call mechanism. It is used by programs that depend on other programs.

The examples include a `guest/src/bin/simple_tail_call.rs` program that shows how to trigger this mechanism. It internally calls the first Hello World program with a fixed greeting: `Hello from tail call`.

> [!NOTE]
> This program hardcodes the ID of the Hello World program. If something fails, check that this ID matches the one produced when building the Hello World program. You can see it in the output of `cargo risczero build` from the earlier sections of this tutorial. If it differs, update the ID in `simple_tail_call.rs` and build again.

As before, let's start by deploying the program

```bash
wallet deploy-program $EXAMPLE_PROGRAMS_BUILD_DIR/simple_tail_call.bin
```

We'll use the first public account of this tutorial. The one with account id `BzdBoL4JRa5M873cuWb9rbYgASr1pXyaAZ1YW9ertWH9`. This account is already owned by the Hello world program and its data reads `Hola mundo!`.

Let's run the tail call program

```bash
cargo run --bin run_hello_world_through_tail_call \
    $EXAMPLE_PROGRAMS_BUILD_DIR/simple_tail_call.bin \
    BzdBoL4JRa5M873cuWb9rbYgASr1pXyaAZ1YW9ertWH9
```

Once the transaction is processed, query the account values with:

```bash
wallet account get --account-id Public/BzdBoL4JRa5M873cuWb9rbYgASr1pXyaAZ1YW9ertWH9
```

You should se an output similar to

```json
{
  "balance":0,
  "program_owner_b64":"fpnW4tFY9N6llZcBHaXRwu7xe+7WZnZX9RWzhwNbk1o=",
  "data_b64":"SG9sYSBtdW5kbyFIZWxsbyBmcm9tIHRhaWwgY2FsbA==",
  "nonce":0
}
```

Decoding the (base64 encoded) data
```bash
echo -n SG9sYSBtdW5kbyFIZWxsbyBmcm9tIHRhaWwgY2FsbA== | base64 -d
```

Output:
```
Hola mundo!Hello from tail call
```
## Private tail-calls
There's support for tail calls in privacy preserving executions too. The `run_hello_world_through_tail_call_private.rs` runner walks you through the process of invoking such an execution.
The only difference is that, since the execution is local, the runner will need both programs: the `simple_tail_call` and it's dependency `hello_world`.

Let's use our existing private account with id `8vzkK7vsdrS2gdPhLk72La8X4FJkgJ5kJLUBRbEVkReU`. This one is already owned by the `hello_world` program.

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

## Digression: account authority vs account program ownership

In LEE there are two distinct concepts that control who can modify an account:
**Program Ownership:** Each account has a field: `program_owner: ProgramId`.
This indicates which program is allowed to update the account’s state during execution.
- If a program is the program_owner of an account, it can freely mutate its fields.
- If the account is uninitialized (`program_owner = DEFAULT_PROGRAM_ID`), a program may claim it and become its owner.
- If a program is not the owner and the account is not claimable, any attempt to modify it will cause the transition to fail.
Program ownership is about mutation rights during program execution.

**Account authority**: Independent from program ownership, each account also has an authority. The entity that is allowed to set: `is_authorized = true`. This flag indicates that the account has been authorized for use in a transaction.
Who can act as authority?
- User-defined accounts: The user is the authority. They can mark an account as authorized by:
  - Signing the transaction (public accounts)
  - Providing a valid nullifiers secret key ownership proof (private accounts)
- Program derived accounts: Programs are automatically the authority of a dedicated namespace of public accounts.

Each program owns a non-overlapping space of 2^256 **public** account IDs. They do not overlap with:
- User accounts (public or private)
- Other program’s PDAs

> [!NOTE]
> Currently PDAs are restricted to the public state.

A program can be the authority of an account owned by another program, which is the most common case.
During a chained call, a program can mark its PDA accounts as `is_authorized=true` without requiring any user signatures or nullifier secret keys. This enables programs to safely authorize accounts during program composition. Importantly, these flags can only be set to true for PDA accounts through an execution of the program that is their authority. No user and no other program can execute any transition that requires authorization of PDA accounts belonging to a different program.

## Running the example
This tutorial includes an example of PDA usage in `methods/guest/src/bin/tail_call_with_pda.rs.`. That program’s sole purpose is to forward one of its own PDA accounts, an account for which it is the authority, to the "Hello World with authorization" program via a chained call. The Hello World program will then claim the account and become its program owner, but the `tail_call_with_pda` program remains the authority. This means it is still the only entity capable of marking that account as `is_authorized=true`.

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
wallet account get --account-id Public/3tfTPPuxj3eSE1cLVuNBEk8eSHzpnYS1oqEdeH3Nfsks
```

Output:
```bash
{
  "balance":0,
  "program_owner_b64":"HZXHYRaKf6YusVo8x00/B15uyY5sGsJb1bzH4KlCY5g=",
  "data_b64": "SGVsbG8gZnJvbSB0YWlsIGNhbGwgd2l0aCBQcm9ncmFtIERlcml2ZWQgQWNjb3VudCBJRA==",
  "nonce":0"
}
```



