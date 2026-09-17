use std::collections::HashMap;

use lee::{
    AccountId, privacy_preserving_transaction::circuit::ProgramWithDependencies, program::Program,
};
use program_deployment::deploy_program;
use wallet::{AccountIdentity, WalletCore};

// Before running this example, compile the `simple_tail_call.rs` and `hello_world.rs` guest
// programs with:
//
//   cargo risczero build --manifest-path examples/program_deployment/methods/guest/Cargo.toml
//
// Note: you must run the above command from the root of the `logos-execution-zone` repository.
// Note: The compiled binaries are stored in
// methods/guest/target/riscv32im-risc0-zkvm-elf/docker/{simple_tail_call,hello_world}.bin
//
//
// Usage:
//   cargo run --bin run_hello_world_through_tail_call_private \
//     /path/to/simple_tail_call/binary /path/to/hello_world/binary <account_id> <payer_account_id>
//
// Example:
//   cargo run --bin run_hello_world_through_tail_call_private \
//     methods/guest/target/riscv32im-risc0-zkvm-elf/docker/simple_tail_call.bin \
//     methods/guest/target/riscv32im-risc0-zkvm-elf/docker/hello_world.bin \
//     Ds8q5PjLcKwwV97Zi7duhRVF9uwA2PuYMoLL7FwCzsXE \
//     <funded payer account_id>

#[tokio::main]
async fn main() {
    // Initialize wallet
    let mut wallet_core = WalletCore::from_env().await.unwrap();

    // Parse arguments
    // First argument is the path to the simple_tail_call program binary
    let simple_tail_call_path = std::env::args_os().nth(1).unwrap().into_string().unwrap();
    // Second argument is the path to the hello_world program binary
    let hello_world_path = std::env::args_os().nth(2).unwrap().into_string().unwrap();
    // Third argument is the account_id
    let account_id: AccountId = std::env::args_os()
        .nth(3)
        .unwrap()
        .into_string()
        .unwrap()
        .parse()
        .unwrap();
    // Fourth argument is an existing, funded account to pay the deployment fees
    let payer: AccountId = std::env::args_os()
        .nth(4)
        .unwrap()
        .into_string()
        .unwrap()
        .parse()
        .unwrap();

    // Deploy both programs through `program_loader` so the sequencer has real on-chain state to
    // anchor this transaction's `ProgramImageClaim`s against.
    let simple_tail_call_bytecode: Vec<u8> = std::fs::read(simple_tail_call_path).unwrap();
    let simple_tail_call = Program::new(simple_tail_call_bytecode.clone().into()).unwrap();
    let simple_tail_call_id = deploy_program(&mut wallet_core, simple_tail_call_bytecode, payer)
        .await
        .unwrap();

    let hello_world_bytecode: Vec<u8> = std::fs::read(hello_world_path).unwrap();
    let hello_world = Program::new(hello_world_bytecode.clone().into()).unwrap();
    let hello_world_id = deploy_program(&mut wallet_core, hello_world_bytecode, payer)
        .await
        .unwrap();

    let dependencies: HashMap<AccountId, Program> =
        std::iter::once((hello_world_id, hello_world)).collect();
    let program_with_dependencies =
        ProgramWithDependencies::new(simple_tail_call, simple_tail_call_id, dependencies);

    let accounts = vec![AccountIdentity::PrivateOwned(account_id)];

    // The instruction carries the callee's `AccountId`, which `simple_tail_call`'s guest reads
    // from here.
    let instruction = hello_world_id;
    wallet_core
        .send_privacy_preserving_tx(
            accounts,
            Program::serialize_instruction(instruction).unwrap(),
            &program_with_dependencies,
        )
        .await
        .unwrap();
}
