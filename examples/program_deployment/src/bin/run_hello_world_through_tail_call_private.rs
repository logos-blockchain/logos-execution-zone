use std::collections::HashMap;

use nssa::{
    AccountId, ProgramId, privacy_preserving_transaction::circuit::ProgramWithDependencies,
    program::Program,
};
use wallet::{PrivacyPreservingAccount, WalletCore};

// Before running this example, compile the `simple_tail_call.rs` guest program with:
//
//   cargo risczero build --manifest-path examples/program_deployment/methods/guest/Cargo.toml
//
// Note: you must run the above command from the root of the `lssa` repository.
// Note: The compiled binary file is stored in
// methods/guest/target/riscv32im-risc0-zkvm-elf/docker/simple_tail_call.bin
//
//
// Usage:
//   cargo run --bin run_hello_world_through_tail_call_private /path/to/guest/binary <account_id>
//
// Example:
//   cargo run --bin run_hello_world_through_tail_call \
//     methods/guest/target/riscv32im-risc0-zkvm-elf/docker/simple_tail_call.bin \
//     Ds8q5PjLcKwwV97Zi7duhRVF9uwA2PuYMoLL7FwCzsXE

#[tokio::main]
async fn main() {
    // Initialize wallet
    let wallet_core = WalletCore::from_env().unwrap();

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

    // Load the program and its dependencies (the hellow world program)
    let simple_tail_call_bytecode: Vec<u8> = std::fs::read(simple_tail_call_path).unwrap();
    let simple_tail_call = Program::new(simple_tail_call_bytecode).unwrap();
    let hello_world_bytecode: Vec<u8> = std::fs::read(hello_world_path).unwrap();
    let hello_world = Program::new(hello_world_bytecode).unwrap();
    let dependencies: HashMap<ProgramId, Program> =
        std::iter::once((hello_world.id(), hello_world)).collect();
    let program_with_dependencies = ProgramWithDependencies::new(simple_tail_call, dependencies);

    let accounts = vec![PrivacyPreservingAccount::PrivateOwned(account_id)];

    // Construct and submit the privacy-preserving transaction
    let instruction = ();
    wallet_core
        .send_privacy_preserving_tx(
            accounts,
            Program::serialize_instruction(instruction).unwrap(),
            &program_with_dependencies,
        )
        .await
        .unwrap();
}
