use std::collections::HashMap;

use lee::{
    AccountId, privacy_preserving_transaction::circuit::ProgramWithDependencies, program::Program,
};
use program_deployment::deploy_program;
use wallet::{AccountIdentity, WalletCore};

// Before running this example, compile the `hello_world.rs` guest program with:
//
//   cargo risczero build --manifest-path examples/program_deployment/methods/guest/Cargo.toml
//
// Note: you must run the above command from the root of the `logos-execution-zone` repository.
// Note: The compiled binary file is stored in
// methods/guest/target/riscv32im-risc0-zkvm-elf/docker/hello_world.bin
//
//
// Usage:
//   cargo run --bin run_hello_world_private /path/to/guest/binary <account_id> <payer_account_id>
//
// Note: the provided account_id needs to be of a private self owned account
//
// Example:
//   cargo run --bin run_hello_world_private \
//     methods/guest/target/riscv32im-risc0-zkvm-elf/docker/hello_world.bin \
//     Ds8q5PjLcKwwV97Zi7duhRVF9uwA2PuYMoLL7FwCzsXE \
//     <funded payer account_id>

#[tokio::main]
async fn main() {
    // Initialize wallet
    let mut wallet_core = WalletCore::from_env().await.unwrap();

    // Parse arguments
    // First argument is the path to the program binary
    let program_path = std::env::args_os().nth(1).unwrap().into_string().unwrap();
    // Second argument is the account_id
    let account_id: AccountId = std::env::args_os()
        .nth(2)
        .unwrap()
        .into_string()
        .unwrap()
        .parse()
        .unwrap();
    // Third argument is an existing, funded account to pay the deployment fee
    let payer: AccountId = std::env::args_os()
        .nth(3)
        .unwrap()
        .into_string()
        .unwrap()
        .parse()
        .unwrap();

    // Deploy the bytecode through `program_loader` so the sequencer has real on-chain state to
    // anchor this transaction's `ProgramImageClaim` against.
    let bytecode: Vec<u8> = std::fs::read(program_path).unwrap();
    let program = Program::new(bytecode.clone().into()).unwrap();
    let program_account_id = deploy_program(&mut wallet_core, bytecode, payer)
        .await
        .unwrap();
    // `Program`'s own `.into::<ProgramWithDependencies>()` assumes the bijection address, so the
    // deployed address is given explicitly instead.
    let program_with_dependencies =
        ProgramWithDependencies::new(program, program_account_id, HashMap::new());

    // Define the desired greeting in ASCII
    let greeting: Vec<u8> = vec![72, 111, 108, 97, 32, 109, 117, 110, 100, 111, 33];

    let accounts = vec![AccountIdentity::PrivateOwned(account_id)];

    // Construct and submit the privacy-preserving transaction
    wallet_core
        .send_privacy_preserving_tx(
            accounts,
            Program::serialize_instruction(greeting).unwrap(),
            &program_with_dependencies,
        )
        .await
        .unwrap();
}
