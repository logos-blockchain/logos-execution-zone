use nssa::{AccountId, program::Program};
use wallet::{PrivacyPreservingAccount, WalletCore};

// Before running this example, compile the `hello_world.rs` guest program with:
//
//   cargo risczero build --manifest-path examples/program_deployment/methods/guest/Cargo.toml
//
// Note: you must run the above command from the root of the `lssa` repository.
// Note: The compiled binary file is stored in
// methods/guest/target/riscv32im-risc0-zkvm-elf/docker/hello_world.bin
//
//
// Usage:
//   cargo run --bin run_hello_world_private /path/to/guest/binary <account_id>
//
// Note: the provided account_id needs to be of a private self owned account
//
// Example:
//   cargo run --bin run_hello_world_private \
//     methods/guest/target/riscv32im-risc0-zkvm-elf/docker/hello_world.bin \
//     Ds8q5PjLcKwwV97Zi7duhRVF9uwA2PuYMoLL7FwCzsXE

#[tokio::main]
async fn main() {
    // Initialize wallet
    let wallet_core = WalletCore::from_env().unwrap();

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

    // Load the program
    let bytecode: Vec<u8> = std::fs::read(program_path).unwrap();
    let program = Program::new(bytecode).unwrap();

    // Define the desired greeting in ASCII
    let greeting: Vec<u8> = vec![72, 111, 108, 97, 32, 109, 117, 110, 100, 111, 33];

    let accounts = vec![PrivacyPreservingAccount::PrivateOwned(account_id)];

    // Construct and submit the privacy-preserving transaction
    wallet_core
        .send_privacy_preserving_tx(
            accounts,
            Program::serialize_instruction(greeting).unwrap(),
            &program.into(),
        )
        .await
        .unwrap();
}
