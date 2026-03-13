#![expect(
    clippy::print_stdout,
    reason = "This is an example program, it's fine to print to stdout"
)]

use common::transaction::NSSATransaction;
use nssa::{
    AccountId, PublicTransaction,
    program::Program,
    public_transaction::{Message, WitnessSet},
};
use nssa_core::program::PdaSeed;
use sequencer_service_rpc::RpcClient as _;
use wallet::WalletCore;

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
//   cargo run --bin run_hello_world_with_authorization_through_tail_call_with_pda
// /path/to/guest/binary <account_id>
//
// Example:
//   cargo run --bin run_hello_world_with_authorization_through_tail_call_with_pda \
//     methods/guest/target/riscv32im-risc0-zkvm-elf/docker/tail_call_with_pda.bin

const PDA_SEED: PdaSeed = PdaSeed::new([37; 32]);

#[tokio::main]
async fn main() {
    // Initialize wallet
    let wallet_core = WalletCore::from_env().unwrap();

    // Parse arguments
    // First argument is the path to the program binary
    let program_path = std::env::args_os().nth(1).unwrap().into_string().unwrap();

    // Load the program
    let bytecode: Vec<u8> = std::fs::read(program_path).unwrap();
    let program = Program::new(bytecode).unwrap();

    // Compute the PDA to pass it as input account to the public execution
    let pda = AccountId::from((&program.id(), &PDA_SEED));
    let account_ids = vec![pda];
    let instruction_data = ();
    let nonces = vec![];
    let signing_keys = [];
    let message = Message::try_new(program.id(), account_ids, nonces, instruction_data).unwrap();
    let witness_set = WitnessSet::for_message(&message, &signing_keys);
    let tx = PublicTransaction::new(message, witness_set);

    // Submit the transaction
    let _response = wallet_core
        .sequencer_client
        .send_transaction(NSSATransaction::Public(tx))
        .await
        .unwrap();

    println!("The program derived account id is: {pda}");
}
