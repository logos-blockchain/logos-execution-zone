#![expect(
    clippy::print_stdout,
    reason = "This is an example program, it's fine to print to stdout"
)]

use std::collections::BTreeMap;

use common::transaction::LeeTransaction;
use lee::{
    AccountId, Actor, PublicTransaction,
    public_transaction::{Message, WitnessSet},
};
use lee_core::program::PdaSeed;
use program_deployment::deploy_program;
use sequencer_service_rpc::RpcClient as _;
use wallet::WalletCore;

// Before running this example, compile the `tail_call_with_pda.rs` and
// `hello_world_with_authorization.rs` guest programs with:
//
//   cargo risczero build --manifest-path examples/program_deployment/methods/guest/Cargo.toml
//
// Note: you must run the above command from the root of the `logos-execution-zone` repository.
// Note: The compiled binaries are stored in
// methods/guest/target/riscv32im-risc0-zkvm-elf/docker/{tail_call_with_pda,
// hello_world_with_authorization}.bin
//
//
// Usage:
//   cargo run --bin run_hello_world_with_authorization_through_tail_call_with_pda \
//     /path/to/tail_call_with_pda/binary /path/to/hello_world_with_authorization/binary \
//     <payer_account_id>
//
// Example:
//   cargo run --bin run_hello_world_with_authorization_through_tail_call_with_pda \
//     methods/guest/target/riscv32im-risc0-zkvm-elf/docker/tail_call_with_pda.bin \
//     methods/guest/target/riscv32im-risc0-zkvm-elf/docker/hello_world_with_authorization.bin \
//     <funded payer account_id>

const PDA_SEED: PdaSeed = PdaSeed::new([37; 32]);

#[tokio::main]
async fn main() {
    // Initialize wallet
    let mut wallet_core = WalletCore::from_env().await.unwrap();

    // Parse arguments
    // First argument is the path to the caller (`tail_call_with_pda`) program binary
    let caller_path = std::env::args_os().nth(1).unwrap().into_string().unwrap();
    // Second argument is the path to the callee (`hello_world_with_authorization`) program binary
    let callee_path = std::env::args_os().nth(2).unwrap().into_string().unwrap();
    // Third argument is an existing, funded account to pay the deployment fees
    let payer: AccountId = std::env::args_os()
        .nth(3)
        .unwrap()
        .into_string()
        .unwrap()
        .parse()
        .unwrap();

    // Deploy both programs through `program_loader`; `tail_call_with_pda` reads the callee's
    // address from its own message.
    let caller_bytecode: Vec<u8> = std::fs::read(caller_path).unwrap();
    let caller_account_id = deploy_program(&mut wallet_core, caller_bytecode, payer)
        .await
        .unwrap();
    let callee_bytecode: Vec<u8> = std::fs::read(callee_path).unwrap();
    let callee_account_id = deploy_program(&mut wallet_core, callee_bytecode, payer)
        .await
        .unwrap();

    // Compute the PDA to pass as the input account.
    let pda = AccountId::for_public_pda(&caller_account_id, &PDA_SEED);
    // The caller's actor on the PDA receives the message and sends the greeting, with the PDA seed,
    // to the callee's actor on the same account, so both are declared.
    let caller = Actor::new(pda, caller_account_id);
    let public_actors = vec![caller, Actor::new(pda, callee_account_id)];
    let nonces = BTreeMap::new();
    let signing_keys = [];
    let message = Message::try_new(caller, public_actors, nonces, callee_account_id).unwrap();
    let witness_set = WitnessSet::for_message(&message, &signing_keys);
    let tx = PublicTransaction::new(message, witness_set);

    // Submit the transaction
    let _response = wallet_core
        .helm_owned()
        .send_transaction(LeeTransaction::Public(tx))
        .await
        .unwrap();

    println!("The program derived account id is: {pda}");
}
