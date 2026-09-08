use common::transaction::LeeTransaction;
use lee::{
    AccountId, PublicTransaction,
    public_transaction::{Message, WitnessSet},
};
use program_deployment::deploy_program;
use sequencer_service_rpc::RpcClient as _;
use wallet::WalletCore;

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
//   cargo run --bin run_hello_world_through_tail_call \
//     /path/to/simple_tail_call/binary /path/to/hello_world/binary <account_id> <payer_account_id>
//
// Example:
//   cargo run --bin run_hello_world_through_tail_call \
//     methods/guest/target/riscv32im-risc0-zkvm-elf/docker/simple_tail_call.bin \
//     methods/guest/target/riscv32im-risc0-zkvm-elf/docker/hello_world.bin \
//     Ds8q5PjLcKwwV97Zi7duhRVF9uwA2PuYMoLL7FwCzsXE \
//     <funded payer account_id>

#[tokio::main]
async fn main() {
    // Initialize wallet
    let mut wallet_core = WalletCore::from_env().await.unwrap();

    // Parse arguments
    // First argument is the path to the caller (`simple_tail_call`) program binary
    let caller_path = std::env::args_os().nth(1).unwrap().into_string().unwrap();
    // Second argument is the path to the callee (`hello_world`) program binary
    let callee_path = std::env::args_os().nth(2).unwrap().into_string().unwrap();
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

    // Deploy both programs through `program_loader`. `simple_tail_call` reads the callee's
    // address from its own instruction data, supplied here.
    let caller_bytecode: Vec<u8> = std::fs::read(caller_path).unwrap();
    let caller_account_id = deploy_program(&mut wallet_core, caller_bytecode, payer)
        .await
        .unwrap();
    let callee_bytecode: Vec<u8> = std::fs::read(callee_path).unwrap();
    let callee_account_id = deploy_program(&mut wallet_core, callee_bytecode, payer)
        .await
        .unwrap();

    let instruction_data = callee_account_id;
    let payer_nonce = wallet_core
        .get_accounts_nonces(&[payer])
        .await
        .expect("Node should be reachable to query account data");
    let payer_key = wallet_core
        .get_account_public_signing_key(payer)
        .expect("Payer's signing key should be held by this wallet")
        .clone();
    let message = Message::try_new_with_fees(
        caller_account_id,
        vec![account_id],
        payer_nonce,
        instruction_data,
        lee::FeeDeclaration::new(payer, wallet::DEFAULT_GAS_LIMIT, 0, wallet::DEFAULT_MAX_FEE),
    )
    .unwrap();
    let witness_set = WitnessSet::for_message(&message, &[&payer_key]);
    let tx = PublicTransaction::new(message, witness_set);

    // Submit the transaction
    let _response = wallet_core
        .helm_owned()
        .send_transaction(LeeTransaction::Public(tx))
        .await
        .unwrap();
}
