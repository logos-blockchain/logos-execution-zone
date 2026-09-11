use common::transaction::LeeTransaction;
use lee::{
    AccountId, PublicTransaction,
    public_transaction::{Message, WitnessSet},
};
use program_deployment::deploy_program;
use sequencer_service_rpc::RpcClient as _;
use wallet::WalletCore;

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
//   cargo run --bin run_hello_world /path/to/guest/binary <account_id> <payer_account_id>
//
// Example:
//   cargo run --bin run_hello_world \
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
    // Second argument is the account_id to write the greeting into
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

    // Deploy the program through `program_loader`; future calls dispatch to the returned
    // header account.
    let bytecode: Vec<u8> = std::fs::read(program_path).unwrap();
    let program_account_id = deploy_program(&mut wallet_core, bytecode, payer)
        .await
        .unwrap();

    // Define the desired greeting in ASCII
    let greeting: Vec<u8> = vec![72, 111, 108, 97, 32, 109, 117, 110, 100, 111, 33];

    // Construct the public transaction. The target account needs no nonce or signature (this
    // program doesn't require its authorization) — only the fee payer does.
    let payer_nonce = wallet_core
        .get_accounts_nonces(&[payer])
        .await
        .expect("Node should be reachable to query account data");
    let payer_key = wallet_core
        .get_account_public_signing_key(payer)
        .expect("Payer's signing key should be held by this wallet")
        .clone();
    let message = Message::try_new_with_fees(
        program_account_id,
        vec![account_id],
        payer_nonce,
        greeting,
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
