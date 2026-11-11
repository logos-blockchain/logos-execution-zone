use common::transaction::LeeTransaction;
use lee::{
    AccountId, ProgramShardSelector, PublicTransaction,
    public_transaction::{Message, WitnessSet},
};
use program_deployment::{deploy_program, fee_paid_by};
use sequencer_service_rpc::RpcClient as _;
use wallet::WalletCore;

// Before running this example, compile the `hello_world.rs` guest program with:
//
//   RISC0_DOCKER_CONTAINER_TAG=r0.1.91.1 cargo risczero build \
//     --manifest-path examples/program_deployment/methods/guest/Cargo.toml
//
// Note: you must run the above command from the root of the `logos-execution-zone` repository.
// Note: The compiled binary file is stored in
// target/riscv32im-risc0-zkvm-elf/docker/hello_world.bin
//
//
// Usage:
//   cargo run --bin run_hello_world /path/to/guest/binary <account_id> <payer_account_id>
//
// Example:
//   cargo run --bin run_hello_world \
//     $EXAMPLE_PROGRAMS_BUILD_DIR/hello_world.bin \
//     Ds8q5PjLcKwwV97Zi7duhRVF9uwA2PuYMoLL7FwCzsXE \
//     <funded payer account_id>

#[tokio::main]
async fn main() {
    // Initialize wallet
    let mut wallet_core = WalletCore::from_env().unwrap();

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
    // Third argument is an existing, funded account to pay the deployment and call fees
    let payer: AccountId = std::env::args_os()
        .nth(3)
        .unwrap()
        .into_string()
        .unwrap()
        .parse()
        .unwrap();

    // Deploy the program through `program_loader`; future calls dispatch to the returned header.
    let bytecode: Vec<u8> = std::fs::read(program_path).unwrap();
    let program_account_id = deploy_program(&mut wallet_core, bytecode, payer)
        .await
        .unwrap();

    // Define the desired greeting in ASCII
    let greeting: Vec<u8> = vec![72, 111, 108, 97, 32, 109, 117, 110, 100, 111, 33];

    // Construct the public transaction
    // Hello World needs no authorization from `account_id`, so the only signer is the fee
    // payer: the message lists the payer's nonce and the payer signs it. Check out
    // `run_hello_world_with_authorization` for a transaction the account itself signs.
    let (fee, payer_nonce, payer_key) = fee_paid_by(&wallet_core, payer).await.unwrap();
    let nonces = vec![payer_nonce];
    let signing_keys = [&payer_key];
    let message = Message::try_new_with_fees(
        program_account_id,
        vec![ProgramShardSelector::new(account_id, program_account_id)],
        nonces,
        greeting,
        fee,
    )
    .unwrap();
    let witness_set = WitnessSet::for_message(&message, &signing_keys);
    let tx = PublicTransaction::new(message, witness_set);

    // Submit the transaction
    let _response = wallet_core
        .client_owned()
        .send_transaction(LeeTransaction::Public(tx))
        .await
        .unwrap();
}
