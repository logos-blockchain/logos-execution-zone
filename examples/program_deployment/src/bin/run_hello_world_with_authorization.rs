use common::transaction::LeeTransaction;
use lee::{
    AccountId, PublicTransaction,
    public_transaction::{Message, WitnessSet},
};
use program_deployment::deploy_program;
use sequencer_service_rpc::RpcClient as _;
use wallet::WalletCore;

// Before running this example, compile the `hello_world_with_authorization.rs` guest program with:
//
//   cargo risczero build --manifest-path examples/program_deployment/methods/guest/Cargo.toml
//
// Note: you must run the above command from the root of the `logos-execution-zone` repository.
// Note: The compiled binary file is stored in
// methods/guest/target/riscv32im-risc0-zkvm-elf/docker/hello_world_with_authorization.bin
//
//
// Usage:
//   ./run_hello_world_with_authorization /path/to/guest/binary <account_id> <payer_account_id>
//
// Note: the provided account_id needs to be of a public self owned account
//
// Example:
//   cargo run --bin run_hello_world_with_authorization \
//      methods/guest/target/riscv32im-risc0-zkvm-elf/docker/hello_world_with_authorization.bin \
//      Ds8q5PjLcKwwV97Zi7duhRVF9uwA2PuYMoLL7FwCzsXE \
//      <funded payer account_id>

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

    // Deploy the program through `program_loader`; future calls dispatch to the returned
    // header account.
    let bytecode: Vec<u8> = std::fs::read(program_path).unwrap();
    let program_account_id = deploy_program(&mut wallet_core, bytecode, payer)
        .await
        .unwrap();

    // Load signing keys to provide authorization
    let signing_key = wallet_core
        .storage()
        .key_chain()
        .pub_account_signing_key(account_id)
        .expect("Input account should be a self owned public account")
        .clone();

    // Define the desired greeting in ASCII
    let greeting: Vec<u8> = vec![72, 111, 108, 97, 32, 109, 117, 110, 100, 111, 33];

    // Construct the public transaction. Query the current nonces from the node — the account's
    // own, then the fee payer's, appended last.
    let mut nonces = wallet_core
        .get_accounts_nonces(&[account_id])
        .await
        .expect("Node should be reachable to query account data");
    let payer_nonce = wallet_core
        .get_accounts_nonces(&[payer])
        .await
        .expect("Node should be reachable to query account data");
    nonces.extend(payer_nonce);
    let payer_key = wallet_core
        .get_account_public_signing_key(payer)
        .expect("Payer's signing key should be held by this wallet")
        .clone();
    let signing_keys = [&signing_key, &payer_key];
    let message = Message::try_new_with_fees(
        program_account_id,
        vec![account_id],
        nonces,
        greeting,
        lee::FeeDeclaration::new(payer, wallet::DEFAULT_GAS_LIMIT, 0, wallet::DEFAULT_MAX_FEE),
    )
    .unwrap();
    // Pass the signing key to sign the message. This will be used by the node
    // to flag the pre_state as `is_authorized` when executing the program
    let witness_set = WitnessSet::for_message(&message, &signing_keys);
    let tx = PublicTransaction::new(message, witness_set);

    // Submit the transaction
    let _response = wallet_core
        .helm_owned()
        .send_transaction(LeeTransaction::Public(tx))
        .await
        .unwrap();
}
