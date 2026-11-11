#![expect(
    clippy::print_stdout,
    reason = "This is an example program, it's fine to print to stdout"
)]

use common::transaction::LeeTransaction;
use lee::{
    AccountId, ProgramShardSelector, PublicTransaction,
    public_transaction::{Message, WitnessSet},
};
use lee_core::program::PdaSeed;
use program_deployment::{deploy_program, fee_paid_by};
use sequencer_service_rpc::RpcClient as _;
use wallet::WalletCore;

// Before running this example, compile the `tail_call_with_pda.rs` and
// `hello_world_with_authorization.rs` guest programs with:
//
//   RISC0_DOCKER_CONTAINER_TAG=r0.1.91.1 cargo risczero build \
//     --manifest-path examples/program_deployment/methods/guest/Cargo.toml
//
// Note: you must run the above command from the root of the `logos-execution-zone` repository.
// Note: The compiled binaries are stored in
// target/riscv32im-risc0-zkvm-elf/docker/{tail_call_with_pda,
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
//     $EXAMPLE_PROGRAMS_BUILD_DIR/tail_call_with_pda.bin \
//     $EXAMPLE_PROGRAMS_BUILD_DIR/hello_world_with_authorization.bin \
//     <funded payer account_id>

const PDA_SEED: PdaSeed = PdaSeed::new([37; 32]);

#[tokio::main]
async fn main() {
    // Initialize wallet
    let mut wallet_core = WalletCore::from_env().unwrap();

    // Parse arguments
    // First argument is the path to the caller (`tail_call_with_pda`) program binary
    let caller_path = std::env::args_os().nth(1).unwrap().into_string().unwrap();
    // Second argument is the path to the callee (`hello_world_with_authorization`) program binary
    let callee_path = std::env::args_os().nth(2).unwrap().into_string().unwrap();
    // Third argument is an existing, funded account to pay the deployment and call fees
    let payer: AccountId = std::env::args_os()
        .nth(3)
        .unwrap()
        .into_string()
        .unwrap()
        .parse()
        .unwrap();

    // Deploy both programs through `program_loader`; `tail_call_with_pda` reads the callee's
    // address from its own instruction data.
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
    // The caller only needs the account ID; the callee selects its shard.
    let shard_selectors = vec![ProgramShardSelector::native_balance(pda)];
    let instruction_data = callee_account_id;
    // The fee payer is the only signer; the PDA is authorized by the caller program, not by a
    // signature
    let (fee, payer_nonce, payer_key) = fee_paid_by(&wallet_core, payer).await.unwrap();
    let nonces = vec![payer_nonce];
    let signing_keys = [&payer_key];
    let message = Message::try_new_with_fees(
        caller_account_id,
        shard_selectors,
        nonces,
        instruction_data,
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

    println!("The program derived account id is: {pda}");
}
