use std::collections::HashMap;

use clap::{Parser, Subcommand};
use common::transaction::LeeTransaction;
use lee::{
    AccountId, PublicTransaction,
    privacy_preserving_transaction::circuit::ProgramWithDependencies, program::Program,
    public_transaction,
};
use program_deployment::deploy_program;
use sequencer_service_rpc::RpcClient as _;
use wallet::{AccountIdentity, WalletCore};

// Before running this example, compile the `hello_world_with_move_function.rs` guest program with:
//
//   cargo risczero build --manifest-path examples/program_deployment/methods/guest/Cargo.toml
//
// Note: you must run the above command from the root of the `logos-execution-zone` repository.
// Note: The compiled binary file is stored in
// methods/guest/target/riscv32im-risc0-zkvm-elf/docker/hello_world_with_move_function.bin
//
//
// Usage:
//   cargo run --bin run_hello_world_with_move_function \
//     /path/to/guest/binary <payer_account_id> <function> <params>
//
// Example:
//   cargo run --bin run_hello_world_with_move_function \
//     methods/guest/target/riscv32im-risc0-zkvm-elf/docker/hello_world_with_move_function.bin \
//     <funded payer account_id> \
//     write-public Ds8q5PjLcKwwV97Zi7duhRVF9uwA2PuYMoLL7FwCzsXE Hola

const WRITE_FUNCTION_ID: u8 = 0;
const MOVE_DATA_FUNCTION_ID: u8 = 1;

type Instruction = (u8, Vec<u8>);

#[derive(Parser, Debug)]
struct Cli {
    /// Path to program binary.
    program_path: String,

    /// An existing, funded account to pay the deployment fee.
    payer: AccountId,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Write instruction into one account.
    WritePublic {
        account_id: String,
        greeting: String,
    },
    WritePrivate {
        account_id: String,
        greeting: String,
    },
    /// Move data between two accounts.
    MoveDataPublicToPublic {
        from: String,
        to: String,
    },
    MoveDataPublicToPrivate {
        from: String,
        to: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize wallet
    let mut wallet_core = WalletCore::from_env().await.unwrap();

    // Deploy the program through `program_loader`. `program` is also needed directly by the
    // private-tx arms below, as the local proving bundle.
    let bytecode: Vec<u8> = std::fs::read(cli.program_path).unwrap();
    let program = Program::new(bytecode.clone().into()).unwrap();
    let program_account_id = deploy_program(&mut wallet_core, bytecode, cli.payer)
        .await
        .unwrap();
    // `Program`'s own `.into::<ProgramWithDependencies>()` assumes the bijection address, so the
    // deployed address is given explicitly instead.
    let program_with_dependencies =
        ProgramWithDependencies::new(program, program_account_id, HashMap::new());

    match cli.command {
        Command::WritePublic {
            account_id,
            greeting,
        } => {
            let instruction: Instruction = (WRITE_FUNCTION_ID, greeting.into_bytes());
            let account_id = account_id.parse().unwrap();
            let nonces = wallet_core
                .get_accounts_nonces(&[cli.payer])
                .await
                .expect("Node should be reachable to query account data");
            let payer_key = wallet_core
                .get_account_public_signing_key(cli.payer)
                .expect("Payer's signing key should be held by this wallet")
                .clone();
            let message = public_transaction::Message::try_new_with_fees(
                program_account_id,
                vec![account_id],
                nonces,
                instruction,
                lee::FeeDeclaration::new(
                    cli.payer,
                    wallet::DEFAULT_GAS_LIMIT,
                    0,
                    wallet::DEFAULT_MAX_FEE,
                ),
            )
            .unwrap();
            let witness_set = public_transaction::WitnessSet::for_message(&message, &[&payer_key]);
            let tx = PublicTransaction::new(message, witness_set);

            // Submit the transaction
            let _response = wallet_core
                .helm_owned()
                .send_transaction(LeeTransaction::Public(tx))
                .await
                .unwrap();
        }
        Command::WritePrivate {
            account_id,
            greeting,
        } => {
            let instruction: Instruction = (WRITE_FUNCTION_ID, greeting.into_bytes());
            let account_id = account_id.parse().unwrap();
            let accounts = vec![AccountIdentity::PrivateOwned(account_id)];

            wallet_core
                .send_privacy_preserving_tx(
                    accounts,
                    Program::serialize_instruction(instruction).unwrap(),
                    &program_with_dependencies,
                )
                .await
                .unwrap();
        }
        Command::MoveDataPublicToPublic { from, to } => {
            let instruction: Instruction = (MOVE_DATA_FUNCTION_ID, vec![]);
            let from = from.parse().unwrap();
            let to = to.parse().unwrap();
            let nonces = wallet_core
                .get_accounts_nonces(&[cli.payer])
                .await
                .expect("Node should be reachable to query account data");
            let payer_key = wallet_core
                .get_account_public_signing_key(cli.payer)
                .expect("Payer's signing key should be held by this wallet")
                .clone();
            let message = public_transaction::Message::try_new_with_fees(
                program_account_id,
                vec![from, to],
                nonces,
                instruction,
                lee::FeeDeclaration::new(
                    cli.payer,
                    wallet::DEFAULT_GAS_LIMIT,
                    0,
                    wallet::DEFAULT_MAX_FEE,
                ),
            )
            .unwrap();
            let witness_set = public_transaction::WitnessSet::for_message(&message, &[&payer_key]);
            let tx = PublicTransaction::new(message, witness_set);

            // Submit the transaction
            let _response = wallet_core
                .helm_owned()
                .send_transaction(LeeTransaction::Public(tx))
                .await
                .unwrap();
        }
        Command::MoveDataPublicToPrivate { from, to } => {
            let instruction: Instruction = (MOVE_DATA_FUNCTION_ID, vec![]);
            let from = from.parse().unwrap();
            let to = to.parse().unwrap();

            let accounts = vec![
                AccountIdentity::Public(from),
                AccountIdentity::PrivateOwned(to),
            ];

            wallet_core
                .send_privacy_preserving_tx(
                    accounts,
                    Program::serialize_instruction(instruction).unwrap(),
                    &program_with_dependencies,
                )
                .await
                .unwrap();
        }
    }
}
