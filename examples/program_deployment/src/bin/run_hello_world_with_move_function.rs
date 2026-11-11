#![expect(
    clippy::print_stdout,
    reason = "This is an example program, it's fine to print to stdout"
)]

use std::collections::HashMap;

use clap::{Parser, Subcommand};
use common::transaction::LeeTransaction;
use lee::{
    AccountId, ProgramShardSelector, PublicTransaction,
    privacy_preserving_transaction::circuit::ProgramWithDependencies, program::Program,
    public_transaction,
};
use program_deployment::{deploy_program, fee_paid_by};
use sequencer_service_rpc::RpcClient as _;
use wallet::{AccountIdentity, WalletCore};

// Before running this example, compile the `hello_world_with_move_function.rs` guest program with:
//
//   RISC0_DOCKER_CONTAINER_TAG=r0.1.91.1 cargo risczero build \
//     --manifest-path examples/program_deployment/methods/guest/Cargo.toml
//
// Note: you must run the above command from the root of the `logos-execution-zone` repository.
// Note: The compiled binary file is stored in
// target/riscv32im-risc0-zkvm-elf/docker/hello_world_with_move_function.bin
//
//
// Usage:
//   cargo run --bin run_hello_world_with_move_function \
//     /path/to/guest/binary <payer_account_id> [--program-id <id>] <function> <params>
//
// Example:
//   cargo run --bin run_hello_world_with_move_function \
//     $EXAMPLE_PROGRAMS_BUILD_DIR/hello_world_with_move_function.bin \
//     <funded payer account_id> \
//     write-public Ds8q5PjLcKwwV97Zi7duhRVF9uwA2PuYMoLL7FwCzsXE Hola

const WRITE_FUNCTION_ID: u8 = 0;
const MOVE_DATA_FUNCTION_ID: u8 = 1;

type Instruction = (u8, Vec<u8>);

#[derive(Parser, Debug)]
struct Cli {
    /// Path to program binary.
    program_path: String,

    /// An existing, funded account to pay the deployment and call fees.
    payer: AccountId,

    /// Call the instance of this program deployed by an earlier run, instead of deploying a new
    /// one. Each run prints the program account ID it calls.
    #[arg(long)]
    program_id: Option<AccountId>,

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

async fn shard_bytes(
    wallet_core: &WalletCore,
    account_id: AccountId,
    program_account_id: AccountId,
) -> Vec<u8> {
    wallet_core
        .get_account_view(ProgramShardSelector::new(account_id, program_account_id))
        .await
        .unwrap()
        .data
        .shard(program_account_id)
        .as_ref()
        .to_vec()
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize wallet
    let mut wallet_core = WalletCore::from_env().unwrap();

    // Deploy the program through `program_loader`, unless an earlier run already did; `program`
    // is also needed directly below, as the local proving bundle for the private-tx arms.
    let bytecode: Vec<u8> = std::fs::read(cli.program_path).unwrap();
    let program = Program::new(bytecode.clone().into()).unwrap();
    let program_account_id = match cli.program_id {
        Some(program_account_id) => program_account_id,
        None => deploy_program(&mut wallet_core, bytecode, cli.payer)
            .await
            .unwrap(),
    };
    println!("Program account ID: {program_account_id}");
    let program_with_dependencies =
        ProgramWithDependencies::new(program, program_account_id, HashMap::new());

    match cli.command {
        Command::WritePublic {
            account_id,
            greeting,
        } => {
            let instruction: Instruction = (WRITE_FUNCTION_ID, greeting.into_bytes());
            let account_id = account_id.parse().unwrap();
            // The fee payer is the only signer
            let (fee, payer_nonce, payer_key) = fee_paid_by(&wallet_core, cli.payer).await.unwrap();
            let nonces = vec![payer_nonce];
            let message = public_transaction::Message::try_new_with_fees(
                program_account_id,
                vec![ProgramShardSelector::new(account_id, program_account_id)],
                nonces,
                instruction,
                fee,
            )
            .unwrap();
            let witness_set = public_transaction::WitnessSet::for_message(&message, &[&payer_key]);
            let tx = PublicTransaction::new(message, witness_set);

            // Submit the transaction
            let _response = wallet_core
                .client_owned()
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
            let accounts = vec![
                AccountIdentity::PrivateOwned(account_id).select_program_shard(program_account_id),
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
        Command::MoveDataPublicToPublic { from, to } => {
            let from = from.parse().unwrap();
            let to = to.parse().unwrap();
            let moved = shard_bytes(&wallet_core, from, program_account_id).await;
            let instruction: Instruction = (MOVE_DATA_FUNCTION_ID, moved);
            // The fee payer is the only signer
            let (fee, payer_nonce, payer_key) = fee_paid_by(&wallet_core, cli.payer).await.unwrap();
            let nonces = vec![payer_nonce];
            let message = public_transaction::Message::try_new_with_fees(
                program_account_id,
                vec![
                    ProgramShardSelector::new(from, program_account_id),
                    ProgramShardSelector::new(to, program_account_id),
                ],
                nonces,
                instruction,
                fee,
            )
            .unwrap();
            let witness_set = public_transaction::WitnessSet::for_message(&message, &[&payer_key]);
            let tx = PublicTransaction::new(message, witness_set);

            // Submit the transaction
            let _response = wallet_core
                .client_owned()
                .send_transaction(LeeTransaction::Public(tx))
                .await
                .unwrap();
        }
        Command::MoveDataPublicToPrivate { from, to } => {
            let from = from.parse().unwrap();
            let to = to.parse().unwrap();
            let moved = shard_bytes(&wallet_core, from, program_account_id).await;
            let instruction: Instruction = (MOVE_DATA_FUNCTION_ID, moved);

            let accounts = vec![
                AccountIdentity::Public(from).select_program_shard(program_account_id),
                AccountIdentity::PrivateOwned(to).select_program_shard(program_account_id),
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
