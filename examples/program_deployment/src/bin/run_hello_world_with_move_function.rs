use clap::{Parser, Subcommand};
use common::transaction::NSSATransaction;
use nssa::{PublicTransaction, program::Program, public_transaction};
use sequencer_service_rpc::RpcClient as _;
use wallet::{PrivacyPreservingAccount, WalletCore};

// Before running this example, compile the `hello_world_with_move_function.rs` guest program with:
//
//   cargo risczero build --manifest-path examples/program_deployment/methods/guest/Cargo.toml
//
// Note: you must run the above command from the root of the `lssa` repository.
// Note: The compiled binary file is stored in
// methods/guest/target/riscv32im-risc0-zkvm-elf/docker/hello_world_with_move_function.bin
//
//
// Usage:
//   cargo run --bin run_hello_world_with_move_function /path/to/guest/binary <function> <params>
//
// Example:
//   cargo run --bin run_hello_world_with_move_function \
//     methods/guest/target/riscv32im-risc0-zkvm-elf/docker/hello_world_with_move_function.bin \
//     write-public Ds8q5PjLcKwwV97Zi7duhRVF9uwA2PuYMoLL7FwCzsXE Hola

const WRITE_FUNCTION_ID: u8 = 0;
const MOVE_DATA_FUNCTION_ID: u8 = 1;

type Instruction = (u8, Vec<u8>);

#[derive(Parser, Debug)]
struct Cli {
    /// Path to program binary.
    program_path: String,

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

    // Load the program
    let bytecode: Vec<u8> = std::fs::read(cli.program_path).unwrap();
    let program = Program::new(bytecode).unwrap();

    // Initialize wallet
    let wallet_core = WalletCore::from_env().unwrap();

    match cli.command {
        Command::WritePublic {
            account_id,
            greeting,
        } => {
            let instruction: Instruction = (WRITE_FUNCTION_ID, greeting.into_bytes());
            let account_id = account_id.parse().unwrap();
            let nonces = vec![];
            let message = public_transaction::Message::try_new(
                program.id(),
                vec![account_id],
                nonces,
                instruction,
            )
            .unwrap();
            let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
            let tx = PublicTransaction::new(message, witness_set);

            // Submit the transaction
            let _response = wallet_core
                .sequencer_client
                .send_transaction(NSSATransaction::Public(tx))
                .await
                .unwrap();
        }
        Command::WritePrivate {
            account_id,
            greeting,
        } => {
            let instruction: Instruction = (WRITE_FUNCTION_ID, greeting.into_bytes());
            let account_id = account_id.parse().unwrap();
            let accounts = vec![PrivacyPreservingAccount::PrivateOwned(account_id)];

            wallet_core
                .send_privacy_preserving_tx(
                    accounts,
                    Program::serialize_instruction(instruction).unwrap(),
                    &program.into(),
                )
                .await
                .unwrap();
        }
        Command::MoveDataPublicToPublic { from, to } => {
            let instruction: Instruction = (MOVE_DATA_FUNCTION_ID, vec![]);
            let from = from.parse().unwrap();
            let to = to.parse().unwrap();
            let nonces = vec![];
            let message = public_transaction::Message::try_new(
                program.id(),
                vec![from, to],
                nonces,
                instruction,
            )
            .unwrap();
            let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
            let tx = PublicTransaction::new(message, witness_set);

            // Submit the transaction
            let _response = wallet_core
                .sequencer_client
                .send_transaction(NSSATransaction::Public(tx))
                .await
                .unwrap();
        }
        Command::MoveDataPublicToPrivate { from, to } => {
            let instruction: Instruction = (MOVE_DATA_FUNCTION_ID, vec![]);
            let from = from.parse().unwrap();
            let to = to.parse().unwrap();

            let accounts = vec![
                PrivacyPreservingAccount::Public(from),
                PrivacyPreservingAccount::PrivateOwned(to),
            ];

            wallet_core
                .send_privacy_preserving_tx(
                    accounts,
                    Program::serialize_instruction(instruction).unwrap(),
                    &program.into(),
                )
                .await
                .unwrap();
        }
    }
}
