use clap::{Parser, Subcommand};
use common::transaction::LeeTransaction;
use lee::{
    AccountId, Actor, PublicTransaction, privacy_preserving_transaction::circuit::ProgramCatalog,
    program::Program, public_transaction,
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

// The guest's `Message::Write(data)`, `Message::MoveData { data, to }` and `Message::Append(data)`,
// borsh-encoded as a variant index followed by the fields.
const WRITE_FUNCTION_ID: u8 = 0;
const MOVE_DATA_FUNCTION_ID: u8 = 1;

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

async fn actor_state_bytes(
    wallet_core: &WalletCore,
    account_id: AccountId,
    program_account_id: AccountId,
) -> Vec<u8> {
    wallet_core
        .get_account_view(Actor::new(account_id, program_account_id))
        .await
        .unwrap()
        .data
        .actor_state(program_account_id)
        .as_ref()
        .to_vec()
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize wallet
    let mut wallet_core = WalletCore::from_env().await.unwrap();

    // Deploy the program through `program_loader`; `program` is also needed directly below, as
    // the local proving bundle for the private-tx arms.
    let bytecode: Vec<u8> = std::fs::read(cli.program_path).unwrap();
    let program = Program::new(bytecode.clone().into()).unwrap();
    let program_account_id = deploy_program(&mut wallet_core, bytecode, cli.payer)
        .await
        .unwrap();
    let programs = ProgramCatalog::from([(program_account_id, program)]);

    match cli.command {
        Command::WritePublic {
            account_id,
            greeting,
        } => {
            let message = (WRITE_FUNCTION_ID, greeting.into_bytes());
            let account = Actor::new(account_id.parse().unwrap(), program_account_id);
            let nonces = vec![];
            let message =
                public_transaction::Message::try_new(account, vec![account], nonces, message)
                    .unwrap();
            let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
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
            let message = (WRITE_FUNCTION_ID, greeting.into_bytes());
            let account = AccountIdentity::PrivateOwned(account_id.parse().unwrap())
                .select_program_actor_state(program_account_id);

            wallet_core
                .send_privacy_preserving_tx(
                    vec![account],
                    0,
                    Program::serialize_message(message).unwrap(),
                    &programs,
                )
                .await
                .unwrap();
        }
        Command::MoveDataPublicToPublic { from, to } => {
            let from = from.parse().unwrap();
            let to = to.parse().unwrap();
            let moved = actor_state_bytes(&wallet_core, from, program_account_id).await;
            let source = Actor::new(from, program_account_id);
            let destination = Actor::new(to, program_account_id);
            let message = (MOVE_DATA_FUNCTION_ID, moved, to);
            let nonces = vec![];
            let message = public_transaction::Message::try_new(
                source,
                vec![source, destination],
                nonces,
                message,
            )
            .unwrap();
            let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
            let tx = PublicTransaction::new(message, witness_set);

            // Submit the transaction
            let _response = wallet_core
                .helm_owned()
                .send_transaction(LeeTransaction::Public(tx))
                .await
                .unwrap();
        }
        Command::MoveDataPublicToPrivate { from, to } => {
            let from = from.parse().unwrap();
            let to = to.parse().unwrap();
            let moved = actor_state_bytes(&wallet_core, from, program_account_id).await;
            let source =
                AccountIdentity::Public(from).select_program_actor_state(program_account_id);
            let destination =
                AccountIdentity::PrivateOwned(to).select_program_actor_state(program_account_id);
            let accounts = vec![source, destination];
            let message = (MOVE_DATA_FUNCTION_ID, moved, to);

            wallet_core
                .send_privacy_preserving_tx(
                    accounts,
                    0,
                    Program::serialize_message(message).unwrap(),
                    &programs,
                )
                .await
                .unwrap();
        }
    }
}
