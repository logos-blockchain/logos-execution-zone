use std::{io::Write, path::PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use common::HashType;
use nssa::{ProgramDeploymentTransaction, program::Program};

use crate::{
    WalletCore,
    cli::{
        account::AccountSubcommand,
        chain::ChainSubcommand,
        config::ConfigSubcommand,
        programs::{
            amm::AmmProgramAgnosticSubcommand, ata::AtaSubcommand,
            native_token_transfer::AuthTransferSubcommand, pinata::PinataProgramAgnosticSubcommand,
            token::TokenProgramAgnosticSubcommand,
        },
    },
};

pub mod account;
pub mod chain;
pub mod config;
pub mod programs;

pub(crate) trait WalletSubcommand {
    async fn handle_subcommand(self, wallet_core: &mut WalletCore)
    -> Result<SubcommandReturnValue>;
}

/// Represents CLI command for a wallet
#[derive(Subcommand, Debug, Clone)]
#[clap(about)]
pub enum Command {
    /// Authenticated transfer subcommand
    #[command(subcommand)]
    AuthTransfer(AuthTransferSubcommand),
    /// Generic chain info subcommand
    #[command(subcommand)]
    ChainInfo(ChainSubcommand),
    /// Account view and sync subcommand
    #[command(subcommand)]
    Account(AccountSubcommand),
    /// Pinata program interaction subcommand
    #[command(subcommand)]
    Pinata(PinataProgramAgnosticSubcommand),
    /// Token program interaction subcommand
    #[command(subcommand)]
    Token(TokenProgramAgnosticSubcommand),
    /// AMM program interaction subcommand
    #[command(subcommand)]
    AMM(AmmProgramAgnosticSubcommand),
    /// Associated Token Account program interaction subcommand
    #[command(subcommand)]
    Ata(AtaSubcommand),
    /// Check the wallet can connect to the node and builtin local programs
    /// match the remote versions
    CheckHealth {},
    /// Command to setup config, get and set config fields
    #[command(subcommand)]
    Config(ConfigSubcommand),
    /// Restoring keys from given password at given `depth`
    ///
    /// !!!WARNING!!! will rewrite current storage
    RestoreKeys {
        #[arg(short, long)]
        /// Indicates, how deep in tree accounts may be. Affects command complexity.
        depth: u32,
    },
    /// Deploy a program
    DeployProgram { binary_filepath: PathBuf },
}

/// To execute commands, env var NSSA_WALLET_HOME_DIR must be set into directory with config
///
/// All account addresses must be valid 32 byte base58 strings.
///
/// All account account_ids must be provided as {privacy_prefix}/{account_id},
/// where valid options for `privacy_prefix` is `Public` and `Private`
#[derive(Parser, Debug)]
#[clap(version, about)]
pub struct Args {
    /// Continious run flag
    #[arg(short, long)]
    pub continuous_run: bool,
    /// Basic authentication in the format `user` or `user:password`
    #[arg(long)]
    pub auth: Option<String>,
    /// Wallet command
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Clone)]
pub enum SubcommandReturnValue {
    PrivacyPreservingTransfer { tx_hash: HashType },
    RegisterAccount { account_id: nssa::AccountId },
    Account(nssa::Account),
    Empty,
    SyncedToBlock(u64),
}

pub async fn execute_subcommand(
    wallet_core: &mut WalletCore,
    command: Command,
) -> Result<SubcommandReturnValue> {
    let subcommand_ret = match command {
        Command::AuthTransfer(transfer_subcommand) => {
            transfer_subcommand.handle_subcommand(wallet_core).await?
        }
        Command::ChainInfo(chain_subcommand) => {
            chain_subcommand.handle_subcommand(wallet_core).await?
        }
        Command::Account(account_subcommand) => {
            account_subcommand.handle_subcommand(wallet_core).await?
        }
        Command::Pinata(pinata_subcommand) => {
            pinata_subcommand.handle_subcommand(wallet_core).await?
        }
        Command::CheckHealth {} => {
            let remote_program_ids = wallet_core
                .sequencer_client
                .get_program_ids()
                .await
                .expect("Error fetching program ids");
            let Some(authenticated_transfer_id) = remote_program_ids.get("authenticated_transfer")
            else {
                panic!("Missing authenticated transfer ID from remote");
            };
            if authenticated_transfer_id != &Program::authenticated_transfer_program().id() {
                panic!("Local ID for authenticated transfer program is different from remote");
            }
            let Some(token_id) = remote_program_ids.get("token") else {
                panic!("Missing token program ID from remote");
            };
            if token_id != &Program::token().id() {
                panic!("Local ID for token program is different from remote");
            }
            let Some(circuit_id) = remote_program_ids.get("privacy_preserving_circuit") else {
                panic!("Missing privacy preserving circuit ID from remote");
            };
            if circuit_id != &nssa::PRIVACY_PRESERVING_CIRCUIT_ID {
                panic!("Local ID for privacy preserving circuit is different from remote");
            }
            let Some(amm_id) = remote_program_ids.get("amm") else {
                panic!("Missing AMM program ID from remote");
            };
            if amm_id != &Program::amm().id() {
                panic!("Local ID for AMM program is different from remote");
            }

            println!("✅All looks good!");

            SubcommandReturnValue::Empty
        }
        Command::Token(token_subcommand) => token_subcommand.handle_subcommand(wallet_core).await?,
        Command::AMM(amm_subcommand) => amm_subcommand.handle_subcommand(wallet_core).await?,
        Command::Ata(ata_subcommand) => ata_subcommand.handle_subcommand(wallet_core).await?,
        Command::Config(config_subcommand) => {
            config_subcommand.handle_subcommand(wallet_core).await?
        }
        Command::RestoreKeys { depth } => {
            let password = read_password_from_stdin()?;
            wallet_core.reset_storage(password)?;
            execute_keys_restoration(wallet_core, depth).await?;

            SubcommandReturnValue::Empty
        }
        Command::DeployProgram { binary_filepath } => {
            let bytecode: Vec<u8> = std::fs::read(&binary_filepath).context(format!(
                "Failed to read program binary at {}",
                binary_filepath.display()
            ))?;
            let message = nssa::program_deployment_transaction::Message::new(bytecode);
            let transaction = ProgramDeploymentTransaction::new(message);
            let _response = wallet_core
                .sequencer_client
                .send_tx_program(transaction)
                .await
                .context("Transaction submission error")?;

            SubcommandReturnValue::Empty
        }
    };

    Ok(subcommand_ret)
}

pub async fn execute_continuous_run(wallet_core: &mut WalletCore) -> Result<()> {
    loop {
        let latest_block_num = wallet_core
            .sequencer_client
            .get_last_block()
            .await?
            .last_block;
        wallet_core.sync_to_block(latest_block_num).await?;

        tokio::time::sleep(wallet_core.config().seq_poll_timeout).await;
    }
}

pub fn read_password_from_stdin() -> Result<String> {
    let mut password = String::new();

    print!("Input password: ");
    std::io::stdout().flush()?;
    std::io::stdin().read_line(&mut password)?;

    Ok(password.trim().to_string())
}

pub async fn execute_keys_restoration(wallet_core: &mut WalletCore, depth: u32) -> Result<()> {
    wallet_core
        .storage
        .user_data
        .public_key_tree
        .generate_tree_for_depth(depth);

    println!("Public tree generated");

    wallet_core
        .storage
        .user_data
        .private_key_tree
        .generate_tree_for_depth(depth);

    println!("Private tree generated");

    wallet_core
        .storage
        .user_data
        .public_key_tree
        .cleanup_tree_remove_uninit_layered(depth, wallet_core.sequencer_client.clone())
        .await?;

    println!("Public tree cleaned up");

    let last_block = wallet_core
        .sequencer_client
        .get_last_block()
        .await?
        .last_block;

    println!("Last block is {last_block}");

    wallet_core.sync_to_block(last_block).await?;

    println!("Private tree clean up start");

    wallet_core
        .storage
        .user_data
        .private_key_tree
        .cleanup_tree_remove_uninit_layered(depth);

    println!("Private tree cleaned up");

    wallet_core.store_persistent_data().await?;

    Ok(())
}
