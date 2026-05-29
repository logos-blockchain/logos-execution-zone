use std::{io::Write as _, path::PathBuf, str::FromStr};

use anyhow::{Context as _, Result};
use bip39::Mnemonic;
use clap::{Parser, Subcommand};
use common::{HashType, transaction::LeeTransaction};
use derive_more::Display;
use futures::TryFutureExt as _;
use lee::{ProgramDeploymentTransaction, program::Program};
use sequencer_service_rpc::RpcClient as _;

pub use crate::helperfunctions::{read_mnemonic, read_pin};
use crate::{
    WalletCore,
    account::{AccountIdWithPrivacy, Label},
    cli::{
        account::AccountSubcommand,
        chain::ChainSubcommand,
        config::ConfigSubcommand,
        group::GroupSubcommand,
        keycard::KeycardSubcommand,
        programs::{
            amm::AmmProgramAgnosticSubcommand, ata::AtaSubcommand,
            native_token_transfer::AuthTransferSubcommand, pinata::PinataProgramAgnosticSubcommand,
            token::TokenProgramAgnosticSubcommand,
        },
    },
    storage::Storage,
};

pub mod account;
pub mod chain;
pub mod config;
pub mod group;
pub mod keycard;
pub mod programs;

pub(crate) trait WalletSubcommand {
    async fn handle_subcommand(self, wallet_core: &mut WalletCore)
    -> Result<SubcommandReturnValue>;
}

/// Represents CLI command for a wallet.
#[derive(Subcommand, Debug, Clone)]
#[clap(about)]
pub enum Command {
    /// Authenticated transfer subcommand.
    #[command(subcommand)]
    AuthTransfer(AuthTransferSubcommand),
    /// Generic chain info subcommand.
    #[command(subcommand)]
    ChainInfo(ChainSubcommand),
    /// Account view and sync subcommand.
    #[command(subcommand)]
    Account(AccountSubcommand),
    /// Pinata program interaction subcommand.
    #[command(subcommand)]
    Pinata(PinataProgramAgnosticSubcommand),
    /// Token program interaction subcommand.
    #[command(subcommand)]
    Token(TokenProgramAgnosticSubcommand),
    /// AMM program interaction subcommand.
    #[command(subcommand)]
    AMM(AmmProgramAgnosticSubcommand),
    /// Associated Token Account program interaction subcommand.
    #[command(subcommand)]
    Ata(AtaSubcommand),
    /// Group key management (create, invite, join, derive keys).
    #[command(subcommand)]
    Group(GroupSubcommand),
    /// Check the wallet can connect to the node and builtin local programs
    /// match the remote versions.
    CheckHealth,
    /// Command to setup config, get and set config fields.
    #[command(subcommand)]
    Config(ConfigSubcommand),
    /// Restoring keys from given password at given `depth`.
    ///
    /// !!!WARNING!!! will rewrite current storage.
    RestoreKeys {
        #[arg(short, long)]
        /// Indicates, how deep in tree accounts may be. Affects command complexity.
        depth: u32,
    },
    /// Deploy a program.
    DeployProgram { binary_filepath: PathBuf },
    /// Keycard hardware wallet management.
    #[command(subcommand)]
    Keycard(KeycardSubcommand),
}

/// To execute commands, env var `LEE_WALLET_HOME_DIR` must be set into directory with config.
///
/// All account addresses must be valid 32 byte base58 strings.
///
/// All account `account_ids` must be provided as {`privacy_prefix}/{account_id`},
/// where valid options for `privacy_prefix` is `Public` and `Private`.
#[derive(Parser, Debug)]
#[clap(version, about)]
pub struct Args {
    /// Continious run flag.
    #[arg(short, long)]
    pub continuous_run: bool,
    /// Basic authentication in the format `user` or `user:password`.
    #[arg(long)]
    pub auth: Option<String>,
    /// Wallet command.
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Clone)]
pub enum SubcommandReturnValue {
    PrivacyPreservingTransfer { tx_hash: HashType },
    RegisterAccount { account_id: lee::AccountId },
    Account(lee::Account),
    Empty,
    SyncedToBlock(u64),
}

#[derive(Debug, Display, Clone, PartialEq, Eq, Hash)]
pub enum CliAccountMention {
    #[display("{_0}")]
    Id(AccountIdWithPrivacy),
    #[display("{_0}")]
    Label(Label),
    #[display("{_0}")]
    KeyPath(String),
}

impl CliAccountMention {
    pub fn resolve(&self, storage: &Storage) -> Result<AccountIdWithPrivacy> {
        match self {
            Self::Id(account_id) => Ok(*account_id),
            Self::Label(label) => storage
                .resolve_label(label)
                .ok_or_else(|| anyhow::anyhow!("No account found for label `{label}`")),
            Self::KeyPath(path) => {
                let pin = read_pin()?;
                let id_str =
                    keycard_wallet::KeycardWallet::get_account_id_for_path_with_connect(&pin, path)
                        .map_err(anyhow::Error::from)?;
                AccountIdWithPrivacy::from_str(&id_str)
                    .map_err(|e| anyhow::anyhow!("Invalid account id from keycard: {e}"))
            }
        }
    }
}

impl FromStr for CliAccountMention {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s.starts_with("m/") {
            return Ok(Self::KeyPath(s.to_owned()));
        }
        AccountIdWithPrivacy::from_str(s).map_or_else(
            |_| Ok(Self::Label(Label::new(s.to_owned()))),
            |account_id| Ok(Self::Id(account_id)),
        )
    }
}

impl From<Label> for CliAccountMention {
    fn from(label: Label) -> Self {
        Self::Label(label)
    }
}

impl Default for CliAccountMention {
    fn default() -> Self {
        Self::Label(Label::new(String::new()))
    }
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
        Command::CheckHealth => {
            let remote_program_ids = wallet_core
                .sequencer_client
                .get_program_ids()
                .await
                .expect("Error fetching program ids");
            let Some(authenticated_transfer_id) = remote_program_ids.get("authenticated_transfer")
            else {
                panic!("Missing authenticated transfer ID from remote");
            };
            assert!(
                authenticated_transfer_id == &Program::authenticated_transfer_program().id(),
                "Local ID for authenticated transfer program is different from remote"
            );
            let Some(token_id) = remote_program_ids.get("token") else {
                panic!("Missing token program ID from remote");
            };
            assert!(
                token_id == &Program::token().id(),
                "Local ID for token program is different from remote"
            );
            let Some(circuit_id) = remote_program_ids.get("privacy_preserving_circuit") else {
                panic!("Missing privacy preserving circuit ID from remote");
            };
            assert!(
                circuit_id == &lee::PRIVACY_PRESERVING_CIRCUIT_ID,
                "Local ID for privacy preserving circuit is different from remote"
            );
            let Some(amm_id) = remote_program_ids.get("amm") else {
                panic!("Missing AMM program ID from remote");
            };
            assert!(
                amm_id == &Program::amm().id(),
                "Local ID for AMM program is different from remote"
            );

            println!("\u{2705}All looks good!");

            SubcommandReturnValue::Empty
        }
        Command::Token(token_subcommand) => token_subcommand.handle_subcommand(wallet_core).await?,
        Command::AMM(amm_subcommand) => amm_subcommand.handle_subcommand(wallet_core).await?,
        Command::Ata(ata_subcommand) => ata_subcommand.handle_subcommand(wallet_core).await?,
        Command::Group(group_subcommand) => group_subcommand.handle_subcommand(wallet_core).await?,
        Command::Keycard(keycard_subcommand) => {
            keycard_subcommand.handle_subcommand(wallet_core).await?
        }
        Command::Config(config_subcommand) => {
            config_subcommand.handle_subcommand(wallet_core).await?
        }
        Command::RestoreKeys { depth } => {
            let mnemonic = read_mnemonic_from_stdin()?;
            let password = read_password_from_stdin()?;
            wallet_core.restore_storage(&mnemonic, &password)?;
            execute_keys_restoration(wallet_core, depth).await?;

            SubcommandReturnValue::Empty
        }
        Command::DeployProgram { binary_filepath } => {
            let bytecode: Vec<u8> = std::fs::read(&binary_filepath).context(format!(
                "Failed to read program binary at {}",
                binary_filepath.display()
            ))?;
            let message = lee::program_deployment_transaction::Message::new(bytecode);
            let transaction = ProgramDeploymentTransaction::new(message);
            let _response = wallet_core
                .sequencer_client
                .send_transaction(LeeTransaction::ProgramDeployment(transaction))
                .await
                .context("Transaction submission error")?;

            SubcommandReturnValue::Empty
        }
    };

    Ok(subcommand_ret)
}

pub async fn execute_continuous_run(wallet_core: &mut WalletCore) -> Result<()> {
    loop {
        wallet_core.sync_to_latest_block().await?;
        tokio::time::sleep(wallet_core.config().seq_poll_timeout).await;
    }
}

pub fn read_password_from_stdin() -> Result<String> {
    let mut password = String::new();

    print!("Input password: ");
    std::io::stdout().flush()?;
    std::io::stdin().read_line(&mut password)?;

    Ok(password.trim().to_owned())
}

/// Parse a keys file exported by `wallet account show-keys`.
///
/// The file format is two lines:
/// - Line 1: npk as hex (64 chars, 32 bytes).
/// - Line 2: vpk as hex (2368 chars, 1184 bytes).
///
/// Returns `(npk_bytes, vpk_bytes)`.
pub fn read_keys_file(path: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let content = std::fs::read_to_string(path).with_context(|| {
        format!("wallet::cli::read_keys_file: failed to read keys file: {path}")
    })?;
    let mut lines = content.lines().filter(|l| !l.trim().is_empty());
    let npk_hex = lines.next().ok_or_else(|| {
        anyhow::anyhow!("wallet::cli::read_keys_file: keys file is missing npk (line 1)")
    })?;
    let vpk_hex = lines.next().ok_or_else(|| {
        anyhow::anyhow!("wallet::cli::read_keys_file: keys file is missing vpk (line 2)")
    })?;
    let npk = hex::decode(npk_hex.trim())
        .context("wallet::cli::read_keys_file: npk in keys file must be valid hex")?;
    let vpk = hex::decode(vpk_hex.trim())
        .context("wallet::cli::read_keys_file: vpk in keys file must be valid hex")?;
    Ok((npk, vpk))
}

pub fn read_mnemonic_from_stdin() -> Result<Mnemonic> {
    let mut phrase = String::new();

    print!("Input recovery phrase: ");
    std::io::stdout().flush()?;
    std::io::stdin().read_line(&mut phrase)?;

    Mnemonic::from_str(phrase.trim()).context("Invalid mnemonic phrase")
}

pub async fn execute_keys_restoration(wallet_core: &mut WalletCore, depth: u32) -> Result<()> {
    wallet_core
        .storage
        .key_chain_mut()
        .generate_trees_for_depth(depth);

    println!(
        "Public tree generated\n\
         Private tree generated"
    );

    wallet_core.sync_to_latest_block().await?;

    wallet_core
        .storage
        .key_chain_mut()
        .cleanup_trees_remove_uninit_layered(depth, |account_id| {
            wallet_core
                .sequencer_client
                .get_account(account_id)
                .map_err(Into::into)
        })
        .await?;

    println!(
        "Public tree cleaned up\n\
         Private tree cleaned up"
    );

    wallet_core.store_persistent_data()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_keys_file_roundtrip() {
        let npk = [0xab_u8; 32];
        let vpk = [0xcd_u8; 1184];

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.keys");

        // Simulate what `wallet account show-keys` writes.
        std::fs::write(
            &path,
            format!("{}\n{}\n", hex::encode(npk), hex::encode(vpk)),
        )
        .unwrap();

        let (parsed_npk, parsed_vpk) = read_keys_file(path.to_str().unwrap()).unwrap();

        assert_eq!(parsed_npk, npk, "npk must round-trip through the keys file");
        assert_eq!(
            parsed_vpk,
            vpk.to_vec(),
            "vpk must round-trip through the keys file"
        );
    }

    #[test]
    fn read_keys_file_missing_vpk_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("incomplete.keys");
        std::fs::write(&path, format!("{}\n", hex::encode([0xab_u8; 32]))).unwrap();

        let result = read_keys_file(path.to_str().unwrap());
        assert!(result.is_err(), "missing vpk line must return an error");
        assert!(
            result.unwrap_err().to_string().contains("missing vpk"),
            "error must mention missing vpk"
        );
    }

    #[test]
    fn read_keys_file_invalid_hex_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("badhex.keys");
        std::fs::write(&path, "not-hex\nalso-not-hex\n").unwrap();

        let result = read_keys_file(path.to_str().unwrap());
        assert!(result.is_err(), "invalid hex must return an error");
    }

    #[test]
    fn read_keys_file_ignores_blank_lines() {
        let npk = [0x11_u8; 32];
        let vpk = [0x22_u8; 1184];

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blanks.keys");

        // Extra blank lines around the data should be tolerated.
        std::fs::write(
            &path,
            format!("\n{}\n\n{}\n\n", hex::encode(npk), hex::encode(vpk)),
        )
        .unwrap();

        let (parsed_npk, parsed_vpk) = read_keys_file(path.to_str().unwrap()).unwrap();
        assert_eq!(parsed_npk, npk);
        assert_eq!(parsed_vpk, vpk.to_vec());
    }
}
