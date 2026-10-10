use std::{io::Write as _, str::FromStr};

use anyhow::{Context as _, Result};
use bip39::Mnemonic;
use clap::{Parser, Subcommand};
use common::HashType;
use derive_more::Display;
use lee::PublicKey;
use lee_core::{BlockId, NullifierPublicKey, PrivateAccountKind, encryption::ViewingPublicKey};

pub use crate::helperfunctions::{read_mnemonic, read_pin};
use crate::{
    AccountIdentity, WalletCore,
    account::{AccountIdWithPrivacy, Label},
    cli::{
        account::AccountSubcommand,
        chain::ChainSubcommand,
        config::ConfigSubcommand,
        group::GroupSubcommand,
        keycard::KeycardSubcommand,
        network::NetworkAlias,
        pending::PendingSubcommand,
        programs::{
            amm::AmmProgramAgnosticSubcommand, ata::AtaSubcommand, bridge::BridgeSubcommand,
            native_token_transfer::AuthTransferSubcommand, program_loader::ProgramLoaderSubcommand,
            token::TokenProgramAgnosticSubcommand,
        },
        statistics::StatisticsSubcommand,
    },
    config::SequencerConnectionData,
    storage::Storage,
};

pub mod account;
pub mod chain;
pub mod config;
pub mod group;
pub mod keycard;
pub mod network;
pub mod pending;
pub mod programs;
pub mod statistics;

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
    /// Token program interaction subcommand.
    #[command(subcommand)]
    Token(TokenProgramAgnosticSubcommand),
    /// AMM program interaction subcommand.
    #[command(subcommand)]
    AMM(AmmProgramAgnosticSubcommand),
    /// Associated Token Account program interaction subcommand.
    #[command(subcommand)]
    Ata(AtaSubcommand),
    /// Bridge program interaction subcommand.
    #[command(subcommand)]
    Bridge(BridgeSubcommand),
    /// `program_loader` program interaction subcommand (deploy/update a program).
    #[command(subcommand)]
    ProgramLoader(ProgramLoaderSubcommand),
    /// Group key management (create, invite, join, derive keys).
    #[command(subcommand)]
    Group(GroupSubcommand),
    /// Pending messages cast to this wallet's accounts (list, receive).
    #[command(subcommand)]
    Pending(PendingSubcommand),
    /// Check the wallet can connect to the node and builtin local programs
    /// match the remote versions.
    CheckHealth,
    /// Command to setup config, get and set config fields.
    #[command(subcommand)]
    Config(ConfigSubcommand),
    /// Change the network the wallet points to.
    ChangeNetwork {
        /// `testnet`, `local`, or a custom sequencer URL.
        network: NetworkAlias,
    },
    /// Restoring keys from given password at given `depth`.
    ///
    /// !!!WARNING!!! will rewrite current storage.
    RestoreKeys {
        #[arg(short, long)]
        /// Indicates, how deep in tree accounts may be. Affects command complexity.
        depth: u32,
    },
    /// Keycard hardware wallet management.
    #[command(subcommand)]
    Keycard(KeycardSubcommand),
    /// Metrics management.
    #[command(subcommand)]
    Statistics(StatisticsSubcommand),
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
    /// Wallet command.
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Clone)]
pub enum SubcommandReturnValue {
    TransactionExecuted { tx_hash: HashType },
    RegisterAccount { account_id: lee::AccountId },
    Account(lee::Account),
    Empty,
    SyncedToBlock(BlockId),
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
                    keycard_wallet::KeycardWallet::get_public_account_id_for_path_with_connect(
                        &pin, path,
                    )
                    .map_err(anyhow::Error::from)?;
                AccountIdWithPrivacy::from_str(&id_str)
                    .map_err(|e| anyhow::anyhow!("Invalid account id from keycard: {e}"))
            }
        }
    }

    #[must_use]
    pub fn key_path(&self) -> Option<&str> {
        match self {
            Self::KeyPath(path) => Some(path),
            Self::Id(_) | Self::Label(_) => None,
        }
    }

    /// Convert to an [`crate::AccountIdentity`] for use in a public transaction.
    ///
    /// The `sign` flag indicates whether to sign or not with the account keys.
    #[must_use]
    pub fn into_public_identity(
        self,
        account_id: lee::AccountId,
        sign: bool,
    ) -> crate::AccountIdentity {
        match self {
            Self::KeyPath(key_path) => crate::AccountIdentity::PublicKeycard {
                account_id,
                key_path,
            },
            Self::Id(_) | Self::Label(_) if sign => crate::AccountIdentity::Public(account_id),
            Self::Id(_) | Self::Label(_) => crate::AccountIdentity::PublicNoSign(account_id),
        }
    }

    // An account that signs where public, with its keycard when named by a key path.
    pub(crate) fn signer(self, storage: &Storage) -> Result<AccountIdentity> {
        match self {
            Self::KeyPath(key_path) => Ok(AccountIdentity::PublicKeycard {
                account_id: lee::AccountId::from(&keycard_public_key(&key_path)?),
                key_path,
            }),
            Self::Id(_) | Self::Label(_) => self.stored(storage, AccountIdentity::Public),
        }
    }

    // An account that does not sign; a keycard's public key admits its account on first use.
    pub(crate) fn unsigned(self, storage: &Storage) -> Result<AccountIdentity> {
        match self {
            Self::KeyPath(key_path) => Ok(AccountIdentity::PublicForeign(keycard_public_key(
                &key_path,
            )?)),
            Self::Id(_) | Self::Label(_) => self.stored(storage, AccountIdentity::PublicNoSign),
        }
    }

    fn stored(
        &self,
        storage: &Storage,
        public: fn(lee::AccountId) -> AccountIdentity,
    ) -> Result<AccountIdentity> {
        Ok(match self.resolve(storage)? {
            AccountIdWithPrivacy::Public(account_id) => public(account_id),
            AccountIdWithPrivacy::Private(account_id) => AccountIdentity::PrivateOwned(account_id),
        })
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
        Command::CheckHealth => {
            let remote_program_ids = wallet_core
                .get_program_ids()
                .await
                .expect("Error fetching program ids");
            let Some(token_id) = remote_program_ids.get("token") else {
                panic!("Missing token program ID from remote");
            };
            assert!(
                token_id == &::programs::token().id(),
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
                amm_id == &::programs::amm().id(),
                "Local ID for AMM program is different from remote"
            );

            println!("\u{2705}All looks good!");

            SubcommandReturnValue::Empty
        }
        Command::Token(token_subcommand) => token_subcommand.handle_subcommand(wallet_core).await?,
        Command::AMM(amm_subcommand) => amm_subcommand.handle_subcommand(wallet_core).await?,
        Command::Ata(ata_subcommand) => ata_subcommand.handle_subcommand(wallet_core).await?,
        Command::Bridge(bridge_subcommand) => {
            bridge_subcommand.handle_subcommand(wallet_core).await?
        }
        Command::ProgramLoader(program_loader_subcommand) => {
            program_loader_subcommand
                .handle_subcommand(wallet_core)
                .await?
        }
        Command::Group(group_subcommand) => group_subcommand.handle_subcommand(wallet_core).await?,
        Command::Pending(pending_subcommand) => {
            pending_subcommand.handle_subcommand(wallet_core).await?
        }
        Command::Keycard(keycard_subcommand) => {
            keycard_subcommand.handle_subcommand(wallet_core).await?
        }
        Command::Config(config_subcommand) => {
            config_subcommand.handle_subcommand(wallet_core).await?
        }
        Command::ChangeNetwork { network } => {
            let sequencer_addr: url::Url = network.try_into().context("Invalid sequencer URL")?;

            let mut config = wallet_core.config().clone();
            config.sequencers = vec![SequencerConnectionData {
                sequencer_addr,
                basic_auth: None,
            }];

            wallet_core.set_config(config);
            wallet_core.store_config_changes().await?;

            SubcommandReturnValue::Empty
        }
        Command::RestoreKeys { depth } => {
            let mnemonic = read_mnemonic_from_stdin()?;
            let password = read_password_from_stdin()?;
            wallet_core.restore_storage(&mnemonic, &password)?;
            wallet_core.restore_keys(depth).await?;

            SubcommandReturnValue::Empty
        }
        Command::Statistics(statistics_subcommand) => {
            statistics_subcommand.handle_subcommand(wallet_core).await?
        }
    };

    // Kind of a sledgehammer solution, but it is not clear if there is the case to not store
    // statistics
    wallet_core
        .client_rotation()
        .await
        .context("Failed to rotate wallet")?;

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
/// Returns `(npk, vpk)`.
pub fn read_keys_file(path: &str) -> Result<(NullifierPublicKey, ViewingPublicKey)> {
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
    decode_npk_vpk(npk_hex.trim(), vpk_hex.trim())
}

// The destination a command names: an account, a private account's public keys or a keys file
// holding them, or the public key of a public account not used yet.
pub(crate) fn destination(
    storage: &Storage,
    account: Option<CliAccountMention>,
    npk: Option<String>,
    vpk: Option<String>,
    keys_file: Option<String>,
    public_key: Option<PublicKey>,
) -> Result<AccountIdentity> {
    if let Some(public_key) = public_key {
        return Ok(AccountIdentity::PublicForeign(public_key));
    }
    let (npk, vpk) = match (account, npk, vpk, keys_file) {
        (Some(account), None, None, None) => return account.unsigned(storage),
        (None, Some(npk), Some(vpk), None) => decode_npk_vpk(&npk, &vpk)?,
        (None, None, None, Some(path)) => read_keys_file(&path)?,
        (None, None, None, None) => {
            anyhow::bail!("Provide either account account_id of receiver or their public keys")
        }
        (_, Some(_), None, _) | (_, None, Some(_), _) => {
            anyhow::bail!("List of public keys is uncomplete")
        }
        (Some(_), _, _, _) | (None, Some(_), Some(_), Some(_)) => anyhow::bail!(
            "Provide only one variant: either account account_id of receiver or their public keys"
        ),
    };
    Ok(AccountIdentity::PrivateForeign {
        npk,
        vpk,
        kind: PrivateAccountKind::Regular,
    })
}

fn keycard_public_key(key_path: &str) -> Result<PublicKey> {
    Ok(
        keycard_wallet::KeycardWallet::get_public_key_for_path_with_connect(
            &read_pin()?,
            key_path,
        )?,
    )
}

pub(crate) fn decode_npk_vpk(
    npk_hex: &str,
    vpk_hex: &str,
) -> Result<(NullifierPublicKey, ViewingPublicKey)> {
    let npk_bytes: [u8; 32] = hex::decode(npk_hex)
        .context("npk must be valid hex")?
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("npk must be exactly 32 bytes, got {}", v.len()))?;

    let vpk = ViewingPublicKey::from_bytes(hex::decode(vpk_hex).context("vpk must be valid hex")?)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    Ok((NullifierPublicKey(npk_bytes), vpk))
}

pub fn read_mnemonic_from_stdin() -> Result<Mnemonic> {
    let mut phrase = String::new();

    print!("Input recovery phrase: ");
    std::io::stdout().flush()?;
    std::io::stdin().read_line(&mut phrase)?;

    Mnemonic::from_str(phrase.trim()).context("Invalid mnemonic phrase")
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

        assert_eq!(
            parsed_npk.0, npk,
            "npk must round-trip through the keys file"
        );
        assert_eq!(
            parsed_vpk.to_bytes(),
            vpk,
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
        assert_eq!(parsed_npk.0, npk);
        assert_eq!(parsed_vpk.to_bytes(), vpk);
    }

    #[test]
    fn a_destination_is_one_account_one_set_of_keys_or_one_public_key() {
        let (storage, _) = Storage::new("password").unwrap();
        let npk = NullifierPublicKey([1; 32]);
        let vpk = ViewingPublicKey::from_seed(&[2; 32], &[3; 32]);
        let (npk_hex, vpk_hex) = (hex::encode(npk.0), hex::encode(vpk.to_bytes()));
        let dir = tempfile::tempdir().unwrap();
        let keys_path = dir.path().join("recipient.keys");
        std::fs::write(&keys_path, format!("{npk_hex}\n{vpk_hex}\n")).unwrap();
        let keys_file = keys_path.to_str().unwrap().to_owned();
        let account_id = lee::AccountId::new([4; 32]);
        let public_key =
            PublicKey::new_from_private_key(&lee::PrivateKey::try_new([5; 32]).unwrap());
        let mention = |prefix: &str| {
            Some(CliAccountMention::from_str(&format!("{prefix}/{account_id}")).unwrap())
        };
        let foreign = AccountIdentity::PrivateForeign {
            npk,
            vpk,
            kind: PrivateAccountKind::Regular,
        };

        for (account, npk, vpk, keys, public, expected) in [
            (
                None,
                Some(&npk_hex),
                Some(&vpk_hex),
                None,
                None,
                foreign.clone(),
            ),
            (None, None, None, Some(&keys_file), None, foreign),
            (
                None,
                None,
                None,
                None,
                Some(public_key.clone()),
                AccountIdentity::PublicForeign(public_key),
            ),
            (
                mention("Public"),
                None,
                None,
                None,
                None,
                AccountIdentity::PublicNoSign(account_id),
            ),
            (
                mention("Private"),
                None,
                None,
                None,
                None,
                AccountIdentity::PrivateOwned(account_id),
            ),
        ] {
            let named = destination(
                &storage,
                account,
                npk.cloned(),
                vpk.cloned(),
                keys.cloned(),
                public,
            );
            assert_eq!(named.unwrap(), expected);
        }

        // Missing, incomplete or competing material names no destination.
        for (account, npk, vpk, keys) in [
            (None, None, None, None),
            (None, Some(&npk_hex), None, None),
            (mention("Public"), Some(&npk_hex), Some(&vpk_hex), None),
            (mention("Public"), None, None, Some(&keys_file)),
        ] {
            assert!(
                destination(
                    &storage,
                    account,
                    npk.cloned(),
                    vpk.cloned(),
                    keys.cloned(),
                    None
                )
                .is_err()
            );
        }
    }
}
