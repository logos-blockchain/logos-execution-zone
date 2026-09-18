#![expect(
    clippy::print_stderr,
    reason = "This is a CLI application, printing to stderr is expected and convenient"
)]

use anyhow::Result;
use clap::Subcommand;
use keycard_wallet::KeycardWallet;

use crate::{
    WalletCore,
    cli::{SubcommandReturnValue, WalletSubcommand, read_mnemonic, read_pin},
};

/// Represents generic chain CLI subcommand.
#[derive(Subcommand, Debug, Clone)]
pub enum KeycardSubcommand {
    Available,
    Connect,
    Init,
    Load,
    /// Wipes the card's PIN, PUK, and loaded keys back to an uninitialized state, so it can be
    /// re-initialized with `wallet keycard init`. Irreversibly destroys any keys currently on
    /// the card. Requires --confirm.
    FactoryReset {
        /// Confirm that the card's current keys should be irreversibly destroyed.
        #[arg(long)]
        confirm: bool,
    },
    /// Retrieve the private keys (NSK, VSK) for a given BIP-32 key path.
    ///
    /// Prints raw key material to stdout — intended for debugging only.
    /// Requires --reveal to confirm intent.
    /// Only available when built with the `keycard-debug` feature.
    #[cfg(feature = "keycard-debug")]
    GetPrivateKeys {
        /// BIP-32 derivation path, e.g. `m/44'/60'/0'/0/0`.
        #[arg(long)]
        key_path: String,
        /// Confirm that raw NSK and VSK should be disclosed on stdout.
        #[arg(long)]
        reveal: bool,
    },
}

impl KeycardSubcommand {
    fn handle_available(_wallet_core: &mut WalletCore) -> SubcommandReturnValue {
        if KeycardWallet::is_keycard_available() {
            println!("\u{2705} Keycard is available.");
        } else {
            println!("\u{274c} Keycard is not available.");
        }

        SubcommandReturnValue::Empty
    }

    fn handle_connect(_wallet_core: &mut WalletCore) -> Result<SubcommandReturnValue> {
        let pin = read_pin()?;

        let mut wallet = KeycardWallet::new()?;
        wallet.connect(&pin)?;
        println!("\u{2705} Keycard connected and PIN verified.");

        Ok(SubcommandReturnValue::Empty)
    }

    fn handle_init(_wallet_core: &mut WalletCore) -> Result<SubcommandReturnValue> {
        let pin = read_pin()?;

        let mut wallet = KeycardWallet::new()?;
        let puk = wallet.initialize(&pin)?;

        println!("Keycard PUK: {puk}");
        println!("Record this PUK and store it somewhere safe. It cannot be recovered.");
        println!("\u{2705} Keycard initialized successfully.");

        Ok(SubcommandReturnValue::Empty)
    }

    fn handle_load(_wallet_core: &mut WalletCore) -> Result<SubcommandReturnValue> {
        let pin = read_pin()?;
        let mnemonic = read_mnemonic()?;

        let mut wallet = KeycardWallet::new()?;
        wallet.connect(&pin)?;
        println!("\u{2705} Keycard is now connected to wallet.");

        wallet.load_mnemonic(&mnemonic)?;
        println!("\u{2705} Mnemonic phrase loaded successfully.");

        Ok(SubcommandReturnValue::Empty)
    }

    fn handle_factory_reset(
        confirm: bool,
        _wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        if !confirm {
            eprintln!(
                "WARNING: pass --confirm to factory-reset the keycard. \
                 This irreversibly destroys any keys currently loaded on it."
            );
            return Ok(SubcommandReturnValue::Empty);
        }

        let mut wallet = KeycardWallet::new()?;
        wallet.factory_reset()?;
        println!("\u{2705} Keycard factory-reset. Run `wallet keycard init` to reinitialize it.");

        Ok(SubcommandReturnValue::Empty)
    }

    #[cfg(feature = "keycard-debug")]
    fn handle_get_private_keys(
        key_path: &str,
        reveal: bool,
        _wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        if !reveal {
            eprintln!(
                "WARNING: pass --reveal to print NSK and VSK. \
                 Disclosing either key fully compromises the account's privacy."
            );
            return Ok(SubcommandReturnValue::Empty);
        }
        eprintln!(
            "WARNING: NSK and VSK are being printed to stdout. \
             Any terminal log, scrollback, or screen recording captures these keys."
        );
        let pin = read_pin()?;
        let (nsk, vsk) = KeycardWallet::get_private_keys_for_path_with_connect(&pin, key_path)
            .map_err(anyhow::Error::from)?;
        println!("NSK: {}", hex::encode(*nsk));
        println!("VSK: {}", hex::encode(*vsk));
        Ok(SubcommandReturnValue::Empty)
    }
}

impl WalletSubcommand for KeycardSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::Available => Ok(Self::handle_available(wallet_core)),
            Self::Connect => Self::handle_connect(wallet_core),
            Self::Init => Self::handle_init(wallet_core),
            Self::Load => Self::handle_load(wallet_core),
            Self::FactoryReset { confirm } => Self::handle_factory_reset(confirm, wallet_core),
            #[cfg(feature = "keycard-debug")]
            Self::GetPrivateKeys { key_path, reveal } => {
                Self::handle_get_private_keys(&key_path, reveal, wallet_core)
            }
        }
    }
}
