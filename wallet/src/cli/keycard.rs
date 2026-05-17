use anyhow::Result;
use clap::Subcommand;
use keycard_wallet::{KeycardWallet, clear_pairing, python_path};
use pyo3::prelude::*;

use crate::{
    WalletCore,
    cli::{SubcommandReturnValue, WalletSubcommand, read_mnemonic, read_pin},
};

/// Represents generic chain CLI subcommand.
#[derive(Subcommand, Debug, Clone)]
pub enum KeycardSubcommand {
    Available,
    Connect,
    Disconnect,
    Init,
    Load,
    /// Retrieve the private keys (NSK, VSK) for a given BIP-32 key path.
    ///
    /// Prints raw key material to stdout — intended for debugging only.
    /// Requires --reveal to confirm intent.
    GetPrivateKeys {
        /// BIP-32 derivation path, e.g. `m/44'/60'/0'/0/0`.
        #[arg(long)]
        key_path: String,
        /// Confirm that raw NSK and VSK should be disclosed on stdout.
        #[arg(long)]
        reveal: bool,
    },
}

impl WalletSubcommand for KeycardSubcommand {
    async fn handle_subcommand(
        self,
        _wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::Available => {
                Python::with_gil(|py| {
                    python_path::add_python_path(py).expect("keycard_wallet.py not found");

                    let wallet = KeycardWallet::new(py)
                        .expect("`wallet::keycard::available`: invalid data received for pin");
                    let available = wallet.is_unpaired_keycard_available(py).expect(
                        "`wallet::keycard::available`: received invalid data from Keycard wrapper",
                    );

                    if available {
                        println!("\u{2705} Keycard is available.");
                    } else {
                        println!("\u{274c} Keycard is not available.");
                    }
                });

                Ok(SubcommandReturnValue::Empty)
            }
            Self::Connect => {
                let pin = read_pin()?;

                Python::with_gil(|py| {
                    python_path::add_python_path(py).expect("keycard_wallet.py not found");

                    let wallet = KeycardWallet::new(py)
                        .expect("`wallet::keycard::connect`: invalid keycard wallet provided");

                    wallet
                        .connect(py, &pin)
                        .expect("`wallet::keycard::connect`: failed to connect to keycard");

                    println!("\u{2705} Keycard paired and ready.");
                    drop(wallet.close_session(py));
                });

                Ok(SubcommandReturnValue::Empty)
            }
            Self::Disconnect => {
                let pin = read_pin()?;

                Python::with_gil(|py| {
                    python_path::add_python_path(py).expect("keycard_wallet.py not found");

                    let wallet = KeycardWallet::new(py)
                        .expect("`wallet::keycard::disconnect`: invalid keycard wallet provided");

                    wallet
                        .connect(py, &pin)
                        .expect("`wallet::keycard::disconnect`: failed to open session");

                    wallet
                        .disconnect(py)
                        .expect("`wallet::keycard::disconnect`: failed to unpair keycard");

                    clear_pairing();
                    println!("\u{2705} Keycard unpaired and pairing cleared.");
                });

                Ok(SubcommandReturnValue::Empty)
            }
            Self::Init => {
                let pin = read_pin()?;

                Python::with_gil(|py| {
                    python_path::add_python_path(py).expect("keycard_wallet.py not found");

                    let wallet = KeycardWallet::new(py)
                        .expect("`wallet::keycard::init`: invalid keycard wallet provided");

                    let initialized = wallet
                        .initialize(py, &pin)
                        .expect("`wallet::keycard::init`: failed to initialize keycard");

                    if initialized {
                        clear_pairing();
                        println!("\u{2705} Keycard initialized successfully.");
                    }
                });

                Ok(SubcommandReturnValue::Empty)
            }
            Self::Load => {
                let pin = read_pin()?;
                let mnemonic = read_mnemonic()?;

                Python::with_gil(|py| {
                    python_path::add_python_path(py).expect("keycard_wallet.py not found");

                    let wallet = KeycardWallet::new(py)
                        .expect("`wallet::keycard::load`: invalid keycard wallet provided");

                    wallet
                        .connect(py, &pin)
                        .expect("`wallet::keycard::load`: failed to connect to keycard");

                    println!("\u{2705} Keycard is now connected to wallet.");
                    if wallet.load_mnemonic(py, &mnemonic).is_ok() {
                        println!("\u{2705} Mnemonic phrase loaded successfully.");
                    } else {
                        println!("\u{274c} Failed to load mnemonic phrase.");
                    }
                    drop(wallet.close_session(py));
                });

                Ok(SubcommandReturnValue::Empty)
            }
            Self::GetPrivateKeys { key_path, reveal } => {
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
                let (nsk, vsk) =
                    KeycardWallet::get_private_keys_for_path_with_connect(&pin, &key_path)
                        .map_err(anyhow::Error::from)?;
                println!("NSK: {}", hex::encode(*nsk));
                println!("VSK: {}", hex::encode(*vsk));
                Ok(SubcommandReturnValue::Empty)
            }
        }
    }
}
