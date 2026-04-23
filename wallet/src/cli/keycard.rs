use anyhow::Result;
use clap::Subcommand;
use pyo3::prelude::*;

use crate::{
    WalletCore,
    cli::{SubcommandReturnValue, WalletSubcommand, keycard_wallet::KeycardWallet, python_path},
};

/// Represents generic chain CLI subcommand.
#[derive(Subcommand, Debug, Clone)]
pub enum KeycardSubcommand {
    Available,
    Connect {
        #[arg(
            short,
            long,
        )]
        pin: Option<String>,
    },
    Load {
        #[arg(
            short,
            long,
        )]
        mnemonic: Option<String>,
    },
}

impl WalletSubcommand for KeycardSubcommand {
    #[expect(clippy::cognitive_complexity, reason = "TODO: fix later")]
    async fn handle_subcommand(
        self,
        _wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::Available => {
                Python::with_gil(|py| {
                    python_path::add_python_path(py).expect("keycard_wallet.py not found");

                    let wallet = KeycardWallet::new(py).expect("Expect keycard wallet");
                    let available = wallet.is_unpaired_keycard_available(py).expect("Expect a Boolean.");

                    if available {
                        println!("\u{2705} Keycard is available.");
                    } else {
                        println!("\u{274c} Keycard is not available.");
                    }
                });

                Ok(SubcommandReturnValue::Empty)
            },
            Self::Connect { pin } => {
                // TODO This should be persistent.  
                Python::with_gil(|py| {
                    python_path::add_python_path(py).expect("keycard_wallet.py not found");

                    let wallet = KeycardWallet::new(py).expect("Expect keycard wallet");

                    let is_connected = wallet.setup_communication(py, pin.expect("TODO")).expect("Expect a Boolean.");

                    if is_connected {
                        println!("\u{2705} Keycard is now connected to wallet.");
                    } else {
                        println!("\u{274c} Keycard is not connected to wallet.");
                    }
                });             

                Ok(SubcommandReturnValue::Empty) 
            },
            Self::Load { mnemonic } => {
                // TODO This should be persistent.  
                Python::with_gil(|py| {
                    python_path::add_python_path(py).expect("keycard_wallet.py not found");

                    let wallet = KeycardWallet::new(py).expect("Expect keycard wallet");

                    let _ = wallet.load_account_keys(py, &mnemonic.expect("TODO"));
                });             

                Ok(SubcommandReturnValue::Empty) 
            },
            Self::Remove => {
                // TODO This should be persistent.  
                Python::with_gil(|py| {
                    python_path::add_python_path(py).expect("keycard_wallet.py not found");

                    let wallet = KeycardWallet::new(py).expect("Expect keycard wallet");

                    let _ = wallet.remove_account_keys(py);
                });             

                Ok(SubcommandReturnValue::Empty) 
            },
        }
    }
}
