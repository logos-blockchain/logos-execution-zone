use anyhow::Result;
use clap::Subcommand;
use keycard_wallet::{KeycardWallet, python_path};
use pyo3::prelude::*;

use crate::{
    WalletCore,
    cli::{SubcommandReturnValue, WalletSubcommand, read_pin},
};

/// Represents generic chain CLI subcommand.
#[derive(Subcommand, Debug, Clone)]
pub enum KeycardSubcommand {
    Available,
    Load {
        #[arg(short, long)]
        mnemonic: Option<String>,
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
            Self::Load { mnemonic } => {
                let pin = read_pin()?;

                Python::with_gil(|py| {
                    python_path::add_python_path(py).expect("keycard_wallet.py not found");

                    let wallet = KeycardWallet::new(py)
                        .expect("`wallet::keycard::load`: invalid keycard wallet provided");

                    let is_connected = wallet
                        .setup_communication(py, &pin)
                        .expect("Expect a Boolean.");

                    if is_connected {
                        println!("\u{2705} Keycard is now connected to wallet.");
                    } else {
                        println!("\u{274c} Keycard is not connected to wallet.");
                    }

                    drop(
                        wallet.load_mnemonic(
                            py,
                            &mnemonic.expect(
                                "E`wallet::keycard::load`: invalid data received for mnemonic",
                            ),
                        ),
                    );

                    drop(wallet.disconnect(py));
                });

                Ok(SubcommandReturnValue::Empty)
            }
        }
    }
}
