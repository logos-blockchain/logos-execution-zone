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
    Remove,
}

/// Represents generic register CLI subcommand.
/*
#[derive(Subcommand, Debug, Clone)]
pub enum NewSubcommand {
    /// Register new public account.
    Public {
        #[arg(long)]
        /// Chain index of a parent node.
        cci: Option<ChainIndex>,
        #[arg(short, long)]
        /// Label to assign to the new account.
        label: Option<String>,
    },
    /// Register new private account.
    Private {
        #[arg(long)]
        /// Chain index of a parent node.
        cci: Option<ChainIndex>,
        #[arg(short, long)]
        /// Label to assign to the new account.
        label: Option<String>,
    },
}
*/
/*
impl WalletSubcommand for NewSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::Public { cci, label } => {
                if let Some(label) = &label
                    && wallet_core
                        .storage
                        .labels
                        .values()
                        .any(|l| l.to_string() == *label)
                {
                    anyhow::bail!("Label '{label}' is already in use by another account");
                }

                let (account_id, chain_index) = wallet_core.create_new_account_public(cci);

                let private_key = wallet_core
                    .storage
                    .user_data
                    .get_pub_account_signing_key(account_id)
                    .unwrap();

                let public_key = PublicKey::new_from_private_key(private_key);

                if let Some(label) = label {
                    wallet_core
                        .storage
                        .labels
                        .insert(account_id.to_string(), Label::new(label));
                }

                println!(
                    "Generated new account with account_id Public/{account_id} at path {chain_index}"
                );
                println!("With pk {}", hex::encode(public_key.value()));

                wallet_core.store_persistent_data().await?;

                Ok(SubcommandReturnValue::RegisterAccount { account_id })
            }
            Self::Private { cci, label } => {
                if let Some(label) = &label
                    && wallet_core
                        .storage
                        .labels
                        .values()
                        .any(|l| l.to_string() == *label)
                {
                    anyhow::bail!("Label '{label}' is already in use by another account");
                }

                let (account_id, chain_index) = wallet_core.create_new_account_private(cci);

                if let Some(label) = label {
                    wallet_core
                        .storage
                        .labels
                        .insert(account_id.to_string(), Label::new(label));
                }

                let (key, _) = wallet_core
                    .storage
                    .user_data
                    .get_private_account(account_id)
                    .unwrap();

                println!(
                    "Generated new account with account_id Private/{account_id} at path {chain_index}",
                );
                println!("With npk {}", hex::encode(key.nullifier_public_key.0));
                println!(
                    "With vpk {}",
                    hex::encode(key.viewing_public_key.to_bytes())
                );

                wallet_core.store_persistent_data().await?;

                Ok(SubcommandReturnValue::RegisterAccount { account_id })
            }
        }
    }
}
    */

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

                    let _available = wallet.is_unpaired_keycard_available(py);
                });

                Ok(SubcommandReturnValue::Empty)
            },
            Self::Connect { pin } => {
                // TODO This should be persistent.  
                Python::with_gil(|py| {
                    python_path::add_python_path(py).expect("keycard_wallet.py not found");

                    let wallet = KeycardWallet::new(py).expect("Expect keycard wallet");

                    let _ = wallet.setup_communication(py, pin.expect("TODO"));
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
