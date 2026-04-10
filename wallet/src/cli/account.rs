use anyhow::{Context as _, Result};
use clap::Subcommand;
use itertools::Itertools as _;
use key_protocol::key_management::{KeyChain, key_tree::chain_index::ChainIndex};
use nssa::{Account, PublicKey, program::Program};
use nssa_core::Identifier;
use token_core::{TokenDefinition, TokenHolding};

use crate::{
    WalletCore,
    account::{AccountIdWithPrivacy, HumanReadableAccount, Label},
    cli::{CliAccountMention, SubcommandReturnValue, WalletSubcommand},
};

/// Represents generic chain CLI subcommand.
#[derive(Subcommand, Debug, Clone)]
pub enum AccountSubcommand {
    /// Get account data.
    Get {
        /// Flag to get raw account data.
        #[arg(short, long)]
        raw: bool,
        /// Display keys (pk for public accounts, npk/vpk for private accounts).
        #[arg(short, long)]
        keys: bool,
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(short, long)]
        account_id: CliAccountMention,
    },
    /// Produce new public or private account.
    #[command(subcommand)]
    New(NewSubcommand),
    /// Sync private accounts.
    SyncPrivate,
    /// List all accounts owned by the wallet.
    #[command(visible_alias = "ls")]
    List {
        /// Show detailed account information (like `account get`).
        #[arg(short, long)]
        long: bool,
    },
    /// Set a label for an account.
    Label {
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(short, long)]
        account_id: CliAccountMention,
        /// The label to assign to the account.
        #[arg(short, long)]
        label: Label,
    },
    /// Import external account.
    #[command(subcommand)]
    Import(ImportSubcommand),
}

/// Represents generic register CLI subcommand.
#[derive(Subcommand, Debug, Clone)]
pub enum NewSubcommand {
    /// Register new public account.
    Public {
        #[arg(long)]
        /// Chain index of a parent node.
        cci: Option<ChainIndex>,
        #[arg(short, long)]
        /// Label to assign to the new account.
        label: Option<Label>,
    },
    /// Single-account convenience: creates a key node and auto-registers one account with a random
    /// identifier.
    Private {
        #[arg(long)]
        /// Chain index of a parent node.
        cci: Option<ChainIndex>,
        #[arg(short, long)]
        /// Label to assign to the new account.
        label: Option<Label>,
    },
    /// Recommended for receiving from multiple senders: creates a key node (npk + vpk) without
    /// registering any account.
    PrivateAccountsKey {
        #[arg(long)]
        /// Chain index of a parent node.
        cci: Option<ChainIndex>,
    },
}

impl WalletSubcommand for NewSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::Public { cci, label } => {
                if let Some(label) = &label {
                    wallet_core.storage().check_label_availability(label)?;
                }

                let (account_id, chain_index) = wallet_core.create_new_account_public(cci);

                let private_key = wallet_core
                    .storage
                    .key_chain()
                    .pub_account_signing_key(account_id)
                    .unwrap();

                let public_key = PublicKey::new_from_private_key(private_key);

                if let Some(label) = label {
                    wallet_core
                        .storage_mut()
                        .add_label(label, AccountIdWithPrivacy::Public(account_id))?;
                }

                println!(
                    "Generated new account with account_id Public/{account_id} at path {chain_index}"
                );
                println!("With pk {}", hex::encode(public_key.value()));

                wallet_core.store_persistent_data()?;

                Ok(SubcommandReturnValue::RegisterAccount { account_id })
            }
            Self::Private { cci, label } => {
                if let Some(label) = &label {
                    wallet_core.storage().check_label_availability(label)?;
                }

                let (account_id, chain_index) = wallet_core.create_new_account_private(cci);

                if let Some(label) = label {
                    wallet_core
                        .storage_mut()
                        .add_label(label, AccountIdWithPrivacy::Private(account_id))?;
                }

                let found_acc = wallet_core
                    .storage()
                    .key_chain()
                    .private_account(account_id)
                    .expect("Account should exist after creation");
                let key_chain = found_acc.key_chain;

                println!(
                    "Generated new account with account_id Private/{account_id} at path {chain_index}"
                );
                println!("With npk {}", hex::encode(key_chain.nullifier_public_key.0));
                println!(
                    "With vpk {}",
                    hex::encode(key_chain.viewing_public_key.to_bytes())
                );

                wallet_core.store_persistent_data()?;

                Ok(SubcommandReturnValue::RegisterAccount { account_id })
            }
            Self::PrivateAccountsKey { cci } => {
                let chain_index = wallet_core.create_private_accounts_key(cci);
                let key_chain = wallet_core
                    .storage()
                    .key_chain()
                    .private_account_key_chain_by_index(&chain_index)
                    .expect("Key chain should exist after creation");

                println!("Generated new private key node at path {chain_index}");
                println!("With npk {}", hex::encode(key_chain.nullifier_public_key.0));
                println!(
                    "With vpk {}",
                    hex::encode(key_chain.viewing_public_key.to_bytes())
                );

                wallet_core.store_persistent_data()?;

                Ok(SubcommandReturnValue::Empty)
            }
        }
    }
}

impl WalletSubcommand for AccountSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::Get {
                raw,
                keys,
                account_id,
            } => {
                let resolved = account_id.resolve(wallet_core.storage())?;
                wallet_core
                    .storage()
                    .labels_for_account(resolved)
                    .for_each(|label| {
                        println!("Label: {label}");
                    });

                let account = wallet_core.get_account(resolved).await?;

                // Helper closure to display keys for the account
                let display_keys = |wallet_core: &WalletCore| -> Result<()> {
                    match resolved {
                        AccountIdWithPrivacy::Public(account_id) => {
                            let private_key = wallet_core
                                .storage
                                .key_chain()
                                .pub_account_signing_key(account_id)
                                .context("Public account not found in storage")?;

                            let public_key = PublicKey::new_from_private_key(private_key);
                            println!("pk {}", hex::encode(public_key.value()));
                        }
                        AccountIdWithPrivacy::Private(account_id) => {
                            let acc = wallet_core
                                .storage
                                .key_chain()
                                .private_account(account_id)
                                .context("Private account not found in storage")?;

                            println!("npk {}", hex::encode(acc.key_chain.nullifier_public_key.0));
                            println!(
                                "vpk {}",
                                hex::encode(acc.key_chain.viewing_public_key.to_bytes())
                            );
                        }
                    }
                    Ok(())
                };

                if account == Account::default() {
                    println!("Account is Uninitialized");

                    if keys {
                        display_keys(wallet_core)?;
                    }

                    return Ok(SubcommandReturnValue::Empty);
                }

                if raw {
                    let account_hr: HumanReadableAccount = account.into();
                    println!("{account_hr}");

                    return Ok(SubcommandReturnValue::Empty);
                }

                let (description, json_view) = format_account_details(&account);
                println!("{description}");
                println!("{json_view}");

                if keys {
                    display_keys(wallet_core)?;
                }

                Ok(SubcommandReturnValue::Empty)
            }
            Self::New(new_subcommand) => new_subcommand.handle_subcommand(wallet_core).await,
            Self::SyncPrivate => {
                let curr_last_block = wallet_core.sync_to_latest_block().await?;
                Ok(SubcommandReturnValue::SyncedToBlock(curr_last_block))
            }
            Self::List { long } => {
                let key_chain = &wallet_core.storage.key_chain();
                let storage = wallet_core.storage();

                let format_with_label =
                    |id: AccountIdWithPrivacy, chain_index: Option<&ChainIndex>| {
                        let id_str =
                            chain_index.map_or_else(|| id.to_string(), |cci| format!("{cci} {id}"));

                        let labels = storage.labels_for_account(id).format(", ").to_string();
                        if labels.is_empty() {
                            id_str
                        } else {
                            format!("{id_str} [{labels}]")
                        }
                    };

                if !long {
                    let accounts = key_chain
                        .account_ids()
                        .map(|(id, idx)| format_with_label(id, idx))
                        .format("\n");
                    println!("{accounts}");

                    return Ok(SubcommandReturnValue::Empty);
                }

                // Detailed listing with --long flag

                // Public key tree accounts
                for (id, chain_index) in key_chain.public_account_ids() {
                    println!(
                        "{}",
                        format_with_label(AccountIdWithPrivacy::Public(id), chain_index)
                    );
                    match wallet_core.get_account_public(id).await {
                        Ok(account) if account != Account::default() => {
                            let (description, json_view) = format_account_details(&account);
                            println!("  {description}");
                            println!("  {json_view}");
                        }
                        Ok(_) => println!("  Uninitialized"),
                        Err(e) => println!("  Error fetching account: {e}"),
                    }
                }

                // Private key tree accounts
                for (id, chain_index) in key_chain.private_account_ids() {
                    println!(
                        "{}",
                        format_with_label(AccountIdWithPrivacy::Private(id), chain_index)
                    );
                    match wallet_core.get_account_private(id) {
                        Some(account) if account != Account::default() => {
                            let (description, json_view) = format_account_details(&account);
                            println!("  {description}");
                            println!("  {json_view}");
                        }
                        Some(_) => println!("  Uninitialized"),
                        None => println!("  Not found in local storage"),
                    }
                }

                Ok(SubcommandReturnValue::Empty)
            }
            Self::Label { account_id, label } => {
                let account_id = account_id.resolve(wallet_core.storage())?;

                wallet_core
                    .storage_mut()
                    .add_label(label.clone(), account_id)?;

                wallet_core.store_persistent_data()?;

                println!("Label '{label}' set for account {account_id}");

                Ok(SubcommandReturnValue::Empty)
            }
            Self::Import(import_subcommand) => {
                import_subcommand.handle_subcommand(wallet_core).await
            }
        }
    }
}

#[derive(Subcommand, Debug, Clone)]
pub enum ImportSubcommand {
    /// Import a public account signing key.
    Public {
        /// Private key in hex format.
        #[arg(long)]
        private_key: nssa::PrivateKey,
    },
    /// Import a private account keychain and account state.
    Private {
        /// Private account keychain JSON.
        #[arg(long)]
        key_chain_json: String,
        /// Private account state JSON (`HumanReadableAccount`).
        #[arg(long)]
        account_state: HumanReadableAccount,
        /// Chain index.
        #[arg(long)]
        chain_index: Option<ChainIndex>,
        /// Identifier.
        #[arg(long, default_value = "0")]
        identifier: Identifier,
    },
}

impl WalletSubcommand for ImportSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::Public { private_key } => {
                let account_id =
                    nssa::AccountId::from(&nssa::PublicKey::new_from_private_key(&private_key));

                wallet_core
                    .storage_mut()
                    .key_chain_mut()
                    .add_imported_public_account(private_key);

                wallet_core.store_persistent_data()?;

                println!("Imported public account Public/{account_id}");

                Ok(SubcommandReturnValue::Empty)
            }
            Self::Private {
                key_chain_json,
                account_state,
                chain_index,
                identifier,
            } => {
                let key_chain: KeyChain = serde_json::from_str(&key_chain_json)
                    .map_err(|err| anyhow::anyhow!("Invalid key chain JSON: {err}"))?;
                let account = nssa::Account::from(account_state);
                let account_id =
                    nssa::AccountId::from((&key_chain.nullifier_public_key, identifier));

                wallet_core
                    .storage_mut()
                    .key_chain_mut()
                    .add_imported_private_account(key_chain, chain_index, identifier, account);

                wallet_core.store_persistent_data()?;

                println!("Imported private account Private/{account_id}");

                Ok(SubcommandReturnValue::Empty)
            }
        }
    }
}

/// Formats account details for display, returning (description, `json_view`).
fn format_account_details(account: &Account) -> (String, String) {
    let auth_tr_prog_id = Program::authenticated_transfer_program().id();
    let token_prog_id = Program::token().id();

    match &account.program_owner {
        o if *o == auth_tr_prog_id => {
            let account_hr: HumanReadableAccount = account.clone().into();
            (
                "Account owned by authenticated transfer program".to_owned(),
                serde_json::to_string(&account_hr).unwrap(),
            )
        }
        o if *o == token_prog_id => TokenDefinition::try_from(&account.data)
            .map(|token_def| {
                (
                    "Definition account owned by token program".to_owned(),
                    serde_json::to_string(&token_def).unwrap(),
                )
            })
            .or_else(|_| {
                TokenHolding::try_from(&account.data).map(|token_hold| {
                    (
                        "Holding account owned by token program".to_owned(),
                        serde_json::to_string(&token_hold).unwrap(),
                    )
                })
            })
            .unwrap_or_else(|_| {
                let account_hr: HumanReadableAccount = account.clone().into();
                (
                    "Unknown token program account".to_owned(),
                    serde_json::to_string(&account_hr).unwrap(),
                )
            }),
        _ => {
            let account_hr: HumanReadableAccount = account.clone().into();
            (
                "Account".to_owned(),
                serde_json::to_string(&account_hr).unwrap(),
            )
        }
    }
}
