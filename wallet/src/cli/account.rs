use anyhow::Result;
use clap::Subcommand;
use itertools::Itertools as _;
use key_protocol::key_management::key_tree::chain_index::ChainIndex;
use nssa::{Account, PublicKey, program::Program};
use token_core::{TokenDefinition, TokenHolding};

use crate::{
    WalletCore,
    cli::{SubcommandReturnValue, WalletSubcommand},
    config::Label,
    helperfunctions::{AccountPrivacyKind, HumanReadableAccount, parse_addr_with_privacy_prefix},
};

/// Represents generic chain CLI subcommand
#[derive(Subcommand, Debug, Clone)]
pub enum AccountSubcommand {
    /// Get account data
    Get {
        /// Flag to get raw account data
        #[arg(short, long)]
        raw: bool,
        /// Display keys (pk for public accounts, npk/vpk for private accounts)
        #[arg(short, long)]
        keys: bool,
        /// Valid 32 byte base58 string with privacy prefix
        #[arg(short, long)]
        account_id: String,
    },
    /// Produce new public or private account
    #[command(subcommand)]
    New(NewSubcommand),
    /// Sync private accounts
    SyncPrivate {},
    /// List all accounts owned by the wallet
    #[command(visible_alias = "ls")]
    List {
        /// Show detailed account information (like `account get`)
        #[arg(short, long)]
        long: bool,
    },
    /// Set a label for an account
    Label {
        /// Valid 32 byte base58 string with privacy prefix
        #[arg(short, long)]
        account_id: String,
        /// The label to assign to the account
        #[arg(short, long)]
        label: String,
    },
}

/// Represents generic register CLI subcommand
#[derive(Subcommand, Debug, Clone)]
pub enum NewSubcommand {
    /// Register new public account
    Public {
        #[arg(long)]
        /// Chain index of a parent node
        cci: Option<ChainIndex>,
        #[arg(short, long)]
        /// Label to assign to the new account
        label: Option<String>,
    },
    /// Register new private account
    Private {
        #[arg(long)]
        /// Chain index of a parent node
        cci: Option<ChainIndex>,
        #[arg(short, long)]
        /// Label to assign to the new account
        label: Option<String>,
    },
}

impl WalletSubcommand for NewSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            NewSubcommand::Public { cci, label } => {
                if let Some(ref label) = label
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
            NewSubcommand::Private { cci, label } => {
                if let Some(ref label) = label
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
                println!("With npk {}", hex::encode(key.nullifer_public_key.0));
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

/// Formats account details for display, returning (description, json_view)
fn format_account_details(account: &Account) -> (String, String) {
    let auth_tr_prog_id = Program::authenticated_transfer_program().id();
    let token_prog_id = Program::token().id();

    match &account.program_owner {
        o if *o == auth_tr_prog_id => {
            let account_hr: HumanReadableAccount = account.clone().into();
            (
                "Account owned by authenticated transfer program".to_string(),
                serde_json::to_string(&account_hr).unwrap(),
            )
        }
        o if *o == token_prog_id => {
            if let Ok(token_def) = TokenDefinition::try_from(&account.data) {
                (
                    "Definition account owned by token program".to_string(),
                    serde_json::to_string(&token_def).unwrap(),
                )
            } else if let Ok(token_hold) = TokenHolding::try_from(&account.data) {
                (
                    "Holding account owned by token program".to_string(),
                    serde_json::to_string(&token_hold).unwrap(),
                )
            } else {
                let account_hr: HumanReadableAccount = account.clone().into();
                (
                    "Unknown token program account".to_string(),
                    serde_json::to_string(&account_hr).unwrap(),
                )
            }
        }
        _ => {
            let account_hr: HumanReadableAccount = account.clone().into();
            (
                "Account".to_string(),
                serde_json::to_string(&account_hr).unwrap(),
            )
        }
    }
}

impl WalletSubcommand for AccountSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            AccountSubcommand::Get {
                raw,
                keys,
                account_id,
            } => {
                let (account_id_str, addr_kind) = parse_addr_with_privacy_prefix(&account_id)?;

                let account_id: nssa::AccountId = account_id_str.parse()?;

                if let Some(label) = wallet_core.storage.labels.get(&account_id_str) {
                    println!("Label: {label}");
                }

                let account = match addr_kind {
                    AccountPrivacyKind::Public => {
                        wallet_core.get_account_public(account_id).await?
                    }
                    AccountPrivacyKind::Private => wallet_core
                        .get_account_private(account_id)
                        .ok_or(anyhow::anyhow!("Private account not found in storage"))?,
                };

                // Helper closure to display keys for the account
                let display_keys = |wallet_core: &WalletCore| -> Result<()> {
                    match addr_kind {
                        AccountPrivacyKind::Public => {
                            let private_key = wallet_core
                                .storage
                                .user_data
                                .get_pub_account_signing_key(account_id)
                                .ok_or(anyhow::anyhow!("Public account not found in storage"))?;

                            let public_key = PublicKey::new_from_private_key(private_key);
                            println!("pk {}", hex::encode(public_key.value()));
                        }
                        AccountPrivacyKind::Private => {
                            let (key, _) = wallet_core
                                .storage
                                .user_data
                                .get_private_account(account_id)
                                .ok_or(anyhow::anyhow!("Private account not found in storage"))?;

                            println!("npk {}", hex::encode(key.nullifer_public_key.0));
                            println!("vpk {}", hex::encode(key.viewing_public_key.to_bytes()));
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
                    let account_hr: HumanReadableAccount = account.clone().into();
                    println!("{}", serde_json::to_string(&account_hr).unwrap());

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
            AccountSubcommand::New(new_subcommand) => {
                new_subcommand.handle_subcommand(wallet_core).await
            }
            AccountSubcommand::SyncPrivate {} => {
                let curr_last_block = wallet_core
                    .sequencer_client
                    .get_last_block()
                    .await?
                    .last_block;

                if wallet_core
                    .storage
                    .user_data
                    .private_key_tree
                    .account_id_map
                    .is_empty()
                {
                    wallet_core.last_synced_block = curr_last_block;

                    wallet_core.store_persistent_data().await?;
                } else {
                    wallet_core.sync_to_block(curr_last_block).await?;
                }

                Ok(SubcommandReturnValue::SyncedToBlock(curr_last_block))
            }
            AccountSubcommand::List { long } => {
                let user_data = &wallet_core.storage.user_data;
                let labels = &wallet_core.storage.labels;

                let format_with_label = |prefix: &str, id: nssa::AccountId| {
                    let id_str = id.to_string();
                    if let Some(label) = labels.get(&id_str) {
                        format!("{prefix} [{label}]")
                    } else {
                        prefix.to_string()
                    }
                };

                if !long {
                    let accounts =
                        user_data
                            .default_pub_account_signing_keys
                            .keys()
                            .copied()
                            .map(|id| format_with_label(&format!("Preconfigured Public/{id}"), id))
                            .chain(user_data.default_user_private_accounts.keys().copied().map(
                                |id| format_with_label(&format!("Preconfigured Private/{id}"), id),
                            ))
                            .chain(user_data.public_key_tree.account_id_map.iter().map(
                                |(id, chain_index)| {
                                    format_with_label(&format!("{chain_index} Public/{id}"), *id)
                                },
                            ))
                            .chain(user_data.private_key_tree.account_id_map.iter().map(
                                |(id, chain_index)| {
                                    format_with_label(&format!("{chain_index} Private/{id}"), *id)
                                },
                            ))
                            .format("\n");

                    println!("{accounts}");
                    return Ok(SubcommandReturnValue::Empty);
                }

                // Detailed listing with --long flag
                // Preconfigured public accounts
                for id in user_data.default_pub_account_signing_keys.keys().copied() {
                    println!(
                        "{}",
                        format_with_label(&format!("Preconfigured Public/{id}"), id)
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

                // Preconfigured private accounts
                for id in user_data.default_user_private_accounts.keys().copied() {
                    println!(
                        "{}",
                        format_with_label(&format!("Preconfigured Private/{id}"), id)
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

                // Public key tree accounts
                for (id, chain_index) in user_data.public_key_tree.account_id_map.iter() {
                    println!(
                        "{}",
                        format_with_label(&format!("{chain_index} Public/{id}"), *id)
                    );
                    match wallet_core.get_account_public(*id).await {
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
                for (id, chain_index) in user_data.private_key_tree.account_id_map.iter() {
                    println!(
                        "{}",
                        format_with_label(&format!("{chain_index} Private/{id}"), *id)
                    );
                    match wallet_core.get_account_private(*id) {
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
            AccountSubcommand::Label { account_id, label } => {
                let (account_id_str, _) = parse_addr_with_privacy_prefix(&account_id)?;

                // Check if label is already used by a different account
                if let Some(existing_account) = wallet_core
                    .storage
                    .labels
                    .iter()
                    .find(|(_, l)| l.to_string() == label)
                    .map(|(a, _)| a.clone())
                    && existing_account != account_id_str
                {
                    anyhow::bail!(
                        "Label '{label}' is already in use by account {existing_account}"
                    );
                }

                let old_label = wallet_core
                    .storage
                    .labels
                    .insert(account_id_str.clone(), Label::new(label.clone()));

                wallet_core.store_persistent_data().await?;

                if let Some(old) = old_label {
                    eprintln!("Warning: overriding existing label '{old}'");
                }
                println!("Label '{label}' set for account {account_id_str}");

                Ok(SubcommandReturnValue::Empty)
            }
        }
    }
}
