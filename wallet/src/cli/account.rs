use anyhow::{Context as _, Result};
use clap::Subcommand;
use itertools::Itertools as _;
use key_protocol::key_management::key_tree::chain_index::ChainIndex;
use nssa::{Account, PublicKey, program::Program};
use sequencer_service_rpc::RpcClient as _;
use token_core::{TokenDefinition, TokenHolding};

use crate::{
    WalletCore,
    cli::{SubcommandReturnValue, WalletSubcommand},
    config::Label,
    helperfunctions::{
        AccountPrivacyKind, HumanReadableAccount, parse_addr_with_privacy_prefix,
        resolve_id_or_label,
    },
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
        /// Valid 32 byte base58 string with privacy prefix.
        #[arg(
            short,
            long,
            conflicts_with = "account_label",
            required_unless_present = "account_label"
        )]
        account_id: Option<String>,
        /// Account label (alternative to --account-id).
        #[arg(long, conflicts_with = "account_id")]
        account_label: Option<String>,
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
        /// Valid 32 byte base58 string with privacy prefix.
        #[arg(
            short,
            long,
            conflicts_with = "account_label",
            required_unless_present = "account_label"
        )]
        account_id: Option<String>,
        /// Account label (alternative to --account-id).
        #[arg(long = "account-label", conflicts_with = "account_id")]
        account_label: Option<String>,
        /// The label to assign to the account.
        #[arg(short, long)]
        label: String,
    },
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
        label: Option<String>,
    },
    /// Single-account convenience: creates a key node and auto-registers one account with a random
    /// identifier. When `--for-gms` is provided, derives keys from the named group instead of
    /// the wallet's key tree.
    Private {
        #[arg(long)]
        /// Chain index of a parent node (ignored when --for-gms is used).
        cci: Option<ChainIndex>,
        #[arg(short, long)]
        /// Label to assign to the new account.
        label: Option<String>,
        #[arg(long)]
        /// Derive keys from a group's GMS instead of the wallet tree.
        for_gms: Option<String>,
        #[arg(long, requires = "for_gms")]
        /// Create a PDA account (requires --seed and --program-id).
        pda: bool,
        #[arg(long, requires = "pda")]
        /// PDA seed as 64-character hex string.
        seed: Option<String>,
        #[arg(long, requires = "pda")]
        /// Program ID as hex string.
        program_id: Option<String>,
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
            Self::Private {
                cci,
                label,
                for_gms,
                pda,
                seed,
                program_id,
            } => {
                if let Some(label) = &label
                    && wallet_core
                        .storage
                        .labels
                        .values()
                        .any(|l| l.to_string() == *label)
                {
                    anyhow::bail!("Label '{label}' is already in use by another account");
                }

                if let Some(group_name) = for_gms {
                    // GMS-derived account
                    let holder = wallet_core
                        .storage()
                        .user_data
                        .group_key_holder(&group_name)
                        .context(format!("Group '{group_name}' not found"))?;

                    if pda {
                        // PDA shared account
                        let seed_hex = seed.context("--seed is required for PDA accounts")?;
                        let pid_hex =
                            program_id.context("--program-id is required for PDA accounts")?;

                        let seed_bytes: [u8; 32] = hex::decode(&seed_hex)
                            .context("Invalid seed hex")?
                            .try_into()
                            .map_err(|_err| anyhow::anyhow!("Seed must be exactly 32 bytes"))?;
                        let pda_seed = nssa_core::program::PdaSeed::new(seed_bytes);

                        let pid_bytes = hex::decode(&pid_hex).context("Invalid program ID hex")?;
                        if pid_bytes.len() != 32 {
                            anyhow::bail!("Program ID must be exactly 32 bytes");
                        }
                        let mut pid: nssa_core::program::ProgramId = [0; 8];
                        for (i, chunk) in pid_bytes.chunks_exact(4).enumerate() {
                            pid[i] = u32::from_le_bytes(chunk.try_into().unwrap());
                        }

                        let keys = holder.derive_keys_for_pda(&pda_seed);
                        let npk = keys.generate_nullifier_public_key();
                        let vpk = keys.generate_viewing_public_key();
                        let account_id = nssa::AccountId::for_private_pda(&pid, &pda_seed, &npk);

                        if let Some(label) = label {
                            wallet_core
                                .storage
                                .labels
                                .insert(account_id.to_string(), Label::new(label));
                        }

                        wallet_core.register_shared_account(
                            account_id,
                            group_name.clone(),
                            u128::MAX,
                        );

                        println!("PDA shared account from group '{group_name}'");
                        println!("AccountId: {account_id}");
                        println!("NPK: {}", hex::encode(npk.0));
                        println!("VPK: {}", hex::encode(&vpk.0));

                        wallet_core.store_persistent_data().await?;
                        Ok(SubcommandReturnValue::RegisterAccount { account_id })
                    } else {
                        // Regular shared account. The tag is derived deterministically
                        // from the identifier so that keys can be re-derived without
                        // storing the tag separately.
                        let identifier: nssa_core::Identifier = rand::random();
                        let tag = {
                            use sha2::Digest as _;
                            let mut hasher = sha2::Sha256::new();
                            hasher.update(b"/LEE/v0.3/SharedAccountTag/\x00\x00\x00\x00\x00");
                            hasher.update(identifier.to_le_bytes());
                            let result: [u8; 32] = hasher.finalize().into();
                            result
                        };

                        let keys = holder.derive_keys_for_shared_account(&tag);
                        let npk = keys.generate_nullifier_public_key();
                        let vpk = keys.generate_viewing_public_key();
                        let account_id = nssa::AccountId::from((&npk, identifier));

                        if let Some(label) = label {
                            wallet_core
                                .storage
                                .labels
                                .insert(account_id.to_string(), Label::new(label));
                        }

                        wallet_core.register_shared_account(
                            account_id,
                            group_name.clone(),
                            identifier,
                        );

                        println!("Shared account from group '{group_name}'");
                        println!("AccountId: Private/{account_id}");
                        println!("NPK: {}", hex::encode(npk.0));
                        println!("VPK: {}", hex::encode(&vpk.0));

                        wallet_core.store_persistent_data().await?;
                        Ok(SubcommandReturnValue::RegisterAccount { account_id })
                    }
                } else {
                    // Standard wallet-tree-derived account
                    let (account_id, chain_index) = wallet_core.create_new_account_private(cci);

                    let node = wallet_core
                        .storage
                        .user_data
                        .private_key_tree
                        .key_map
                        .get(&chain_index)
                        .expect("Node was just inserted");
                    let key = &node.value.0;

                    if let Some(label) = label {
                        wallet_core
                            .storage
                            .labels
                            .insert(account_id.to_string(), Label::new(label));
                    }

                    println!(
                        "Generated new account with account_id Private/{account_id} at path {chain_index}"
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
            Self::PrivateAccountsKey { cci } => {
                let chain_index = wallet_core.create_private_accounts_key(cci);

                let node = wallet_core
                    .storage
                    .user_data
                    .private_key_tree
                    .key_map
                    .get(&chain_index)
                    .expect("Node was just inserted");
                let key = &node.value.0;

                println!("Generated new private key node at path {chain_index}");
                println!("With npk {}", hex::encode(key.nullifier_public_key.0));
                println!(
                    "With vpk {}",
                    hex::encode(key.viewing_public_key.to_bytes())
                );

                wallet_core.store_persistent_data().await?;

                Ok(SubcommandReturnValue::Empty)
            }
        }
    }
}

impl WalletSubcommand for AccountSubcommand {
    #[expect(clippy::cognitive_complexity, reason = "TODO: fix later")]
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::Get {
                raw,
                keys,
                account_id,
                account_label,
            } => {
                let resolved = resolve_id_or_label(
                    account_id,
                    account_label,
                    &wallet_core.storage.labels,
                    &wallet_core.storage.user_data,
                )?;
                let (account_id_str, addr_kind) = parse_addr_with_privacy_prefix(&resolved)?;

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
                        .context("Private account not found in storage")?,
                };

                // Helper closure to display keys for the account
                let display_keys = |wallet_core: &WalletCore| -> Result<()> {
                    match addr_kind {
                        AccountPrivacyKind::Public => {
                            let private_key = wallet_core
                                .storage
                                .user_data
                                .get_pub_account_signing_key(account_id)
                                .context("Public account not found in storage")?;

                            let public_key = PublicKey::new_from_private_key(private_key);
                            println!("pk {}", hex::encode(public_key.value()));
                        }
                        AccountPrivacyKind::Private => {
                            let (key, _, _) = wallet_core
                                .storage
                                .user_data
                                .get_private_account(account_id)
                                .context("Private account not found in storage")?;

                            println!("npk {}", hex::encode(key.nullifier_public_key.0));
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
                    let account_hr: HumanReadableAccount = account.into();
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
            Self::New(new_subcommand) => new_subcommand.handle_subcommand(wallet_core).await,
            Self::SyncPrivate => {
                let curr_last_block = wallet_core.sequencer_client.get_last_block_id().await?;
                wallet_core.sync_to_block(curr_last_block).await?;
                Ok(SubcommandReturnValue::SyncedToBlock(curr_last_block))
            }
            Self::List { long } => {
                let user_data = &wallet_core.storage.user_data;
                let labels = &wallet_core.storage.labels;

                let format_with_label = |prefix: &str, id: nssa::AccountId| {
                    let id_str = id.to_string();
                    labels
                        .get(&id_str)
                        .map_or_else(|| prefix.to_owned(), |label| format!("{prefix} [{label}]"))
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
                for (id, chain_index) in &user_data.public_key_tree.account_id_map {
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
                for (id, chain_index) in &user_data.private_key_tree.account_id_map {
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
            Self::Label {
                account_id,
                account_label,
                label,
            } => {
                let resolved = resolve_id_or_label(
                    account_id,
                    account_label,
                    &wallet_core.storage.labels,
                    &wallet_core.storage.user_data,
                )?;
                let (account_id_str, _) = parse_addr_with_privacy_prefix(&resolved)?;

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
