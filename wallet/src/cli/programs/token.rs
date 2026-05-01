use anyhow::Result;
use clap::Subcommand;
use common::transaction::NSSATransaction;
use nssa::AccountId;

use crate::{
    AccDecodeData::Decode,
    PrivacyPreservingAccount,
    WalletCore,
    cli::{SubcommandReturnValue, WalletSubcommand},
    helperfunctions::{
        AccountPrivacyKind, parse_addr_with_privacy_prefix, resolve_account_label,
        resolve_id_or_label, resolve_keycard_id,
    },
    program_facades::token::Token,
};

/// Represents generic CLI subcommand for a wallet working with token program.
#[derive(Subcommand, Debug, Clone)]
pub enum TokenProgramAgnosticSubcommand {
    /// Produce a new token.
    New {
        /// `definition_account_id` - valid 32 byte base58 string with privacy prefix.
        #[arg(
            long,
            conflicts_with = "definition_account_label",
            conflicts_with = "definition_key_path",
            required_unless_present_any = ["definition_account_label", "definition_key_path"]
        )]
        definition_account_id: Option<String>,
        /// Definition account label (alternative to --definition-account-id).
        #[arg(long, conflicts_with = "definition_account_id", conflicts_with = "definition_key_path")]
        definition_account_label: Option<String>,
        /// Key path for the definition account (uses Keycard).
        #[arg(long, conflicts_with = "definition_account_id", conflicts_with = "definition_account_label")]
        definition_key_path: Option<String>,
        /// `supply_account_id` - valid 32 byte base58 string with privacy prefix.
        #[arg(
            long,
            conflicts_with = "supply_account_label",
            conflicts_with = "supply_key_path",
            required_unless_present_any = ["supply_account_label", "supply_key_path"]
        )]
        supply_account_id: Option<String>,
        /// Supply account label (alternative to --supply-account-id).
        #[arg(long, conflicts_with = "supply_account_id", conflicts_with = "supply_key_path")]
        supply_account_label: Option<String>,
        /// Key path for the supply account (uses Keycard).
        #[arg(long, conflicts_with = "supply_account_id", conflicts_with = "supply_account_label")]
        supply_key_path: Option<String>,
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        total_supply: u128,
    },
    /// Initialize a token holding account for a given token definition.
    Init {
        /// `definition_account_id` - valid 32 byte base58 string with privacy prefix.
        #[arg(
            long,
            conflicts_with = "definition_account_label",
            required_unless_present = "definition_account_label"
        )]
        definition_account_id: Option<String>,
        /// Definition account label (alternative to --definition-account-id).
        #[arg(long, conflicts_with = "definition_account_id")]
        definition_account_label: Option<String>,
        /// `holder_account_id` - valid 32 byte base58 string with privacy prefix.
        #[arg(
            long,
            conflicts_with = "holder_account_label",
            required_unless_present_any = ["holder_account_label", "holder_key_path"]
        )]
        holder_account_id: Option<String>,
        /// Holder account label (alternative to --holder-account-id).
        #[arg(long, conflicts_with = "holder_account_id")]
        holder_account_label: Option<String>,
        /// `holder_key_path` (alternative to --holder-account-id) uses Keycard.
        #[arg(
            long,
            conflicts_with = "holder_account_id",
            conflicts_with = "holder_account_label"
        )]
        holder_key_path: Option<String>,
    },
    /// Send tokens from one account to another with variable privacy.
    ///
    /// If receiver is private, then `to` and (`to_npk` , `to_vpk`) is a mutually exclusive
    /// patterns.
    ///
    /// First is used for owned accounts, second otherwise.
    Send {
        /// from - valid 32 byte base58 string with privacy prefix.
        #[arg(
            long,
            conflicts_with = "from_label",
            conflicts_with = "from_key_path",
            required_unless_present_any = ["from_label", "from_key_path"]
        )]
        from: Option<String>,
        /// From account label (alternative to --from).
        #[arg(long, conflicts_with = "from", conflicts_with = "from_key_path")]
        from_label: Option<String>,
        /// to - valid 32 byte base58 string with privacy prefix.
        #[arg(long, conflicts_with = "to_label")]
        to: Option<String>,
        /// To account label (alternative to --to).
        #[arg(long, conflicts_with = "to")]
        to_label: Option<String>,
        /// `to_npk` - valid 32 byte hex string.
        #[arg(long)]
        to_npk: Option<String>,
        /// `to_vpk` - valid 33 byte hex string.
        #[arg(long)]
        to_vpk: Option<String>,
        /// Identifier for the recipient's private account (only used when sending to a foreign
        /// private account via `--to-npk`/`--to-vpk`).
        #[arg(long)]
        to_identifier: Option<u128>,
        /// amount - amount of balance to move.
        #[arg(long)]
        amount: u128,
        /// `from_key_path` (alternative to --from) uses Keycard.
        #[arg(long, conflicts_with = "from", conflicts_with = "from", conflicts_with = "from_label")]
        from_key_path: Option<String>,
        /// `to_key_path` (alternative to --to) uses Keycard.
        #[arg(long, conflicts_with = "to", conflicts_with = "to", conflicts_with = "to_label")]
        to_key_path: Option<String>,
    },
    /// Burn tokens on `holder`, modify `definition`.
    ///
    /// `holder` is owned.
    ///
    /// Also if `definition` is private then it is owned, because
    /// we can not modify foreign accounts.
    Burn {
        /// definition - valid 32 byte base58 string with privacy prefix.
        #[arg(
            long,
            conflicts_with = "definition_label",
            required_unless_present = "definition_label"
        )]
        definition: Option<String>,
        /// Definition account label (alternative to --definition).
        #[arg(long, conflicts_with = "definition")]
        definition_label: Option<String>,
        /// holder - valid 32 byte base58 string with privacy prefix.
        #[arg(long, conflicts_with = "holder_label")]
        holder: Option<String>,
        /// Holder account label (alternative to --holder).
        #[arg(long, conflicts_with = "holder")]
        holder_label: Option<String>,
        /// amount - amount of balance to burn.
        #[arg(long)]
        amount: u128,
        #[arg(long, conflicts_with = "holder", conflicts_with = "holder_label")]
        holder_key_path: Option<String>,
    },
    /// Mint tokens on `holder`, modify `definition`.
    ///
    /// `definition` is owned.
    ///
    /// If `holder` is private, then `holder` and (`holder_npk` , `holder_vpk`) is a mutually
    /// exclusive patterns.
    ///
    /// First is used for owned accounts, second otherwise.
    Mint {
        /// definition - valid 32 byte base58 string with privacy prefix.
        #[arg(
            long,
            conflicts_with = "definition_label",
            conflicts_with = "definition_key_path",
            required_unless_present_any = ["definition_label", "definition_key_path"]
        )]
        definition: Option<String>,
        /// Definition account label (alternative to --definition).
        #[arg(long, conflicts_with = "definition", conflicts_with = "definition_key_path")]
        definition_label: Option<String>,
        /// Key path for the definition account (uses Keycard).
        #[arg(long, conflicts_with = "definition", conflicts_with = "definition_label")]
        definition_key_path: Option<String>,
        /// holder - valid 32 byte base58 string with privacy prefix.
        #[arg(long, conflicts_with = "holder_label", conflicts_with = "holder_key_path", required_unless_present_any = ["holder_label", "holder_key_path"])]
        holder: Option<String>,
        /// Holder account label (alternative to --holder).
        #[arg(long, conflicts_with = "holder", conflicts_with = "holder_key_path")]
        holder_label: Option<String>,
        /// Key path for the holder account (uses Keycard, for account ID resolution only).
        #[arg(long, conflicts_with = "holder", conflicts_with = "holder_label")]
        holder_key_path: Option<String>,
        /// `holder_npk` - valid 32 byte hex string.
        #[arg(long)]
        holder_npk: Option<String>,
        /// `to_vpk` - valid 33 byte hex string.
        #[arg(long)]
        holder_vpk: Option<String>,
        /// Identifier for the holder's private account (only used when minting to a foreign
        /// private account via `--holder-npk`/`--holder-vpk`).
        #[arg(long)]
        holder_identifier: Option<u128>,
        /// amount - amount of balance to mint.
        #[arg(long)]
        amount: u128,
    },
}

impl WalletSubcommand for TokenProgramAgnosticSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::Init {
                definition_account_id,
                definition_account_label,
                holder_account_id,
                holder_account_label,
                holder_key_path,
            } => {
                let definition_str = resolve_id_or_label(
                    definition_account_id,
                    definition_account_label,
                    &wallet_core.storage.labels,
                    &wallet_core.storage.user_data,
                    None,
                )?;
                let holder_str = resolve_id_or_label(
                    holder_account_id,
                    holder_account_label,
                    &wallet_core.storage.labels,
                    &wallet_core.storage.user_data,
                    holder_key_path.as_deref(),
                )?;

                let (definition_id, definition_privacy) =
                    parse_addr_with_privacy_prefix(&definition_str)?;
                let (holder_id, holder_privacy) = parse_addr_with_privacy_prefix(&holder_str)?;

                let definition_account_id: AccountId = definition_id.parse()?;
                let holder_account_id: AccountId = holder_id.parse()?;

                // Skip if the holder is already initialised — prevents a ZK-prove panic when
                // the account already has token data (e.g. on re-runs against the same chain).
                let already_initialized = match holder_privacy {
                    AccountPrivacyKind::Public => {
                        let account = wallet_core.get_account_public(holder_account_id).await?;
                        account != nssa::Account::default()
                    }
                    AccountPrivacyKind::Private => wallet_core
                        .storage
                        .user_data
                        .get_private_account(holder_account_id)
                        .is_some_and(|(_, acct, _)| acct != nssa::Account::default()),
                };
                if already_initialized {
                    println!(
                        "Holder {holder_id} is already initialized as a token holding. Skipping."
                    );
                    return Ok(SubcommandReturnValue::Empty);
                }

                let definition_account = match definition_privacy {
                    AccountPrivacyKind::Public => {
                        PrivacyPreservingAccount::Public(definition_account_id)
                    }
                    AccountPrivacyKind::Private => {
                        PrivacyPreservingAccount::PrivateOwned(definition_account_id)
                    }
                };
                let holder_account = match holder_privacy {
                    AccountPrivacyKind::Public => {
                        PrivacyPreservingAccount::Public(holder_account_id)
                    }
                    AccountPrivacyKind::Private => {
                        PrivacyPreservingAccount::PrivateOwned(holder_account_id)
                    }
                };

                let (tx_hash, secrets) = Token(wallet_core)
                    .send_initialize_account(definition_account, holder_account, &holder_key_path)
                    .await?;

                println!("Transaction hash is {tx_hash}");

                if secrets.is_empty() {
                    return Ok(SubcommandReturnValue::Empty);
                }

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let NSSATransaction::PrivacyPreserving(tx) = transfer_tx {
                    let mut secrets_iter = secrets.into_iter();
                    let mut acc_decode_data = Vec::new();

                    if matches!(definition_privacy, AccountPrivacyKind::Private) {
                        acc_decode_data.push(Decode(
                            secrets_iter.next().expect("expected definition's secret"),
                            definition_account_id,
                        ));
                    }
                    if matches!(holder_privacy, AccountPrivacyKind::Private) {
                        acc_decode_data.push(Decode(
                            secrets_iter.next().expect("expected holder's secret"),
                            holder_account_id,
                        ));
                    }

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data().await?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::New {
                definition_account_id,
                definition_account_label,
                definition_key_path,
                supply_account_id,
                supply_account_label,
                supply_key_path,
                name,
                total_supply,
            } => {
                let definition_account_id = resolve_id_or_label(
                    definition_account_id,
                    definition_account_label,
                    &wallet_core.storage.labels,
                    &wallet_core.storage.user_data,
                    definition_key_path.as_deref(),
                )?;
                let supply_account_id = resolve_id_or_label(
                    supply_account_id,
                    supply_account_label,
                    &wallet_core.storage.labels,
                    &wallet_core.storage.user_data,
                    supply_key_path.as_deref(),
                )?;
                let (definition_account_id, definition_addr_privacy) =
                    parse_addr_with_privacy_prefix(&definition_account_id)?;
                let (supply_account_id, supply_addr_privacy) =
                    parse_addr_with_privacy_prefix(&supply_account_id)?;

                let underlying_subcommand = match (definition_addr_privacy, supply_addr_privacy) {
                    (AccountPrivacyKind::Public, AccountPrivacyKind::Public) => {
                        TokenProgramSubcommand::Create(
                            CreateNewTokenProgramSubcommand::NewPublicDefPublicSupp {
                                definition_account_id,
                                supply_account_id,
                                name,
                                total_supply,
                                definition_key_path,
                                supply_key_path,
                            },
                        )
                    }
                    (AccountPrivacyKind::Public, AccountPrivacyKind::Private) => {
                        TokenProgramSubcommand::Create(
                            CreateNewTokenProgramSubcommand::NewPublicDefPrivateSupp {
                                definition_account_id,
                                supply_account_id,
                                name,
                                total_supply,
                            },
                        )
                    }
                    (AccountPrivacyKind::Private, AccountPrivacyKind::Private) => {
                        TokenProgramSubcommand::Create(
                            CreateNewTokenProgramSubcommand::NewPrivateDefPrivateSupp {
                                definition_account_id,
                                supply_account_id,
                                name,
                                total_supply,
                            },
                        )
                    }
                    (AccountPrivacyKind::Private, AccountPrivacyKind::Public) => {
                        TokenProgramSubcommand::Create(
                            CreateNewTokenProgramSubcommand::NewPrivateDefPublicSupp {
                                definition_account_id,
                                supply_account_id,
                                name,
                                total_supply,
                            },
                        )
                    }
                };

                underlying_subcommand.handle_subcommand(wallet_core).await
            }
            Self::Send {
                from,
                from_label,
                to,
                to_label,
                to_npk,
                to_vpk,
                to_identifier,
                amount,
                from_key_path,
                to_key_path,
            } => {
                let from = resolve_id_or_label(
                    from,
                    from_label,
                    &wallet_core.storage.labels,
                    &wallet_core.storage.user_data,
                    from_key_path.as_deref(),
                )?;
                let to = match (to, to_label, to_key_path) {
                    (v, None, None) => v,
                    (None, Some(label), None) => Some(resolve_account_label(
                        &label,
                        &wallet_core.storage.labels,
                        &wallet_core.storage.user_data,
                    )?),
                    (None, None, Some(to_key_path)) => {
                        Some(resolve_keycard_id(&to_key_path)?)
                    }
                    _ => {
                        anyhow::bail!("Provide only one of --to or --to-label")
                    }
                };
                let underlying_subcommand = match (to, to_npk, to_vpk) {
                    (None, None, None) => {
                        anyhow::bail!(
                            "Provide either account account_id of receiver or their public keys"
                        );
                    }
                    (Some(_), Some(_), Some(_)) => {
                        anyhow::bail!(
                            "Provide only one variant: either account account_id of receiver or their public keys"
                        );
                    }
                    (_, Some(_), None) | (_, None, Some(_)) => {
                        anyhow::bail!("List of public keys is uncomplete");
                    }
                    (Some(to), None, None) => {
                        let (from, from_privacy) = parse_addr_with_privacy_prefix(&from)?;
                        let (to, to_privacy) = parse_addr_with_privacy_prefix(&to)?;

                        match (from_privacy, to_privacy) {
                            (AccountPrivacyKind::Public, AccountPrivacyKind::Public) => {
                                TokenProgramSubcommand::Public(
                                    TokenProgramSubcommandPublic::TransferToken {
                                        sender_account_id: from,
                                        recipient_account_id: to,
                                        balance_to_move: amount,
                                        sender_key_path: from_key_path,
                                    },
                                )
                            }
                            (AccountPrivacyKind::Private, AccountPrivacyKind::Private) => {
                                TokenProgramSubcommand::Private(
                                    TokenProgramSubcommandPrivate::TransferTokenPrivateOwned {
                                        sender_account_id: from,
                                        recipient_account_id: to,
                                        balance_to_move: amount,
                                    },
                                )
                            }
                            (AccountPrivacyKind::Private, AccountPrivacyKind::Public) => {
                                TokenProgramSubcommand::Deshielded(
                                    TokenProgramSubcommandDeshielded::TransferTokenDeshielded {
                                        sender_account_id: from,
                                        recipient_account_id: to,
                                        balance_to_move: amount,
                                    },
                                )
                            }
                            (AccountPrivacyKind::Public, AccountPrivacyKind::Private) => {
                                TokenProgramSubcommand::Shielded(
                                    TokenProgramSubcommandShielded::TransferTokenShieldedOwned {
                                        sender_account_id: from,
                                        recipient_account_id: to,
                                        balance_to_move: amount,
                                        sender_key_path: from_key_path,
                                    },
                                )
                            }
                        }
                    }
                    (None, Some(to_npk), Some(to_vpk)) => {
                        let (from, from_privacy) = parse_addr_with_privacy_prefix(&from)?;

                        match from_privacy {
                            AccountPrivacyKind::Private => TokenProgramSubcommand::Private(
                                TokenProgramSubcommandPrivate::TransferTokenPrivateForeign {
                                    sender_account_id: from,
                                    recipient_npk: to_npk,
                                    recipient_vpk: to_vpk,
                                    recipient_identifier: to_identifier,
                                    balance_to_move: amount,
                                },
                            ),
                            AccountPrivacyKind::Public => TokenProgramSubcommand::Shielded(
                                TokenProgramSubcommandShielded::TransferTokenShieldedForeign {
                                    sender_account_id: from,
                                    recipient_npk: to_npk,
                                    recipient_vpk: to_vpk,
                                    recipient_identifier: to_identifier,
                                    balance_to_move: amount,
                                },
                            ),
                        }
                    }
                };

                underlying_subcommand.handle_subcommand(wallet_core).await
            }
            Self::Burn {
                definition,
                definition_label,
                holder,
                holder_label,
                amount,
                holder_key_path,
            } => {
                let definition = resolve_id_or_label(
                    definition,
                    definition_label,
                    &wallet_core.storage.labels,
                    &wallet_core.storage.user_data,
                    None,
                )?;
                let holder = resolve_id_or_label(
                    holder,
                    holder_label,
                    &wallet_core.storage.labels,
                    &wallet_core.storage.user_data,
                    holder_key_path.as_deref(),
                )?;
                let underlying_subcommand = {
                    let (definition, definition_privacy) =
                        parse_addr_with_privacy_prefix(&definition)?;
                    let (holder, holder_privacy) = parse_addr_with_privacy_prefix(&holder)?;
                    match (definition_privacy, holder_privacy) {
                        (AccountPrivacyKind::Public, AccountPrivacyKind::Public) => {
                            TokenProgramSubcommand::Public(
                                TokenProgramSubcommandPublic::BurnToken {
                                    definition_account_id: definition,
                                    holder_account_id: holder,
                                    amount,
                                    holder_key_path,
                                },
                            )
                        }
                        (AccountPrivacyKind::Private, AccountPrivacyKind::Private) => {
                            TokenProgramSubcommand::Private(
                                TokenProgramSubcommandPrivate::BurnTokenPrivateOwned {
                                    definition_account_id: definition,
                                    holder_account_id: holder,
                                    amount,
                                },
                            )
                        }
                        (AccountPrivacyKind::Private, AccountPrivacyKind::Public) => {
                            TokenProgramSubcommand::Deshielded(
                                TokenProgramSubcommandDeshielded::BurnTokenDeshieldedOwned {
                                    definition_account_id: definition,
                                    holder_account_id: holder,
                                    amount,
                                },
                            )
                        }
                        (AccountPrivacyKind::Public, AccountPrivacyKind::Private) => {
                            TokenProgramSubcommand::Shielded(
                                TokenProgramSubcommandShielded::BurnTokenShielded {
                                    definition_account_id: definition,
                                    holder_account_id: holder,
                                    amount,
                                },
                            )
                        }
                    }
                };

                underlying_subcommand.handle_subcommand(wallet_core).await
            }
            Self::Mint {
                definition,
                definition_label,
                definition_key_path,
                holder,
                holder_label,
                holder_key_path,
                holder_npk,
                holder_vpk,
                holder_identifier,
                amount,
            } => {
                let definition = resolve_id_or_label(
                    definition,
                    definition_label,
                    &wallet_core.storage.labels,
                    &wallet_core.storage.user_data,
                    definition_key_path.as_deref(),
                )?;
                let holder = match (holder, holder_label, holder_key_path.as_deref()) {
                    (v, None, None) => v,
                    (None, Some(label), None) => Some(resolve_account_label(
                        &label,
                        &wallet_core.storage.labels,
                        &wallet_core.storage.user_data,
                    )?),
                    (None, None, Some(kp)) => Some(resolve_keycard_id(kp)?),
                    _ => {
                        anyhow::bail!("Provide only one of --holder, --holder-label, or --holder-key-path")
                    }
                };
                let underlying_subcommand = match (holder, holder_npk, holder_vpk) {
                    (None, None, None) => {
                        anyhow::bail!(
                            "Provide either account account_id of holder or their public keys"
                        );
                    }
                    (Some(_), Some(_), Some(_)) => {
                        anyhow::bail!(
                            "Provide only one variant: either account_id of holder or their public keys"
                        );
                    }
                    (_, Some(_), None) | (_, None, Some(_)) => {
                        anyhow::bail!("List of public keys is uncomplete");
                    }
                    (Some(holder), None, None) => {
                        let (definition, definition_privacy) =
                            parse_addr_with_privacy_prefix(&definition)?;
                        let (holder, holder_privacy) = parse_addr_with_privacy_prefix(&holder)?;

                        match (definition_privacy, holder_privacy) {
                            (AccountPrivacyKind::Public, AccountPrivacyKind::Public) => {
                                TokenProgramSubcommand::Public(
                                    TokenProgramSubcommandPublic::MintToken {
                                        definition_account_id: definition,
                                        holder_account_id: holder,
                                        amount,
                                        definition_key_path: definition_key_path.clone(),
                                    },
                                )
                            }
                            (AccountPrivacyKind::Private, AccountPrivacyKind::Private) => {
                                TokenProgramSubcommand::Private(
                                    TokenProgramSubcommandPrivate::MintTokenPrivateOwned {
                                        definition_account_id: definition,
                                        holder_account_id: holder,
                                        amount,
                                    },
                                )
                            }
                            (AccountPrivacyKind::Private, AccountPrivacyKind::Public) => {
                                TokenProgramSubcommand::Deshielded(
                                    TokenProgramSubcommandDeshielded::MintTokenDeshielded {
                                        definition_account_id: definition,
                                        holder_account_id: holder,
                                        amount,
                                    },
                                )
                            }
                            (AccountPrivacyKind::Public, AccountPrivacyKind::Private) => {
                                TokenProgramSubcommand::Shielded(
                                    TokenProgramSubcommandShielded::MintTokenShieldedOwned {
                                        definition_account_id: definition,
                                        holder_account_id: holder,
                                        amount,
                                    },
                                )
                            }
                        }
                    }
                    (None, Some(holder_npk), Some(holder_vpk)) => {
                        let (definition, definition_privacy) =
                            parse_addr_with_privacy_prefix(&definition)?;

                        match definition_privacy {
                            AccountPrivacyKind::Private => TokenProgramSubcommand::Private(
                                TokenProgramSubcommandPrivate::MintTokenPrivateForeign {
                                    definition_account_id: definition,
                                    holder_npk,
                                    holder_vpk,
                                    holder_identifier,
                                    amount,
                                },
                            ),
                            AccountPrivacyKind::Public => TokenProgramSubcommand::Shielded(
                                TokenProgramSubcommandShielded::MintTokenShieldedForeign {
                                    definition_account_id: definition,
                                    holder_npk,
                                    holder_vpk,
                                    holder_identifier,
                                    amount,
                                },
                            ),
                        }
                    }
                };

                underlying_subcommand.handle_subcommand(wallet_core).await
            }
        }
    }
}

/// Represents generic CLI subcommand for a wallet working with `token_program`.
#[derive(Subcommand, Debug, Clone)]
pub enum TokenProgramSubcommand {
    /// Creation of new token.
    #[command(subcommand)]
    Create(CreateNewTokenProgramSubcommand),
    /// Public execution.
    #[command(subcommand)]
    Public(TokenProgramSubcommandPublic),
    /// Private execution.
    #[command(subcommand)]
    Private(TokenProgramSubcommandPrivate),
    /// Deshielded execution.
    #[command(subcommand)]
    Deshielded(TokenProgramSubcommandDeshielded),
    /// Shielded execution.
    #[command(subcommand)]
    Shielded(TokenProgramSubcommandShielded),
}

/// Represents generic public CLI subcommand for a wallet working with `token_program`.
#[derive(Subcommand, Debug, Clone)]
pub enum TokenProgramSubcommandPublic {
    // Transfer tokens using the token program
    TransferToken {
        #[arg(short, long)]
        sender_account_id: String,
        #[arg(short, long)]
        recipient_account_id: String,
        #[arg(short, long)]
        balance_to_move: u128,
        #[arg(long)]
        sender_key_path: Option<String>,
    },
    // Burn tokens using the token program
    BurnToken {
        #[arg(short, long)]
        definition_account_id: String,
        #[arg(short, long)]
        holder_account_id: String,
        #[arg(short, long)]
        amount: u128,
        #[arg(skip)]
        holder_key_path: Option<String>,
    },
    // Transfer tokens using the token program
    MintToken {
        #[arg(short, long)]
        definition_account_id: String,
        #[arg(short, long)]
        holder_account_id: String,
        #[arg(short, long)]
        amount: u128,
        #[arg(skip)]
        definition_key_path: Option<String>,
    },
}

/// Represents generic private CLI subcommand for a wallet working with `token_program`.
#[derive(Subcommand, Debug, Clone)]
pub enum TokenProgramSubcommandPrivate {
    // Transfer tokens using the token program
    TransferTokenPrivateOwned {
        #[arg(short, long)]
        sender_account_id: String,
        #[arg(short, long)]
        recipient_account_id: String,
        #[arg(short, long)]
        balance_to_move: u128,
    },
    // Transfer tokens using the token program
    TransferTokenPrivateForeign {
        #[arg(short, long)]
        sender_account_id: String,
        /// `recipient_npk` - valid 32 byte hex string.
        #[arg(long)]
        recipient_npk: String,
        /// `recipient_vpk` - valid 33 byte hex string.
        #[arg(long)]
        recipient_vpk: String,
        /// Identifier for the recipient's private account.
        #[arg(long)]
        recipient_identifier: Option<u128>,
        #[arg(short, long)]
        balance_to_move: u128,
    },
    // Burn tokens using the token program
    BurnTokenPrivateOwned {
        #[arg(short, long)]
        definition_account_id: String,
        #[arg(short, long)]
        holder_account_id: String,
        #[arg(short, long)]
        amount: u128,
    },
    // Transfer tokens using the token program
    MintTokenPrivateOwned {
        #[arg(short, long)]
        definition_account_id: String,
        #[arg(short, long)]
        holder_account_id: String,
        #[arg(short, long)]
        amount: u128,
    },
    // Transfer tokens using the token program
    MintTokenPrivateForeign {
        #[arg(short, long)]
        definition_account_id: String,
        #[arg(short, long)]
        holder_npk: String,
        #[arg(short, long)]
        holder_vpk: String,
        /// Identifier for the holder's private account.
        #[arg(long)]
        holder_identifier: Option<u128>,
        #[arg(short, long)]
        amount: u128,
    },
}

/// Represents deshielded public CLI subcommand for a wallet working with `token_program`.
#[derive(Subcommand, Debug, Clone)]
pub enum TokenProgramSubcommandDeshielded {
    // Transfer tokens using the token program
    TransferTokenDeshielded {
        #[arg(short, long)]
        sender_account_id: String,
        #[arg(short, long)]
        recipient_account_id: String,
        #[arg(short, long)]
        balance_to_move: u128,
    },
    // Burn tokens using the token program
    BurnTokenDeshieldedOwned {
        #[arg(short, long)]
        definition_account_id: String,
        #[arg(short, long)]
        holder_account_id: String,
        #[arg(short, long)]
        amount: u128,
    },
    // Transfer tokens using the token program
    MintTokenDeshielded {
        #[arg(short, long)]
        definition_account_id: String,
        #[arg(short, long)]
        holder_account_id: String,
        #[arg(short, long)]
        amount: u128,
    },
}

/// Represents generic shielded CLI subcommand for a wallet working with `token_program`.
#[derive(Subcommand, Debug, Clone)]
pub enum TokenProgramSubcommandShielded {
    // Transfer tokens using the token program
    TransferTokenShieldedOwned {
        #[arg(short, long)]
        sender_account_id: String,
        #[arg(short, long)]
        recipient_account_id: String,
        #[arg(short, long)]
        balance_to_move: u128,
        #[arg(long)]
        sender_key_path: Option<String>,
    },
    // Transfer tokens using the token program
    TransferTokenShieldedForeign {
        #[arg(short, long)]
        sender_account_id: String,
        /// `recipient_npk` - valid 32 byte hex string.
        #[arg(long)]
        recipient_npk: String,
        /// `recipient_vpk` - valid 33 byte hex string.
        #[arg(long)]
        recipient_vpk: String,
        /// Identifier for the recipient's private account.
        #[arg(long)]
        recipient_identifier: Option<u128>,
        #[arg(short, long)]
        balance_to_move: u128,
    },
    // Burn tokens using the token program
    BurnTokenShielded {
        #[arg(short, long)]
        definition_account_id: String,
        #[arg(short, long)]
        holder_account_id: String,
        #[arg(short, long)]
        amount: u128,
    },
    // Transfer tokens using the token program
    MintTokenShieldedOwned {
        #[arg(short, long)]
        definition_account_id: String,
        #[arg(short, long)]
        holder_account_id: String,
        #[arg(short, long)]
        amount: u128,
    },
    // Transfer tokens using the token program
    MintTokenShieldedForeign {
        #[arg(short, long)]
        definition_account_id: String,
        #[arg(short, long)]
        holder_npk: String,
        #[arg(short, long)]
        holder_vpk: String,
        /// Identifier for the holder's private account.
        #[arg(long)]
        holder_identifier: Option<u128>,
        #[arg(short, long)]
        amount: u128,
    },
}

/// Represents generic initialization subcommand for a wallet working with `token_program`.
#[derive(Subcommand, Debug, Clone)]
pub enum CreateNewTokenProgramSubcommand {
    /// Create a new token using the token program.
    ///
    /// Definition - public, supply - public.
    NewPublicDefPublicSupp {
        #[arg(short, long)]
        definition_account_id: String,
        #[arg(short, long)]
        supply_account_id: String,
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        total_supply: u128,
        #[arg(skip)]
        definition_key_path: Option<String>,
        #[arg(skip)]
        supply_key_path: Option<String>,
    },
    /// Create a new token using the token program.
    ///
    /// Definition - public, supply - private.
    NewPublicDefPrivateSupp {
        #[arg(short, long)]
        definition_account_id: String,
        #[arg(short, long)]
        supply_account_id: String,
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        total_supply: u128,
    },
    /// Create a new token using the token program.
    ///
    /// Definition - private, supply - public.
    NewPrivateDefPublicSupp {
        #[arg(short, long)]
        definition_account_id: String,
        #[arg(short, long)]
        supply_account_id: String,
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        total_supply: u128,
    },
    /// Create a new token using the token program.
    ///
    /// Definition - private, supply - private.
    NewPrivateDefPrivateSupp {
        #[arg(short, long)]
        definition_account_id: String,
        #[arg(short, long)]
        supply_account_id: String,
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        total_supply: u128,
    },
}

impl WalletSubcommand for TokenProgramSubcommandPublic {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::TransferToken {
                sender_account_id,
                recipient_account_id,
                balance_to_move,
                sender_key_path,
            } => {
                Token(wallet_core)
                    .send_transfer_transaction(
                        sender_account_id.parse().unwrap(),
                        recipient_account_id.parse().unwrap(),
                        balance_to_move,
                        sender_key_path,
                    )
                    .await?;
                Ok(SubcommandReturnValue::Empty)
            }
            Self::BurnToken {
                definition_account_id,
                holder_account_id,
                amount,
                holder_key_path,
            } => {
                Token(wallet_core)
                    .send_burn_transaction(
                        definition_account_id.parse().unwrap(),
                        holder_account_id.parse().unwrap(),
                        amount,
                        holder_key_path.as_deref(),
                    )
                    .await?;
                Ok(SubcommandReturnValue::Empty)
            }
            Self::MintToken {
                definition_account_id,
                holder_account_id,
                amount,
                definition_key_path,
            } => {
                Token(wallet_core)
                    .send_mint_transaction(
                        definition_account_id.parse().unwrap(),
                        holder_account_id.parse().unwrap(),
                        amount,
                        definition_key_path.as_deref(),
                    )
                    .await?;
                Ok(SubcommandReturnValue::Empty)
            }
        }
    }
}

impl WalletSubcommand for TokenProgramSubcommandPrivate {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::TransferTokenPrivateOwned {
                sender_account_id,
                recipient_account_id,
                balance_to_move,
            } => {
                let sender_account_id: AccountId = sender_account_id.parse().unwrap();
                let recipient_account_id: AccountId = recipient_account_id.parse().unwrap();

                let (tx_hash, [secret_sender, secret_recipient]) = Token(wallet_core)
                    .send_transfer_transaction_private_owned_account(
                        sender_account_id,
                        recipient_account_id,
                        balance_to_move,
                    )
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let NSSATransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![
                        Decode(secret_sender, sender_account_id),
                        Decode(secret_recipient, recipient_account_id),
                    ];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data().await?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::TransferTokenPrivateForeign {
                sender_account_id,
                recipient_npk,
                recipient_vpk,
                recipient_identifier,
                balance_to_move,
            } => {
                let sender_account_id: AccountId = sender_account_id.parse().unwrap();
                let recipient_npk_res = hex::decode(recipient_npk)?;
                let mut recipient_npk = [0; 32];
                recipient_npk.copy_from_slice(&recipient_npk_res);
                let recipient_npk = nssa_core::NullifierPublicKey(recipient_npk);

                let recipient_vpk_res = hex::decode(recipient_vpk)?;
                let mut recipient_vpk = [0_u8; 33];
                recipient_vpk.copy_from_slice(&recipient_vpk_res);
                let recipient_vpk = nssa_core::encryption::shared_key_derivation::Secp256k1Point(
                    recipient_vpk.to_vec(),
                );

                let (tx_hash, [secret_sender, _]) = Token(wallet_core)
                    .send_transfer_transaction_private_foreign_account(
                        sender_account_id,
                        recipient_npk,
                        recipient_vpk,
                        recipient_identifier.unwrap_or_else(rand::random),
                        balance_to_move,
                    )
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let NSSATransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![Decode(secret_sender, sender_account_id)];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data().await?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::BurnTokenPrivateOwned {
                definition_account_id,
                holder_account_id,
                amount,
            } => {
                let definition_account_id: AccountId = definition_account_id.parse().unwrap();
                let holder_account_id: AccountId = holder_account_id.parse().unwrap();

                let (tx_hash, [secret_definition, secret_holder]) = Token(wallet_core)
                    .send_burn_transaction_private_owned_account(
                        definition_account_id,
                        holder_account_id,
                        amount,
                    )
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let NSSATransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![
                        Decode(secret_definition, definition_account_id),
                        Decode(secret_holder, holder_account_id),
                    ];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data().await?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::MintTokenPrivateOwned {
                definition_account_id,
                holder_account_id,
                amount,
            } => {
                let definition_account_id: AccountId = definition_account_id.parse().unwrap();
                let holder_account_id: AccountId = holder_account_id.parse().unwrap();

                let (tx_hash, [secret_definition, secret_holder]) = Token(wallet_core)
                    .send_mint_transaction_private_owned_account(
                        definition_account_id,
                        holder_account_id,
                        amount,
                    )
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let NSSATransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![
                        Decode(secret_definition, definition_account_id),
                        Decode(secret_holder, holder_account_id),
                    ];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data().await?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::MintTokenPrivateForeign {
                definition_account_id,
                holder_npk,
                holder_vpk,
                holder_identifier,
                amount,
            } => {
                let definition_account_id: AccountId = definition_account_id.parse().unwrap();

                let holder_npk_res = hex::decode(holder_npk)?;
                let mut holder_npk = [0; 32];
                holder_npk.copy_from_slice(&holder_npk_res);
                let holder_npk = nssa_core::NullifierPublicKey(holder_npk);

                let holder_vpk_res = hex::decode(holder_vpk)?;
                let mut holder_vpk = [0_u8; 33];
                holder_vpk.copy_from_slice(&holder_vpk_res);
                let holder_vpk = nssa_core::encryption::shared_key_derivation::Secp256k1Point(
                    holder_vpk.to_vec(),
                );

                let (tx_hash, [secret_definition, _]) = Token(wallet_core)
                    .send_mint_transaction_private_foreign_account(
                        definition_account_id,
                        holder_npk,
                        holder_vpk,
                        holder_identifier.unwrap_or_else(rand::random),
                        amount,
                    )
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let NSSATransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![Decode(secret_definition, definition_account_id)];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data().await?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
        }
    }
}

impl WalletSubcommand for TokenProgramSubcommandDeshielded {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::TransferTokenDeshielded {
                sender_account_id,
                recipient_account_id,
                balance_to_move,
            } => {
                let sender_account_id: AccountId = sender_account_id.parse().unwrap();
                let recipient_account_id: AccountId = recipient_account_id.parse().unwrap();

                let (tx_hash, secret_sender) = Token(wallet_core)
                    .send_transfer_transaction_deshielded(
                        sender_account_id,
                        recipient_account_id,
                        balance_to_move,
                    )
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let NSSATransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![Decode(secret_sender, sender_account_id)];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data().await?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::BurnTokenDeshieldedOwned {
                definition_account_id,
                holder_account_id,
                amount,
            } => {
                let definition_account_id: AccountId = definition_account_id.parse().unwrap();
                let holder_account_id: AccountId = holder_account_id.parse().unwrap();

                let (tx_hash, secret_definition) = Token(wallet_core)
                    .send_burn_transaction_deshielded_owned_account(
                        definition_account_id,
                        holder_account_id,
                        amount,
                    )
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let NSSATransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![Decode(secret_definition, definition_account_id)];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data().await?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::MintTokenDeshielded {
                definition_account_id,
                holder_account_id,
                amount,
            } => {
                let definition_account_id: AccountId = definition_account_id.parse().unwrap();
                let holder_account_id: AccountId = holder_account_id.parse().unwrap();

                let (tx_hash, secret_definition) = Token(wallet_core)
                    .send_mint_transaction_deshielded(
                        definition_account_id,
                        holder_account_id,
                        amount,
                    )
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let NSSATransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![Decode(secret_definition, definition_account_id)];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data().await?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
        }
    }
}

impl WalletSubcommand for TokenProgramSubcommandShielded {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::TransferTokenShieldedForeign {
                sender_account_id,
                recipient_npk,
                recipient_vpk,
                recipient_identifier,
                balance_to_move,
            } => {
                let sender_account_id: AccountId = sender_account_id.parse().unwrap();
                let recipient_npk_res = hex::decode(recipient_npk)?;
                let mut recipient_npk = [0; 32];
                recipient_npk.copy_from_slice(&recipient_npk_res);
                let recipient_npk = nssa_core::NullifierPublicKey(recipient_npk);

                let recipient_vpk_res = hex::decode(recipient_vpk)?;
                let mut recipient_vpk = [0_u8; 33];
                recipient_vpk.copy_from_slice(&recipient_vpk_res);
                let recipient_vpk = nssa_core::encryption::shared_key_derivation::Secp256k1Point(
                    recipient_vpk.to_vec(),
                );

                let (tx_hash, _) = Token(wallet_core)
                    .send_transfer_transaction_shielded_foreign_account(
                        sender_account_id,
                        recipient_npk,
                        recipient_vpk,
                        recipient_identifier.unwrap_or_else(rand::random),
                        balance_to_move,
                    )
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let NSSATransaction::PrivacyPreserving(tx) = transfer_tx {
                    println!("Transaction data is {:?}", tx.message);
                }

                wallet_core.store_persistent_data().await?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::TransferTokenShieldedOwned {
                sender_account_id,
                recipient_account_id,
                balance_to_move,
                sender_key_path,
            } => {
                let sender_account_id: AccountId = sender_account_id.parse().unwrap();
                let recipient_account_id: AccountId = recipient_account_id.parse().unwrap();

                let (tx_hash, secret_recipient) = Token(wallet_core)
                    .send_transfer_transaction_shielded_owned_account(
                        sender_account_id,
                        recipient_account_id,
                        balance_to_move,
                        sender_key_path,
                    )
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let NSSATransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![Decode(secret_recipient, recipient_account_id)];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data().await?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::BurnTokenShielded {
                definition_account_id,
                holder_account_id,
                amount,
            } => {
                let definition_account_id: AccountId = definition_account_id.parse().unwrap();
                let holder_account_id: AccountId = holder_account_id.parse().unwrap();

                let (tx_hash, secret_holder) = Token(wallet_core)
                    .send_burn_transaction_shielded(
                        definition_account_id,
                        holder_account_id,
                        amount,
                    )
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let NSSATransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![Decode(secret_holder, holder_account_id)];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data().await?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::MintTokenShieldedOwned {
                definition_account_id,
                holder_account_id,
                amount,
            } => {
                let definition_account_id: AccountId = definition_account_id.parse().unwrap();
                let holder_account_id: AccountId = holder_account_id.parse().unwrap();

                let (tx_hash, secret_holder) = Token(wallet_core)
                    .send_mint_transaction_shielded_owned_account(
                        definition_account_id,
                        holder_account_id,
                        amount,
                    )
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let NSSATransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![Decode(secret_holder, holder_account_id)];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data().await?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::MintTokenShieldedForeign {
                definition_account_id,
                holder_npk,
                holder_vpk,
                holder_identifier,
                amount,
            } => {
                let definition_account_id: AccountId = definition_account_id.parse().unwrap();

                let holder_npk_res = hex::decode(holder_npk)?;
                let mut holder_npk = [0; 32];
                holder_npk.copy_from_slice(&holder_npk_res);
                let holder_npk = nssa_core::NullifierPublicKey(holder_npk);

                let holder_vpk_res = hex::decode(holder_vpk)?;
                let mut holder_vpk = [0_u8; 33];
                holder_vpk.copy_from_slice(&holder_vpk_res);
                let holder_vpk = nssa_core::encryption::shared_key_derivation::Secp256k1Point(
                    holder_vpk.to_vec(),
                );

                let (tx_hash, _) = Token(wallet_core)
                    .send_mint_transaction_shielded_foreign_account(
                        definition_account_id,
                        holder_npk,
                        holder_vpk,
                        holder_identifier.unwrap_or_else(rand::random),
                        amount,
                    )
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let NSSATransaction::PrivacyPreserving(tx) = transfer_tx {
                    println!("Transaction data is {:?}", tx.message);
                }

                wallet_core.store_persistent_data().await?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
        }
    }
}

impl WalletSubcommand for CreateNewTokenProgramSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::NewPrivateDefPrivateSupp {
                definition_account_id,
                supply_account_id,
                name,
                total_supply,
            } => {
                let definition_account_id: AccountId = definition_account_id.parse().unwrap();
                let supply_account_id: AccountId = supply_account_id.parse().unwrap();

                let (tx_hash, [secret_definition, secret_supply]) = Token(wallet_core)
                    .send_new_definition_private_owned_definiton_and_supply(
                        definition_account_id,
                        supply_account_id,
                        name,
                        total_supply,
                    )
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let NSSATransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![
                        Decode(secret_definition, definition_account_id),
                        Decode(secret_supply, supply_account_id),
                    ];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data().await?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::NewPrivateDefPublicSupp {
                definition_account_id,
                supply_account_id,
                name,
                total_supply,
            } => {
                let definition_account_id: AccountId = definition_account_id.parse().unwrap();
                let supply_account_id: AccountId = supply_account_id.parse().unwrap();

                let (tx_hash, secret_definition) = Token(wallet_core)
                    .send_new_definition_private_owned_definiton(
                        definition_account_id,
                        supply_account_id,
                        name,
                        total_supply,
                    )
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let NSSATransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![Decode(secret_definition, definition_account_id)];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data().await?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::NewPublicDefPrivateSupp {
                definition_account_id,
                supply_account_id,
                name,
                total_supply,
            } => {
                let definition_account_id: AccountId = definition_account_id.parse().unwrap();
                let supply_account_id: AccountId = supply_account_id.parse().unwrap();

                let (tx_hash, secret_supply) = Token(wallet_core)
                    .send_new_definition_private_owned_supply(
                        definition_account_id,
                        supply_account_id,
                        name,
                        total_supply,
                    )
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let NSSATransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![Decode(secret_supply, supply_account_id)];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data().await?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::NewPublicDefPublicSupp {
                definition_account_id,
                supply_account_id,
                name,
                total_supply,
                definition_key_path,
                supply_key_path,
            } => {
                Token(wallet_core)
                    .send_new_definition(
                        definition_account_id.parse().unwrap(),
                        supply_account_id.parse().unwrap(),
                        name,
                        total_supply,
                        definition_key_path.as_deref(),
                        supply_key_path.as_deref(),
                    )
                    .await?;
                Ok(SubcommandReturnValue::Empty)
            }
        }
    }
}

impl WalletSubcommand for TokenProgramSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::Create(creation_subcommand) => {
                creation_subcommand.handle_subcommand(wallet_core).await
            }
            Self::Private(private_subcommand) => {
                private_subcommand.handle_subcommand(wallet_core).await
            }
            Self::Public(public_subcommand) => {
                public_subcommand.handle_subcommand(wallet_core).await
            }
            Self::Deshielded(deshielded_subcommand) => {
                deshielded_subcommand.handle_subcommand(wallet_core).await
            }
            Self::Shielded(shielded_subcommand) => {
                shielded_subcommand.handle_subcommand(wallet_core).await
            }
        }
    }
}
