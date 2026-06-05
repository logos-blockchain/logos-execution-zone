use anyhow::{Context as _, Result};
use clap::Subcommand;
use common::transaction::LeeTransaction;
use lee::AccountId;

use crate::{
    AccDecodeData::Decode,
    AccountIdentity, WalletCore,
    account::AccountIdWithPrivacy,
    cli::{CliAccountMention, SubcommandReturnValue, WalletSubcommand},
    program_facades::token::Token,
};

/// Represents generic CLI subcommand for a wallet working with token program.
#[derive(Subcommand, Debug, Clone)]
pub enum TokenProgramAgnosticSubcommand {
    /// Produce a new token.
    New {
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        definition_account_id: CliAccountMention,
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        supply_account_id: CliAccountMention,
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        total_supply: u128,
    },
    /// Send tokens from one account to another with variable privacy.
    ///
    /// If receiver is private, then `to` and (`to_npk` , `to_vpk`) is a mutually exclusive
    /// patterns.
    ///
    /// First is used for owned accounts, second otherwise.
    Send {
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        from: CliAccountMention,
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        to: Option<CliAccountMention>,
        /// `to_npk` - valid 32 byte hex string.
        #[arg(long, conflicts_with = "to_keys")]
        to_npk: Option<String>,
        /// `to_vpk` - valid hex-encoded ML-KEM-768 encapsulation key (1184 bytes).
        #[arg(long, conflicts_with = "to_keys")]
        to_vpk: Option<String>,
        /// Path to a keys file exported by `wallet account show-keys`, containing npk
        /// and vpk on separate lines. Replaces `--to-npk` and `--to-vpk`.
        #[arg(long, conflicts_with_all = ["to_npk", "to_vpk"])]
        to_keys: Option<String>,
        /// Identifier for the recipient's private account (only used when sending to a foreign
        /// private account via `--to-npk`/`--to-vpk` or `--to-keys`).
        #[arg(long)]
        to_identifier: Option<u128>,
        /// amount - amount of balance to move.
        #[arg(long)]
        amount: u128,
    },
    /// Burn tokens on `holder`, modify `definition`.
    ///
    /// `holder` is owned.
    ///
    /// Also if `definition` is private then it is owned, because
    /// we can not modify foreign accounts.
    Burn {
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        definition: CliAccountMention,
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        holder: CliAccountMention,
        /// amount - amount of balance to burn.
        #[arg(long)]
        amount: u128,
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
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        definition: CliAccountMention,
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        holder: Option<CliAccountMention>,
        /// `holder_npk` - valid 32 byte hex string.
        #[arg(long, conflicts_with = "holder_keys")]
        holder_npk: Option<String>,
        /// `holder_vpk` - valid hex-encoded ML-KEM-768 encapsulation key (1184 bytes).
        #[arg(long, conflicts_with = "holder_keys")]
        holder_vpk: Option<String>,
        /// Path to a keys file exported by `wallet account show-keys`, containing npk
        /// and vpk on separate lines. Replaces `--holder-npk` and `--holder-vpk`.
        #[arg(long, conflicts_with_all = ["holder_npk", "holder_vpk"])]
        holder_keys: Option<String>,
        /// Identifier for the holder's private account (only used when minting to a foreign
        /// private account via `--holder-npk`/`--holder-vpk` or `--holder-keys`).
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
            Self::New {
                definition_account_id,
                supply_account_id,
                name,
                total_supply,
            } => {
                let def_mention = definition_account_id.clone();
                let sup_mention = supply_account_id.clone();
                let definition_account_id = definition_account_id.resolve(wallet_core.storage())?;
                let supply_account_id = supply_account_id.resolve(wallet_core.storage())?;
                let underlying_subcommand = match (definition_account_id, supply_account_id) {
                    (AccountIdWithPrivacy::Public(_), AccountIdWithPrivacy::Public(_)) => {
                        TokenProgramSubcommand::Create(
                            CreateNewTokenProgramSubcommand::NewPublicDefPublicSupp {
                                definition_account_id: def_mention,
                                supply_account_id: sup_mention,
                                name,
                                total_supply,
                            },
                        )
                    }
                    (
                        AccountIdWithPrivacy::Public(definition_account_id),
                        AccountIdWithPrivacy::Private(supply_account_id),
                    ) => TokenProgramSubcommand::Create(
                        CreateNewTokenProgramSubcommand::NewPublicDefPrivateSupp {
                            definition_account_id,
                            supply_account_id,
                            name,
                            total_supply,
                        },
                    ),
                    (
                        AccountIdWithPrivacy::Private(definition_account_id),
                        AccountIdWithPrivacy::Private(supply_account_id),
                    ) => TokenProgramSubcommand::Create(
                        CreateNewTokenProgramSubcommand::NewPrivateDefPrivateSupp {
                            definition_account_id,
                            supply_account_id,
                            name,
                            total_supply,
                        },
                    ),
                    (
                        AccountIdWithPrivacy::Private(definition_account_id),
                        AccountIdWithPrivacy::Public(supply_account_id),
                    ) => TokenProgramSubcommand::Create(
                        CreateNewTokenProgramSubcommand::NewPrivateDefPublicSupp {
                            definition_account_id,
                            supply_account_id,
                            name,
                            total_supply,
                        },
                    ),
                };

                underlying_subcommand.handle_subcommand(wallet_core).await
            }
            Self::Send {
                from,
                to,
                to_npk,
                to_vpk,
                to_keys,
                to_identifier,
                amount,
            } => {
                let from_mention = from.clone();
                let to_mention = to.clone();
                let (to_npk, to_vpk) = if let Some(path) = to_keys {
                    let (npk_bytes, vpk_bytes) = crate::cli::read_keys_file(&path)?;
                    (Some(hex::encode(npk_bytes)), Some(hex::encode(vpk_bytes)))
                } else {
                    (to_npk, to_vpk)
                };

                let from = from.resolve(wallet_core.storage())?;
                let to = to
                    .map(|account_mention| account_mention.resolve(wallet_core.storage()))
                    .transpose()?;
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
                    (Some(to), None, None) => match (from, to) {
                        (AccountIdWithPrivacy::Public(_), AccountIdWithPrivacy::Public(_)) => {
                            TokenProgramSubcommand::Public(
                                TokenProgramSubcommandPublic::TransferToken {
                                    sender_account_id: from_mention,
                                    recipient_account_id: to_mention.expect("`wallet::cli::programs::token::Send`: Invalid to_mention account provided"),
                                    balance_to_move: amount,
                                },
                            )
                        }
                        (
                            AccountIdWithPrivacy::Private(from),
                            AccountIdWithPrivacy::Private(to),
                        ) => TokenProgramSubcommand::Private(
                            TokenProgramSubcommandPrivate::TransferTokenPrivateOwned {
                                sender_account_id: from,
                                recipient_account_id: to,
                                balance_to_move: amount,
                            },
                        ),
                        (AccountIdWithPrivacy::Private(from), AccountIdWithPrivacy::Public(to)) => {
                            TokenProgramSubcommand::Deshielded(
                                TokenProgramSubcommandDeshielded::TransferTokenDeshielded {
                                    sender_account_id: from,
                                    recipient_account_id: to,
                                    balance_to_move: amount,
                                },
                            )
                        }
                        (AccountIdWithPrivacy::Public(from), AccountIdWithPrivacy::Private(to)) => {
                            TokenProgramSubcommand::Shielded(
                                TokenProgramSubcommandShielded::TransferTokenShieldedOwned {
                                    sender: Some(from_mention.into_public_identity(from)),
                                    recipient_account_id: to,
                                    balance_to_move: amount,
                                },
                            )
                        }
                    },
                    (None, Some(to_npk), Some(to_vpk)) => match from {
                        AccountIdWithPrivacy::Private(from) => TokenProgramSubcommand::Private(
                            TokenProgramSubcommandPrivate::TransferTokenPrivateForeign {
                                sender_account_id: from,
                                recipient_npk: to_npk,
                                recipient_vpk: to_vpk,
                                recipient_identifier: to_identifier,
                                balance_to_move: amount,
                            },
                        ),
                        AccountIdWithPrivacy::Public(from) => TokenProgramSubcommand::Shielded(
                            TokenProgramSubcommandShielded::TransferTokenShieldedForeign {
                                sender: Some(from_mention.into_public_identity(from)),
                                recipient_npk: to_npk,
                                recipient_vpk: to_vpk,
                                recipient_identifier: to_identifier,
                                balance_to_move: amount,
                            },
                        ),
                    },
                };

                underlying_subcommand.handle_subcommand(wallet_core).await
            }
            Self::Burn {
                definition,
                holder,
                amount,
            } => {
                let holder_mention = holder.clone();
                let definition = definition.resolve(wallet_core.storage())?;
                let holder = holder.resolve(wallet_core.storage())?;
                let underlying_subcommand = match (definition, holder) {
                    (AccountIdWithPrivacy::Public(definition), AccountIdWithPrivacy::Public(_)) => {
                        TokenProgramSubcommand::Public(TokenProgramSubcommandPublic::BurnToken {
                            definition_account_id: definition,
                            holder_account_id: holder_mention,
                            amount,
                        })
                    }
                    (
                        AccountIdWithPrivacy::Private(definition),
                        AccountIdWithPrivacy::Private(holder),
                    ) => TokenProgramSubcommand::Private(
                        TokenProgramSubcommandPrivate::BurnTokenPrivateOwned {
                            definition_account_id: definition,
                            holder_account_id: holder,
                            amount,
                        },
                    ),
                    (
                        AccountIdWithPrivacy::Private(definition),
                        AccountIdWithPrivacy::Public(holder),
                    ) => TokenProgramSubcommand::Deshielded(
                        TokenProgramSubcommandDeshielded::BurnTokenDeshieldedOwned {
                            definition_account_id: definition,
                            holder_account_id: holder,
                            amount,
                        },
                    ),
                    (
                        AccountIdWithPrivacy::Public(definition),
                        AccountIdWithPrivacy::Private(holder),
                    ) => TokenProgramSubcommand::Shielded(
                        TokenProgramSubcommandShielded::BurnTokenShielded {
                            definition_account_id: definition,
                            holder_account_id: holder,
                            amount,
                        },
                    ),
                };

                underlying_subcommand.handle_subcommand(wallet_core).await
            }
            Self::Mint {
                definition,
                holder,
                holder_npk,
                holder_vpk,
                holder_keys,
                holder_identifier,
                amount,
            } => {
                let def_mention = definition.clone();
                let holder_mention = holder.clone();
                let (holder_npk, holder_vpk) = if let Some(path) = holder_keys {
                    let (npk_bytes, vpk_bytes) = crate::cli::read_keys_file(&path)?;
                    (Some(hex::encode(npk_bytes)), Some(hex::encode(vpk_bytes)))
                } else {
                    (holder_npk, holder_vpk)
                };

                let definition = definition.resolve(wallet_core.storage())?;
                let holder = holder
                    .map(|account_mention| account_mention.resolve(wallet_core.storage()))
                    .transpose()?;
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
                    (Some(holder), None, None) => match (definition, holder) {
                        (AccountIdWithPrivacy::Public(_), AccountIdWithPrivacy::Public(_)) => {
                            TokenProgramSubcommand::Public(
                                TokenProgramSubcommandPublic::MintToken {
                                    definition_account_id: def_mention,
                                    holder_account_id: holder_mention.expect("`wallet::cli::programs::token::Mint`: Invalid holder_mention account provided"),
                                    amount,
                                },
                            )
                        }
                        (
                            AccountIdWithPrivacy::Private(definition),
                            AccountIdWithPrivacy::Private(holder),
                        ) => TokenProgramSubcommand::Private(
                            TokenProgramSubcommandPrivate::MintTokenPrivateOwned {
                                definition_account_id: definition,
                                holder_account_id: holder,
                                amount,
                            },
                        ),
                        (
                            AccountIdWithPrivacy::Private(definition),
                            AccountIdWithPrivacy::Public(holder),
                        ) => TokenProgramSubcommand::Deshielded(
                            TokenProgramSubcommandDeshielded::MintTokenDeshielded {
                                definition_account_id: definition,
                                holder_account_id: holder,
                                amount,
                            },
                        ),
                        (
                            AccountIdWithPrivacy::Public(definition),
                            AccountIdWithPrivacy::Private(holder),
                        ) => TokenProgramSubcommand::Shielded(
                            TokenProgramSubcommandShielded::MintTokenShieldedOwned {
                                definition_account_id: definition,
                                holder_account_id: holder,
                                amount,
                            },
                        ),
                    },
                    (None, Some(holder_npk), Some(holder_vpk)) => match definition {
                        AccountIdWithPrivacy::Private(definition) => {
                            TokenProgramSubcommand::Private(
                                TokenProgramSubcommandPrivate::MintTokenPrivateForeign {
                                    definition_account_id: definition,
                                    holder_npk,
                                    holder_vpk,
                                    holder_identifier,
                                    amount,
                                },
                            )
                        }
                        AccountIdWithPrivacy::Public(definition) => {
                            TokenProgramSubcommand::Shielded(
                                TokenProgramSubcommandShielded::MintTokenShieldedForeign {
                                    definition_account_id: definition,
                                    holder_npk,
                                    holder_vpk,
                                    holder_identifier,
                                    amount,
                                },
                            )
                        }
                    },
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
        sender_account_id: CliAccountMention,
        #[arg(short, long)]
        recipient_account_id: CliAccountMention,
        #[arg(short, long)]
        balance_to_move: u128,
    },
    // Burn tokens using the token program
    BurnToken {
        #[arg(short, long)]
        definition_account_id: AccountId,
        #[arg(short, long)]
        holder_account_id: CliAccountMention,
        #[arg(short, long)]
        amount: u128,
    },
    // Transfer tokens using the token program
    MintToken {
        #[arg(short, long)]
        definition_account_id: CliAccountMention,
        #[arg(short, long)]
        holder_account_id: CliAccountMention,
        #[arg(short, long)]
        amount: u128,
    },
}

/// Represents generic private CLI subcommand for a wallet working with `token_program`.
#[derive(Subcommand, Debug, Clone)]
pub enum TokenProgramSubcommandPrivate {
    // Transfer tokens using the token program
    TransferTokenPrivateOwned {
        #[arg(short, long)]
        sender_account_id: AccountId,
        #[arg(short, long)]
        recipient_account_id: AccountId,
        #[arg(short, long)]
        balance_to_move: u128,
    },
    // Transfer tokens using the token program
    TransferTokenPrivateForeign {
        #[arg(short, long)]
        sender_account_id: AccountId,
        /// `recipient_npk` - valid 32 byte hex string.
        #[arg(long)]
        recipient_npk: String,
        /// `recipient_vpk` - valid hex-encoded ML-KEM-768 encapsulation key (1184 bytes).
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
        definition_account_id: AccountId,
        #[arg(short, long)]
        holder_account_id: AccountId,
        #[arg(short, long)]
        amount: u128,
    },
    // Transfer tokens using the token program
    MintTokenPrivateOwned {
        #[arg(short, long)]
        definition_account_id: AccountId,
        #[arg(short, long)]
        holder_account_id: AccountId,
        #[arg(short, long)]
        amount: u128,
    },
    // Transfer tokens using the token program
    MintTokenPrivateForeign {
        #[arg(short, long)]
        definition_account_id: AccountId,
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
        sender_account_id: AccountId,
        #[arg(short, long)]
        recipient_account_id: AccountId,
        #[arg(short, long)]
        balance_to_move: u128,
    },
    // Burn tokens using the token program
    BurnTokenDeshieldedOwned {
        #[arg(short, long)]
        definition_account_id: AccountId,
        #[arg(short, long)]
        holder_account_id: AccountId,
        #[arg(short, long)]
        amount: u128,
    },
    // Transfer tokens using the token program
    MintTokenDeshielded {
        #[arg(short, long)]
        definition_account_id: AccountId,
        #[arg(short, long)]
        holder_account_id: AccountId,
        #[arg(short, long)]
        amount: u128,
    },
}

/// Represents generic shielded CLI subcommand for a wallet working with `token_program`.
#[derive(Subcommand, Debug, Clone)]
pub enum TokenProgramSubcommandShielded {
    // Transfer tokens using the token program
    TransferTokenShieldedOwned {
        #[arg(skip)]
        sender: Option<AccountIdentity>,
        #[arg(short, long)]
        recipient_account_id: AccountId,
        #[arg(short, long)]
        balance_to_move: u128,
    },
    // Transfer tokens using the token program
    TransferTokenShieldedForeign {
        #[arg(skip)]
        sender: Option<AccountIdentity>,
        /// `recipient_npk` - valid 32 byte hex string.
        #[arg(long)]
        recipient_npk: String,
        /// `recipient_vpk` - valid hex-encoded ML-KEM-768 encapsulation key (1184 bytes).
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
        definition_account_id: AccountId,
        #[arg(short, long)]
        holder_account_id: AccountId,
        #[arg(short, long)]
        amount: u128,
    },
    // Transfer tokens using the token program
    MintTokenShieldedOwned {
        #[arg(short, long)]
        definition_account_id: AccountId,
        #[arg(short, long)]
        holder_account_id: AccountId,
        #[arg(short, long)]
        amount: u128,
    },
    // Transfer tokens using the token program
    MintTokenShieldedForeign {
        #[arg(short, long)]
        definition_account_id: AccountId,
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
        definition_account_id: CliAccountMention,
        #[arg(short, long)]
        supply_account_id: CliAccountMention,
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        total_supply: u128,
    },
    /// Create a new token using the token program.
    ///
    /// Definition - public, supply - private.
    NewPublicDefPrivateSupp {
        #[arg(short, long)]
        definition_account_id: AccountId,
        #[arg(short, long)]
        supply_account_id: AccountId,
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
        definition_account_id: AccountId,
        #[arg(short, long)]
        supply_account_id: AccountId,
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
        definition_account_id: AccountId,
        #[arg(short, long)]
        supply_account_id: AccountId,
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
            } => {
                let sender = sender_account_id.resolve(wallet_core.storage())?;
                let recipient = recipient_account_id.resolve(wallet_core.storage())?;
                let (
                    AccountIdWithPrivacy::Public(sender_id),
                    AccountIdWithPrivacy::Public(recipient_id),
                ) = (sender, recipient)
                else {
                    anyhow::bail!(
                        "`TokenProgramSubcommandPublic::TransferToken`: Unexpected private account received."
                    );
                };
                let tx_hash = Token(wallet_core)
                    .send_transfer_transaction(
                        sender_account_id.into_public_identity(sender_id),
                        recipient_account_id.into_public_identity(recipient_id),
                        balance_to_move,
                    )
                    .await?;
                println!("Transaction hash is {tx_hash}");
                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;
                println!("Transaction data is {transfer_tx:?}");
                wallet_core.store_persistent_data()?;
                Ok(SubcommandReturnValue::Empty)
            }
            Self::BurnToken {
                definition_account_id,
                holder_account_id,
                amount,
            } => {
                let holder = holder_account_id.resolve(wallet_core.storage())?;
                let AccountIdWithPrivacy::Public(holder_id) = holder else {
                    anyhow::bail!(
                        "`TokenProgramSubcommandPublic::BurnToken`: holder account must be public."
                    );
                };
                let tx_hash = Token(wallet_core)
                    .send_burn_transaction(
                        definition_account_id,
                        holder_account_id.into_public_identity(holder_id),
                        amount,
                    )
                    .await?;
                println!("Transaction hash is {tx_hash}");
                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;
                println!("Transaction data is {transfer_tx:?}");
                wallet_core.store_persistent_data()?;
                Ok(SubcommandReturnValue::Empty)
            }
            Self::MintToken {
                definition_account_id,
                holder_account_id,
                amount,
            } => {
                let definition = definition_account_id.resolve(wallet_core.storage())?;
                let holder = holder_account_id.resolve(wallet_core.storage())?;
                let (AccountIdWithPrivacy::Public(def_id), AccountIdWithPrivacy::Public(holder_id)) =
                    (definition, holder)
                else {
                    anyhow::bail!(
                        "`TokenProgramSubcommandPublic::MintToken`: holder account must be public."
                    );
                };
                let tx_hash = Token(wallet_core)
                    .send_mint_transaction(
                        definition_account_id.into_public_identity(def_id),
                        holder_account_id.into_public_identity(holder_id),
                        amount,
                    )
                    .await?;
                println!("Transaction hash is {tx_hash}");
                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;
                println!("Transaction data is {transfer_tx:?}");
                wallet_core.store_persistent_data()?;
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
                let (tx_hash, [secret_sender, secret_recipient]) = Token(wallet_core)
                    .send_transfer_transaction_private_owned_account(
                        sender_account_id,
                        recipient_account_id,
                        balance_to_move,
                    )
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let LeeTransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![
                        Decode(secret_sender, sender_account_id),
                        Decode(secret_recipient, recipient_account_id),
                    ];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data()?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::TransferTokenPrivateForeign {
                sender_account_id,
                recipient_npk,
                recipient_vpk,
                recipient_identifier,
                balance_to_move,
            } => {
                let recipient_npk_res = hex::decode(recipient_npk)?;
                let mut recipient_npk = [0; 32];
                recipient_npk.copy_from_slice(&recipient_npk_res);
                let recipient_npk = lee_core::NullifierPublicKey(recipient_npk);

                let recipient_vpk_res = hex::decode(&recipient_vpk).context(
                    "wallet::cli::programs::token: recipient_vpk must be a valid hex string",
                )?;
                let recipient_vpk =
                    lee_core::encryption::ViewingPublicKey::from_bytes(recipient_vpk_res)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;

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

                if let LeeTransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![Decode(secret_sender, sender_account_id)];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data()?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::BurnTokenPrivateOwned {
                definition_account_id,
                holder_account_id,
                amount,
            } => {
                let (tx_hash, [secret_definition, secret_holder]) = Token(wallet_core)
                    .send_burn_transaction_private_owned_account(
                        definition_account_id,
                        holder_account_id,
                        amount,
                    )
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let LeeTransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![
                        Decode(secret_definition, definition_account_id),
                        Decode(secret_holder, holder_account_id),
                    ];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data()?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::MintTokenPrivateOwned {
                definition_account_id,
                holder_account_id,
                amount,
            } => {
                let (tx_hash, [secret_definition, secret_holder]) = Token(wallet_core)
                    .send_mint_transaction_private_owned_account(
                        definition_account_id,
                        holder_account_id,
                        amount,
                    )
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let LeeTransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![
                        Decode(secret_definition, definition_account_id),
                        Decode(secret_holder, holder_account_id),
                    ];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data()?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::MintTokenPrivateForeign {
                definition_account_id,
                holder_npk,
                holder_vpk,
                holder_identifier,
                amount,
            } => {
                let holder_npk_res = hex::decode(holder_npk)?;
                let mut holder_npk = [0; 32];
                holder_npk.copy_from_slice(&holder_npk_res);
                let holder_npk = lee_core::NullifierPublicKey(holder_npk);

                let holder_vpk_res = hex::decode(&holder_vpk).context(
                    "wallet::cli::programs::token: holder_vpk must be a valid hex string",
                )?;
                let holder_vpk = lee_core::encryption::ViewingPublicKey::from_bytes(holder_vpk_res)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;

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

                if let LeeTransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![Decode(secret_definition, definition_account_id)];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data()?;

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
                let (tx_hash, secret_sender) = Token(wallet_core)
                    .send_transfer_transaction_deshielded(
                        sender_account_id,
                        recipient_account_id,
                        balance_to_move,
                    )
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let LeeTransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![Decode(secret_sender, sender_account_id)];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data()?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::BurnTokenDeshieldedOwned {
                definition_account_id,
                holder_account_id,
                amount,
            } => {
                let (tx_hash, secret_definition) = Token(wallet_core)
                    .send_burn_transaction_deshielded_owned_account(
                        definition_account_id,
                        holder_account_id,
                        amount,
                    )
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let LeeTransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![Decode(secret_definition, definition_account_id)];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data()?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::MintTokenDeshielded {
                definition_account_id,
                holder_account_id,
                amount,
            } => {
                let (tx_hash, secret_definition) = Token(wallet_core)
                    .send_mint_transaction_deshielded(
                        definition_account_id,
                        holder_account_id,
                        amount,
                    )
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let LeeTransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![Decode(secret_definition, definition_account_id)];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data()?;

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
                sender,
                recipient_npk,
                recipient_vpk,
                recipient_identifier,
                balance_to_move,
            } => {
                let recipient_npk_res = hex::decode(recipient_npk)?;
                let mut recipient_npk = [0; 32];
                recipient_npk.copy_from_slice(&recipient_npk_res);
                let recipient_npk = lee_core::NullifierPublicKey(recipient_npk);

                let recipient_vpk_res = hex::decode(&recipient_vpk).context(
                    "wallet::cli::programs::token: recipient_vpk must be a valid hex string",
                )?;
                let recipient_vpk =
                    lee_core::encryption::ViewingPublicKey::from_bytes(recipient_vpk_res)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;

                let (tx_hash, _) = Token(wallet_core)
                    .send_transfer_transaction_shielded_foreign_account(
                        sender.expect("sender set during Send dispatch"),
                        recipient_npk,
                        recipient_vpk,
                        recipient_identifier.unwrap_or_else(rand::random),
                        balance_to_move,
                    )
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let LeeTransaction::PrivacyPreserving(tx) = transfer_tx {
                    println!("Transaction data is {:?}", tx.message);
                }

                wallet_core.store_persistent_data()?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::TransferTokenShieldedOwned {
                sender,
                recipient_account_id,
                balance_to_move,
            } => {
                let (tx_hash, secret_recipient) = Token(wallet_core)
                    .send_transfer_transaction_shielded_owned_account(
                        sender.expect("sender set during Send dispatch"),
                        recipient_account_id,
                        balance_to_move,
                    )
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let LeeTransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![Decode(secret_recipient, recipient_account_id)];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data()?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::BurnTokenShielded {
                definition_account_id,
                holder_account_id,
                amount,
            } => {
                let (tx_hash, secret_holder) = Token(wallet_core)
                    .send_burn_transaction_shielded(
                        definition_account_id,
                        holder_account_id,
                        amount,
                    )
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let LeeTransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![Decode(secret_holder, holder_account_id)];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data()?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::MintTokenShieldedOwned {
                definition_account_id,
                holder_account_id,
                amount,
            } => {
                let (tx_hash, secret_holder) = Token(wallet_core)
                    .send_mint_transaction_shielded_owned_account(
                        definition_account_id,
                        holder_account_id,
                        amount,
                    )
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let LeeTransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![Decode(secret_holder, holder_account_id)];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data()?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::MintTokenShieldedForeign {
                definition_account_id,
                holder_npk,
                holder_vpk,
                holder_identifier,
                amount,
            } => {
                let holder_npk_res = hex::decode(holder_npk)?;
                let mut holder_npk = [0; 32];
                holder_npk.copy_from_slice(&holder_npk_res);
                let holder_npk = lee_core::NullifierPublicKey(holder_npk);

                let holder_vpk_res = hex::decode(&holder_vpk).context(
                    "wallet::cli::programs::token: holder_vpk must be a valid hex string",
                )?;
                let holder_vpk = lee_core::encryption::ViewingPublicKey::from_bytes(holder_vpk_res)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;

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

                if let LeeTransaction::PrivacyPreserving(tx) = transfer_tx {
                    println!("Transaction data is {:?}", tx.message);
                }

                wallet_core.store_persistent_data()?;

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

                if let LeeTransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![
                        Decode(secret_definition, definition_account_id),
                        Decode(secret_supply, supply_account_id),
                    ];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data()?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::NewPrivateDefPublicSupp {
                definition_account_id,
                supply_account_id,
                name,
                total_supply,
            } => {
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

                if let LeeTransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![Decode(secret_definition, definition_account_id)];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data()?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::NewPublicDefPrivateSupp {
                definition_account_id,
                supply_account_id,
                name,
                total_supply,
            } => {
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

                if let LeeTransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![Decode(secret_supply, supply_account_id)];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data()?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::NewPublicDefPublicSupp {
                definition_account_id,
                supply_account_id,
                name,
                total_supply,
            } => {
                let definition = definition_account_id.resolve(wallet_core.storage())?;
                let supply = supply_account_id.resolve(wallet_core.storage())?;
                let (AccountIdWithPrivacy::Public(def_id), AccountIdWithPrivacy::Public(sup_id)) =
                    (definition, supply)
                else {
                    anyhow::bail!("`NewPublicDefPublicSupp`: unexpected private account received.");
                };
                let tx_hash = Token(wallet_core)
                    .send_new_definition(
                        definition_account_id.into_public_identity(def_id),
                        supply_account_id.into_public_identity(sup_id),
                        name,
                        total_supply,
                    )
                    .await?;
                println!("Transaction hash is {tx_hash}");
                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;
                println!("Transaction data is {transfer_tx:?}");
                wallet_core.store_persistent_data()?;
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
