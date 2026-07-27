use anyhow::Result;
use clap::Subcommand;
use lee::AccountId;

use crate::{
    AccDecodeData::Decode,
    AccountIdentity, WalletCore,
    account::AccountIdWithPrivacy,
    cli::{CliAccountMention, SubcommandReturnValue, WalletSubcommand},
    program_facades::native_token_transfer::NativeTokenTransfer,
};

/// Represents generic CLI subcommand for a wallet working with native token transfer program.
#[derive(Subcommand, Debug, Clone)]
pub enum AuthTransferSubcommand {
    /// Initialize account under authenticated transfer program.
    Init {
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        account_id: CliAccountMention,
    },
    /// Send native tokens from one account to another with variable privacy.
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
        /// and vpk on separate lines. Replaces `--to-npk`/`--to-vpk`.
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
}

impl AuthTransferSubcommand {
    async fn handle_init(
        account_id: CliAccountMention,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let resolved = account_id.resolve(wallet_core.storage())?;
        match resolved {
            AccountIdWithPrivacy::Public(pub_account_id) => {
                let tx_hash = NativeTokenTransfer(wallet_core)
                    .register_account(account_id.into_public_identity(pub_account_id))
                    .await?;

                wallet_core
                    .poll_and_finalize_public_transaction(tx_hash)
                    .await
            }
            AccountIdWithPrivacy::Private(account_id) => {
                let (tx_hash, secret) = NativeTokenTransfer(wallet_core)
                    .register_account_private(account_id)
                    .await?;

                wallet_core
                    .poll_and_finalize_pp_transaction(tx_hash, &[Decode(secret, account_id)])
                    .await
            }
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "extracted match arm with many destructured fields"
    )]
    async fn handle_send(
        from_account: CliAccountMention,
        to_account: Option<CliAccountMention>,
        to_npk: Option<String>,
        to_vpk: Option<String>,
        to_keys: Option<String>,
        to_identifier: Option<u128>,
        amount: u128,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        // Resolve --to-keys into --to-npk / --to-vpk equivalents.
        let (to_npk, to_vpk) = if let Some(path) = to_keys {
            let (npk_bytes, vpk_bytes) = crate::cli::read_keys_file(&path)?;
            (Some(hex::encode(npk_bytes)), Some(hex::encode(vpk_bytes)))
        } else {
            (to_npk, to_vpk)
        };

        let from = from_account.resolve(wallet_core.storage())?;
        let to = to_account
            .as_ref()
            .map(|m| m.resolve(wallet_core.storage()))
            .transpose()?;
        let underlying_subcommand = match (to, to_npk, to_vpk) {
            (None, None, None) => {
                anyhow::bail!("Provide either account account_id of receiver or their public keys");
            }
            (Some(to), None, None) => match (from, to) {
                (AccountIdWithPrivacy::Public(from), AccountIdWithPrivacy::Public(to)) => {
                    let to_mention = to_account.expect("matched Some branch");
                    NativeTokenTransferProgramSubcommand::Public {
                        from: Some(from_account.into_public_identity(from)),
                        to: Some(to_mention.into_public_identity(to)),
                        amount,
                    }
                }
                (AccountIdWithPrivacy::Private(from), AccountIdWithPrivacy::Private(to)) => {
                    NativeTokenTransferProgramSubcommand::Private(
                        NativeTokenTransferProgramSubcommandPrivate::PrivateOwned {
                            from,
                            to,
                            amount,
                        },
                    )
                }
                (AccountIdWithPrivacy::Private(from), AccountIdWithPrivacy::Public(to)) => {
                    NativeTokenTransferProgramSubcommand::Deshielded { from, to, amount }
                }
                (AccountIdWithPrivacy::Public(from), AccountIdWithPrivacy::Private(to)) => {
                    NativeTokenTransferProgramSubcommand::Shielded(
                        NativeTokenTransferProgramSubcommandShielded::ShieldedOwned {
                            from: Some(from_account.into_public_identity(from)),
                            to,
                            amount,
                        },
                    )
                }
            },
            (None, Some(to_npk), Some(to_vpk)) => match from {
                AccountIdWithPrivacy::Private(from) => {
                    NativeTokenTransferProgramSubcommand::Private(
                        NativeTokenTransferProgramSubcommandPrivate::PrivateForeign {
                            from,
                            to_npk,
                            to_vpk,
                            to_identifier,
                            amount,
                        },
                    )
                }
                AccountIdWithPrivacy::Public(from) => {
                    NativeTokenTransferProgramSubcommand::Shielded(
                        NativeTokenTransferProgramSubcommandShielded::ShieldedForeign {
                            from: Some(from_account.into_public_identity(from)),
                            to_npk,
                            to_vpk,
                            to_identifier,
                            amount,
                        },
                    )
                }
            },
            (Some(_), _, _) => {
                anyhow::bail!(
                    "Provide only one variant: either account account_id of receiver or their public keys"
                );
            }
            _ => {
                anyhow::bail!("List of public keys is uncomplete");
            }
        };

        underlying_subcommand.handle_subcommand(wallet_core).await
    }
}

impl WalletSubcommand for AuthTransferSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::Init { account_id } => Self::handle_init(account_id, wallet_core).await,
            Self::Send {
                from,
                to,
                to_npk,
                to_vpk,
                to_keys,
                to_identifier,
                amount,
            } => {
                Self::handle_send(
                    from,
                    to,
                    to_npk,
                    to_vpk,
                    to_keys,
                    to_identifier,
                    amount,
                    wallet_core,
                )
                .await
            }
        }
    }
}

/// Represents generic CLI subcommand for a wallet working with native token transfer program.
#[derive(Subcommand, Debug, Clone)]
pub enum NativeTokenTransferProgramSubcommand {
    /// Send native token transfer from `from` to `to` for `amount`.
    ///
    /// Public operation.
    Public {
        #[arg(skip)]
        from: Option<AccountIdentity>,
        #[arg(skip)]
        to: Option<AccountIdentity>,
        /// amount - amount of balance to move.
        #[arg(long)]
        amount: u128,
    },
    /// Private execution.
    #[command(subcommand)]
    Private(NativeTokenTransferProgramSubcommandPrivate),
    /// Send native token transfer from `from` to `to` for `amount`.
    ///
    /// Deshielded operation.
    Deshielded {
        /// from - valid 32 byte hex string.
        #[arg(long)]
        from: AccountId,
        /// to - valid 32 byte hex string.
        #[arg(long)]
        to: AccountId,
        /// amount - amount of balance to move.
        #[arg(long)]
        amount: u128,
    },
    /// Shielded execution.
    #[command(subcommand)]
    Shielded(NativeTokenTransferProgramSubcommandShielded),
}

/// Represents generic shielded CLI subcommand for a wallet working with native token transfer
/// program.
#[derive(Subcommand, Debug, Clone)]
pub enum NativeTokenTransferProgramSubcommandShielded {
    /// Send native token transfer from `from` to `to` for `amount`.
    ///
    /// Shielded operation.
    ShieldedOwned {
        /// from - valid 32 byte hex string.
        #[arg(skip)]
        from: Option<AccountIdentity>,
        /// to - valid 32 byte hex string.
        #[arg(long)]
        to: AccountId,
        /// amount - amount of balance to move.
        #[arg(long)]
        amount: u128,
    },
    /// Send native token transfer from `from` to `to` for `amount`.
    ///
    /// Shielded operation.
    ShieldedForeign {
        #[arg(skip)]
        from: Option<AccountIdentity>,
        /// `to_npk` - valid 32 byte hex string.
        #[arg(long)]
        to_npk: String,
        #[arg(long)]
        /// `to_vpk` - valid hex-encoded ML-KEM-768 encapsulation key (1184 bytes).
        #[arg(long)]
        to_vpk: String,
        /// Identifier for the recipient's private account.
        #[arg(long)]
        to_identifier: Option<u128>,
        /// amount - amount of balance to move.
        #[arg(long)]
        amount: u128,
    },
}

/// Represents generic private CLI subcommand for a wallet working with native token transfer
/// program.
#[derive(Subcommand, Debug, Clone)]
pub enum NativeTokenTransferProgramSubcommandPrivate {
    /// Send native token transfer from `from` to `to` for `amount`.
    ///
    /// Private operation.
    PrivateOwned {
        /// from - valid 32 byte hex string.
        #[arg(long)]
        from: AccountId,
        /// to - valid 32 byte hex string.
        #[arg(long)]
        to: AccountId,
        /// amount - amount of balance to move.
        #[arg(long)]
        amount: u128,
    },
    /// Send native token transfer from `from` to `to` for `amount`.
    ///
    /// Private operation.
    PrivateForeign {
        /// from - valid 32 byte hex string.
        #[arg(long)]
        from: AccountId,
        /// `to_npk` - valid 32 byte hex string.
        #[arg(long)]
        to_npk: String,
        #[arg(long)]
        /// `to_vpk` - valid hex-encoded ML-KEM-768 encapsulation key (1184 bytes).
        #[arg(long)]
        to_vpk: String,
        /// Identifier for the recipient's private account.
        #[arg(long)]
        to_identifier: Option<u128>,
        /// amount - amount of balance to move.
        #[arg(long)]
        amount: u128,
    },
}

impl NativeTokenTransferProgramSubcommandPrivate {
    async fn handle_private_owned(
        from: AccountId,
        to: AccountId,
        amount: u128,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let (tx_hash, [secret_from, secret_to]) = NativeTokenTransfer(wallet_core)
            .send_private_transfer_to_owned_account(from, to, amount)
            .await?;

        wallet_core
            .poll_and_finalize_pp_transaction(
                tx_hash,
                &[Decode(secret_from, from), Decode(secret_to, to)],
            )
            .await
    }

    async fn handle_private_foreign(
        from: AccountId,
        to_npk: String,
        to_vpk: String,
        to_identifier: Option<u128>,
        amount: u128,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let (to_npk, to_vpk) = crate::cli::decode_npk_vpk(&to_npk, &to_vpk)?;

        let (tx_hash, [secret_from, _]) = NativeTokenTransfer(wallet_core)
            .send_private_transfer_to_outer_account(
                from,
                to_npk,
                to_vpk,
                to_identifier.unwrap_or_else(rand::random),
                amount,
            )
            .await?;

        wallet_core
            .poll_and_finalize_pp_transaction(tx_hash, &[Decode(secret_from, from)])
            .await
    }
}

impl WalletSubcommand for NativeTokenTransferProgramSubcommandPrivate {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::PrivateOwned { from, to, amount } => {
                Self::handle_private_owned(from, to, amount, wallet_core).await
            }
            Self::PrivateForeign {
                from,
                to_npk,
                to_vpk,
                to_identifier,
                amount,
            } => {
                Self::handle_private_foreign(
                    from,
                    to_npk,
                    to_vpk,
                    to_identifier,
                    amount,
                    wallet_core,
                )
                .await
            }
        }
    }
}

impl NativeTokenTransferProgramSubcommandShielded {
    async fn handle_shielded_owned(
        from: Option<AccountIdentity>,
        to: AccountId,
        amount: u128,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let (tx_hash, secret) = NativeTokenTransfer(wallet_core)
            .send_shielded_transfer(from.expect("from set during Send dispatch"), to, amount)
            .await?;

        wallet_core
            .poll_and_finalize_pp_transaction(tx_hash, &[Decode(secret, to)])
            .await
    }

    async fn handle_shielded_foreign(
        from: Option<AccountIdentity>,
        to_npk: String,
        to_vpk: String,
        to_identifier: Option<u128>,
        amount: u128,
        wallet_core: &WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let (to_npk, to_vpk) = crate::cli::decode_npk_vpk(&to_npk, &to_vpk)?;

        let (tx_hash, _) = NativeTokenTransfer(wallet_core)
            .send_shielded_transfer_to_outer_account(
                from.expect("from set during Send dispatch"),
                to_npk,
                to_vpk,
                to_identifier.unwrap_or_else(rand::random),
                amount,
            )
            .await?;

        println!("Transaction hash is {tx_hash}");

        wallet_core.store_persistent_data()?;

        Ok(SubcommandReturnValue::TransactionExecuted { tx_hash })
    }
}

impl WalletSubcommand for NativeTokenTransferProgramSubcommandShielded {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::ShieldedOwned { from, to, amount } => {
                Self::handle_shielded_owned(from, to, amount, wallet_core).await
            }
            Self::ShieldedForeign {
                from,
                to_npk,
                to_vpk,
                to_identifier,
                amount,
            } => {
                Self::handle_shielded_foreign(
                    from,
                    to_npk,
                    to_vpk,
                    to_identifier,
                    amount,
                    wallet_core,
                )
                .await
            }
        }
    }
}

impl NativeTokenTransferProgramSubcommand {
    async fn handle_deshielded(
        from: AccountId,
        to: AccountId,
        amount: u128,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let (tx_hash, secret) = NativeTokenTransfer(wallet_core)
            .send_deshielded_transfer(from, to, amount)
            .await?;

        wallet_core
            .poll_and_finalize_pp_transaction(tx_hash, &[Decode(secret, from)])
            .await
    }

    async fn handle_public(
        from: Option<AccountIdentity>,
        to: Option<AccountIdentity>,
        amount: u128,
        wallet_core: &WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let tx_hash = NativeTokenTransfer(wallet_core)
            .send_public_transfer(
                from.expect("from is set during Send dispatch"),
                to.expect("to is set during Send dispatch"),
                amount,
            )
            .await?;

        wallet_core
            .poll_and_finalize_public_transaction(tx_hash)
            .await
    }
}

impl WalletSubcommand for NativeTokenTransferProgramSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::Private(private_subcommand) => {
                private_subcommand.handle_subcommand(wallet_core).await
            }
            Self::Shielded(shielded_subcommand) => {
                shielded_subcommand.handle_subcommand(wallet_core).await
            }
            Self::Deshielded { from, to, amount } => {
                Self::handle_deshielded(from, to, amount, wallet_core).await
            }
            Self::Public { from, to, amount } => {
                Self::handle_public(from, to, amount, wallet_core).await
            }
        }
    }
}
