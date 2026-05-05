use anyhow::Result;
use clap::Subcommand;
use common::transaction::NSSATransaction;
use nssa::AccountId;

use crate::{
    AccDecodeData::Decode,
    WalletCore,
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
    },
}

impl WalletSubcommand for AuthTransferSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::Init { account_id } => {
                let resolved = account_id.resolve(wallet_core.storage())?;
                match resolved {
                    AccountIdWithPrivacy::Public(account_id) => {
                        let tx_hash = NativeTokenTransfer(wallet_core)
                            .register_account(account_id)
                            .await?;

                        println!("Transaction hash is {tx_hash}");

                        let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                        println!("Transaction data is {transfer_tx:?}");

                        wallet_core.store_persistent_data()?;
                    }
                    AccountIdWithPrivacy::Private(account_id) => {
                        let (tx_hash, secret) = NativeTokenTransfer(wallet_core)
                            .register_account_private(account_id)
                            .await?;

                        println!("Transaction hash is {tx_hash}");

                        let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                        if let NSSATransaction::PrivacyPreserving(tx) = transfer_tx {
                            let acc_decode_data = vec![Decode(secret, account_id)];

                            wallet_core.decode_insert_privacy_preserving_transaction_results(
                                &tx,
                                &acc_decode_data,
                            )?;
                        }

                        wallet_core.store_persistent_data()?;
                    }
                }

                Ok(SubcommandReturnValue::Empty)
            }
            Self::Send {
                from,
                to,
                to_npk,
                to_vpk,
                to_identifier,
                amount,
            } => {
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
                        (AccountIdWithPrivacy::Public(from), AccountIdWithPrivacy::Public(to)) => {
                            NativeTokenTransferProgramSubcommand::Public { from, to, amount }
                        }
                        (
                            AccountIdWithPrivacy::Private(from),
                            AccountIdWithPrivacy::Private(to),
                        ) => NativeTokenTransferProgramSubcommand::Private(
                            NativeTokenTransferProgramSubcommandPrivate::PrivateOwned {
                                from,
                                to,
                                amount,
                            },
                        ),
                        (AccountIdWithPrivacy::Private(from), AccountIdWithPrivacy::Public(to)) => {
                            NativeTokenTransferProgramSubcommand::Deshielded { from, to, amount }
                        }
                        (AccountIdWithPrivacy::Public(from), AccountIdWithPrivacy::Private(to)) => {
                            NativeTokenTransferProgramSubcommand::Shielded(
                                NativeTokenTransferProgramSubcommandShielded::ShieldedOwned {
                                    from,
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
                                    from,
                                    to_npk,
                                    to_vpk,
                                    to_identifier,
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

/// Represents generic CLI subcommand for a wallet working with native token transfer program.
#[derive(Subcommand, Debug, Clone)]
pub enum NativeTokenTransferProgramSubcommand {
    /// Send native token transfer from `from` to `to` for `amount`.
    ///
    /// Public operation.
    Public {
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
    /// Shielded operation.
    ShieldedForeign {
        /// from - valid 32 byte hex string.
        #[arg(long)]
        from: AccountId,
        /// `to_npk` - valid 32 byte hex string.
        #[arg(long)]
        to_npk: String,
        /// `to_vpk` - valid 33 byte hex string.
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
        /// `to_vpk` - valid 33 byte hex string.
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

impl WalletSubcommand for NativeTokenTransferProgramSubcommandPrivate {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::PrivateOwned { from, to, amount } => {
                let (tx_hash, [secret_from, secret_to]) = NativeTokenTransfer(wallet_core)
                    .send_private_transfer_to_owned_account(from, to, amount)
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let NSSATransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![Decode(secret_from, from), Decode(secret_to, to)];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data()?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::PrivateForeign {
                from,
                to_npk,
                to_vpk,
                to_identifier,
                amount,
            } => {
                let to_npk_res = hex::decode(to_npk)?;
                let mut to_npk = [0; 32];
                to_npk.copy_from_slice(&to_npk_res);
                let to_npk = nssa_core::NullifierPublicKey(to_npk);

                let to_vpk_res = hex::decode(to_vpk)?;
                let mut to_vpk = [0_u8; 33];
                to_vpk.copy_from_slice(&to_vpk_res);
                let to_vpk =
                    nssa_core::encryption::shared_key_derivation::Secp256k1Point(to_vpk.to_vec());

                let (tx_hash, [secret_from, _]) = NativeTokenTransfer(wallet_core)
                    .send_private_transfer_to_outer_account(
                        from,
                        to_npk,
                        to_vpk,
                        to_identifier.unwrap_or_else(rand::random),
                        amount,
                    )
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let NSSATransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![Decode(secret_from, from)];

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

impl WalletSubcommand for NativeTokenTransferProgramSubcommandShielded {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::ShieldedOwned { from, to, amount } => {
                let (tx_hash, secret) = NativeTokenTransfer(wallet_core)
                    .send_shielded_transfer(from, to, amount)
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let NSSATransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![Decode(secret, to)];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data()?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::ShieldedForeign {
                from,
                to_npk,
                to_vpk,
                to_identifier,
                amount,
            } => {
                let to_npk_res = hex::decode(to_npk)?;
                let mut to_npk = [0; 32];
                to_npk.copy_from_slice(&to_npk_res);
                let to_npk = nssa_core::NullifierPublicKey(to_npk);

                let to_vpk_res = hex::decode(to_vpk)?;
                let mut to_vpk = [0_u8; 33];
                to_vpk.copy_from_slice(&to_vpk_res);
                let to_vpk =
                    nssa_core::encryption::shared_key_derivation::Secp256k1Point(to_vpk.to_vec());

                let (tx_hash, _) = NativeTokenTransfer(wallet_core)
                    .send_shielded_transfer_to_outer_account(
                        from,
                        to_npk,
                        to_vpk,
                        to_identifier.unwrap_or_else(rand::random),
                        amount,
                    )
                    .await?;

                println!("Transaction hash is {tx_hash}");

                wallet_core.store_persistent_data()?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
        }
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
                let (tx_hash, secret) = NativeTokenTransfer(wallet_core)
                    .send_deshielded_transfer(from, to, amount)
                    .await?;

                println!("Transaction hash is {tx_hash}");

                let transfer_tx = wallet_core.poll_native_token_transfer(tx_hash).await?;

                if let NSSATransaction::PrivacyPreserving(tx) = transfer_tx {
                    let acc_decode_data = vec![Decode(secret, from)];

                    wallet_core.decode_insert_privacy_preserving_transaction_results(
                        &tx,
                        &acc_decode_data,
                    )?;
                }

                wallet_core.store_persistent_data()?;

                Ok(SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash })
            }
            Self::Public { from, to, amount } => {
                let tx_hash = NativeTokenTransfer(wallet_core)
                    .send_public_transfer(from, to, amount)
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
