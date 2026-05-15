use anyhow::Result;
use clap::Subcommand;
use common::transaction::NSSATransaction;
use nssa::{Account, AccountId, program::Program};
use token_core::TokenHolding;

use crate::{
    AccDecodeData::Decode,
    WalletCore,
    account::AccountIdWithPrivacy,
    cli::{CliAccountMention, SubcommandReturnValue, WalletSubcommand},
    program_facades::ata::Ata,
};

/// Represents generic CLI subcommand for a wallet working with the ATA program.
#[derive(Subcommand, Debug, Clone)]
pub enum AtaSubcommand {
    /// Derive and print the Associated Token Account address (local only, no network).
    Address {
        /// Owner account - valid 32 byte base58 string (no privacy prefix).
        #[arg(long)]
        owner: AccountId,
        /// Token definition account - valid 32 byte base58 string (no privacy prefix).
        #[arg(long)]
        token_definition: AccountId,
    },
    /// Create (or idempotently no-op) the Associated Token Account.
    Create {
        /// Owner account mention - account id with privacy prefix or label.
        #[arg(long)]
        owner: CliAccountMention,
        /// Token definition account - valid 32 byte base58 string WITHOUT privacy prefix.
        #[arg(long)]
        token_definition: AccountId,
    },
    /// Send tokens from owner's ATA to a recipient token holding account.
    Send {
        /// Sender account mention - account id with privacy prefix or label.
        #[arg(long)]
        from: CliAccountMention,
        /// Token definition account - valid 32 byte base58 string WITHOUT privacy prefix.
        #[arg(long)]
        token_definition: AccountId,
        /// Recipient account - valid 32 byte base58 string WITHOUT privacy prefix.
        #[arg(long)]
        to: AccountId,
        #[arg(long)]
        amount: u128,
    },
    /// Burn tokens from holder's ATA.
    Burn {
        /// Holder account mention - account id with privacy prefix or label.
        #[arg(long)]
        holder: CliAccountMention,
        /// Token definition account - valid 32 byte base58 string WITHOUT privacy prefix.
        #[arg(long)]
        token_definition: AccountId,
        #[arg(long)]
        amount: u128,
    },
    /// List all ATAs for a given owner across multiple token definitions.
    List {
        /// Owner account - valid 32 byte base58 string (no privacy prefix).
        #[arg(long)]
        owner: AccountId,
        /// Token definition accounts - valid 32 byte base58 strings (no privacy prefix).
        #[arg(long, num_args = 1..)]
        token_definition: Vec<AccountId>,
    },
}

impl WalletSubcommand for AtaSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::Address {
                owner,
                token_definition,
            } => {
                let ata_program_id = Program::ata().id();
                let ata_id = ata_core::get_associated_token_account_id(
                    &ata_program_id,
                    &ata_core::compute_ata_seed(owner, token_definition),
                );
                println!("{ata_id}");
                Ok(SubcommandReturnValue::Empty)
            }
            Self::Create {
                owner,
                token_definition,
            } => {
                let owner = owner.resolve(wallet_core.storage())?;
                let definition_id = token_definition;

                match owner {
                    AccountIdWithPrivacy::Public(owner_id) => {
                        Ata(wallet_core)
                            .send_create(owner_id, definition_id)
                            .await?;
                        Ok(SubcommandReturnValue::Empty)
                    }
                    AccountIdWithPrivacy::Private(owner_id) => {
                        let (tx_hash, secret) = Ata(wallet_core)
                            .send_create_private_owner(owner_id, definition_id)
                            .await?;

                        println!("Transaction hash is {tx_hash}");

                        let tx = wallet_core.poll_native_token_transfer(tx_hash).await?;
                        if let NSSATransaction::PrivacyPreserving(tx) = tx {
                            wallet_core.decode_insert_privacy_preserving_transaction_results(
                                &tx,
                                &[Decode(secret, owner_id)],
                            )?;
                        }

                        wallet_core.store_persistent_data()?;
                        Ok(SubcommandReturnValue::Empty)
                    }
                }
            }
            Self::Send {
                from,
                token_definition,
                to,
                amount,
            } => {
                let from = from.resolve(wallet_core.storage())?;
                let definition_id = token_definition;
                let to_id = to;

                match from {
                    AccountIdWithPrivacy::Public(from_id) => {
                        Ata(wallet_core)
                            .send_transfer(from_id, definition_id, to_id, amount)
                            .await?;
                        Ok(SubcommandReturnValue::Empty)
                    }
                    AccountIdWithPrivacy::Private(from_id) => {
                        let (tx_hash, secret) = Ata(wallet_core)
                            .send_transfer_private_owner(from_id, definition_id, to_id, amount)
                            .await?;

                        println!("Transaction hash is {tx_hash}");

                        let tx = wallet_core.poll_native_token_transfer(tx_hash).await?;
                        if let NSSATransaction::PrivacyPreserving(tx) = tx {
                            wallet_core.decode_insert_privacy_preserving_transaction_results(
                                &tx,
                                &[Decode(secret, from_id)],
                            )?;
                        }

                        wallet_core.store_persistent_data()?;
                        Ok(SubcommandReturnValue::Empty)
                    }
                }
            }
            Self::Burn {
                holder,
                token_definition,
                amount,
            } => {
                let holder = holder.resolve(wallet_core.storage())?;
                let definition_id = token_definition;

                match holder {
                    AccountIdWithPrivacy::Public(holder_id) => {
                        Ata(wallet_core)
                            .send_burn(holder_id, definition_id, amount)
                            .await?;
                        Ok(SubcommandReturnValue::Empty)
                    }
                    AccountIdWithPrivacy::Private(holder_id) => {
                        let (tx_hash, secret) = Ata(wallet_core)
                            .send_burn_private_owner(holder_id, definition_id, amount)
                            .await?;

                        println!("Transaction hash is {tx_hash}");

                        let tx = wallet_core.poll_native_token_transfer(tx_hash).await?;
                        if let NSSATransaction::PrivacyPreserving(tx) = tx {
                            wallet_core.decode_insert_privacy_preserving_transaction_results(
                                &tx,
                                &[Decode(secret, holder_id)],
                            )?;
                        }

                        wallet_core.store_persistent_data()?;
                        Ok(SubcommandReturnValue::Empty)
                    }
                }
            }
            Self::List {
                owner,
                token_definition,
            } => {
                let ata_program_id = Program::ata().id();

                for def in &token_definition {
                    let ata_id = ata_core::get_associated_token_account_id(
                        &ata_program_id,
                        &ata_core::compute_ata_seed(owner, *def),
                    );
                    let account = wallet_core.get_account_public(ata_id).await?;

                    if account == Account::default() {
                        println!("No ATA for definition {def}");
                    } else {
                        let holding = TokenHolding::try_from(&account.data)?;
                        match holding {
                            TokenHolding::Fungible { balance, .. } => {
                                println!("ATA {ata_id} (definition {def}): balance {balance}");
                            }
                            TokenHolding::NftMaster { .. }
                            | TokenHolding::NftPrintedCopy { .. } => {
                                println!("ATA {ata_id} (definition {def}): unsupported token type");
                            }
                        }
                    }
                }

                Ok(SubcommandReturnValue::Empty)
            }
        }
    }
}
