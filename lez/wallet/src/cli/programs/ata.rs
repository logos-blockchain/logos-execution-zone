use anyhow::Result;
use clap::Subcommand;
use lee::AccountId;
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

impl AtaSubcommand {
    fn handle_address(
        owner: AccountId,
        token_definition: AccountId,
        _wallet_core: &WalletCore,
    ) -> SubcommandReturnValue {
        let ata_program_id = programs::ata().id();
        let ata_id = associated_token_account_core::get_associated_token_account_id(
            &ata_program_id,
            &associated_token_account_core::compute_ata_seed(owner, token_definition),
        );
        println!("{ata_id}");
        SubcommandReturnValue::Empty
    }

    async fn handle_create(
        owner: CliAccountMention,
        token_definition: AccountId,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let owner_resolved = owner.resolve(wallet_core.storage())?;
        let definition_id = token_definition;

        match owner_resolved {
            AccountIdWithPrivacy::Public(owner_id) => {
                let tx_hash = Ata(wallet_core)
                    .send_create(owner.into_public_identity(owner_id, true), definition_id)
                    .await?;
                wallet_core
                    .poll_and_finalize_public_transaction(tx_hash)
                    .await
            }
            AccountIdWithPrivacy::Private(owner_id) => {
                let (tx_hash, secret) = Ata(wallet_core)
                    .send_create_private_owner(owner_id, definition_id)
                    .await?;

                wallet_core
                    .poll_and_finalize_pp_transaction(tx_hash, &[Decode(secret, owner_id)])
                    .await
            }
        }
    }

    async fn handle_send(
        from: CliAccountMention,
        token_definition: AccountId,
        to: AccountId,
        amount: u128,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let from_resolved = from.resolve(wallet_core.storage())?;
        let definition_id = token_definition;
        let to_id = to;

        match from_resolved {
            AccountIdWithPrivacy::Public(from_id) => {
                let tx_hash = Ata(wallet_core)
                    .send_transfer(
                        from.into_public_identity(from_id, true),
                        definition_id,
                        to_id,
                        amount,
                    )
                    .await?;
                wallet_core
                    .poll_and_finalize_public_transaction(tx_hash)
                    .await
            }
            AccountIdWithPrivacy::Private(from_id) => {
                let (tx_hash, secret) = Ata(wallet_core)
                    .send_transfer_private_owner(from_id, definition_id, to_id, amount)
                    .await?;

                wallet_core
                    .poll_and_finalize_pp_transaction(tx_hash, &[Decode(secret, from_id)])
                    .await
            }
        }
    }

    async fn handle_burn(
        holder: CliAccountMention,
        token_definition: AccountId,
        amount: u128,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let holder_resolved = holder.resolve(wallet_core.storage())?;
        let definition_id = token_definition;

        match holder_resolved {
            AccountIdWithPrivacy::Public(holder_id) => {
                let tx_hash = Ata(wallet_core)
                    .send_burn(
                        holder.into_public_identity(holder_id, true),
                        definition_id,
                        amount,
                    )
                    .await?;
                wallet_core
                    .poll_and_finalize_public_transaction(tx_hash)
                    .await
            }
            AccountIdWithPrivacy::Private(holder_id) => {
                let (tx_hash, secret) = Ata(wallet_core)
                    .send_burn_private_owner(holder_id, definition_id, amount)
                    .await?;

                wallet_core
                    .poll_and_finalize_pp_transaction(tx_hash, &[Decode(secret, holder_id)])
                    .await
            }
        }
    }

    async fn handle_list(
        owner: AccountId,
        token_definition: Vec<AccountId>,
        wallet_core: &WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let ata_program_id = programs::ata().id();
        let token_program_id = programs::token().id();

        for def in &token_definition {
            let ata_id = associated_token_account_core::get_associated_token_account_id(
                &ata_program_id,
                &associated_token_account_core::compute_ata_seed(owner, *def),
            );
            let account = wallet_core.get_account_public(ata_id).await?;

            // A slot with no data holds no token: a stranger's bare credit brings the slot
            // into existence without ever writing a holding. Same rule as `token::close`.
            if account.data(token_program_id).is_empty() {
                println!("No ATA for definition {def}");
            } else {
                let holding = TokenHolding::try_from(account.data(token_program_id))?;
                match holding {
                    TokenHolding::Fungible { balance, .. } => {
                        println!("ATA {ata_id} (definition {def}): balance {balance}");
                    }
                    TokenHolding::NftMaster { .. } | TokenHolding::NftPrintedCopy { .. } => {
                        println!("ATA {ata_id} (definition {def}): unsupported token type");
                    }
                }
            }
        }

        Ok(SubcommandReturnValue::Empty)
    }
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
            } => Ok(Self::handle_address(owner, token_definition, wallet_core)),
            Self::Create {
                owner,
                token_definition,
            } => Self::handle_create(owner, token_definition, wallet_core).await,
            Self::Send {
                from,
                token_definition,
                to,
                amount,
            } => Self::handle_send(from, token_definition, to, amount, wallet_core).await,
            Self::Burn {
                holder,
                token_definition,
                amount,
            } => Self::handle_burn(holder, token_definition, amount, wallet_core).await,
            Self::List {
                owner,
                token_definition,
            } => Self::handle_list(owner, token_definition, wallet_core).await,
        }
    }
}
