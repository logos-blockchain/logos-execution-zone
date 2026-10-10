use anyhow::Result;
use clap::Subcommand;
use lee::{AccountId, Actor};
use token_core::TokenHolding;

use crate::{
    WalletCore,
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
        let ata_program_id = programs::ata_account_id();
        let token_program_id = programs::token_account_id();
        let ata_id = associated_token_account_core::get_associated_token_account_id(
            &ata_program_id,
            &associated_token_account_core::compute_ata_seed(
                owner,
                token_definition,
                token_program_id,
            ),
        );
        println!("{ata_id}");
        SubcommandReturnValue::Empty
    }

    async fn handle_list(
        owner: AccountId,
        token_definition: Vec<AccountId>,
        wallet_core: &WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let ata_program_id = programs::ata_account_id();
        let token_program_id = programs::token_account_id();

        for def in &token_definition {
            let ata_id = associated_token_account_core::get_associated_token_account_id(
                &ata_program_id,
                &associated_token_account_core::compute_ata_seed(owner, *def, token_program_id),
            );
            let account = wallet_core
                .get_account_view(Actor::new(ata_id, token_program_id))
                .await?
                .unwrap_or_default();
            let holding = account.data.actor_state(token_program_id);

            if holding.is_empty() {
                println!("No ATA for definition {def}");
            } else {
                let holding = TokenHolding::try_from(holding)?;
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
            } => {
                let owner = owner.signer(wallet_core.storage())?;
                let (tx_hash, _) = Ata(wallet_core).create(owner, token_definition).await?;
                wallet_core.finish_transaction(tx_hash).await
            }
            Self::Send {
                from,
                token_definition,
                to,
                amount,
            } => {
                let owner = from.signer(wallet_core.storage())?;
                let (tx_hash, _) = Ata(wallet_core)
                    .transfer(owner, token_definition, to, amount)
                    .await?;
                wallet_core.finish_transaction(tx_hash).await
            }
            Self::Burn {
                holder,
                token_definition,
                amount,
            } => {
                let owner = holder.signer(wallet_core.storage())?;
                let (tx_hash, _) = Ata(wallet_core)
                    .burn(owner, token_definition, amount)
                    .await?;
                wallet_core.finish_transaction(tx_hash).await
            }
            Self::List {
                owner,
                token_definition,
            } => Self::handle_list(owner, token_definition, wallet_core).await,
        }
    }
}
