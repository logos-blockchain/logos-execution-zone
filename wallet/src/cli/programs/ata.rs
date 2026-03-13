use anyhow::Result;
use clap::Subcommand;
use nssa::{Account, AccountId, program::Program};
use token_core::TokenHolding;

use crate::{
    WalletCore,
    cli::{SubcommandReturnValue, WalletSubcommand},
    helperfunctions::{AccountPrivacyKind, parse_addr_with_privacy_prefix},
    program_facades::ata::Ata,
};

/// Represents generic CLI subcommand for a wallet working with the ATA program
#[derive(Subcommand, Debug, Clone)]
pub enum AtaSubcommand {
    /// Derive and print the Associated Token Account address (local only, no network)
    Address {
        /// Owner account - valid 32 byte base58 string (no privacy prefix)
        #[arg(long)]
        owner: String,
        /// Token definition account - valid 32 byte base58 string (no privacy prefix)
        #[arg(long)]
        token_definition: String,
    },
    /// Create (or idempotently no-op) the Associated Token Account
    ///
    /// Only public execution allowed
    Create {
        /// Owner account - valid 32 byte base58 string with privacy prefix
        #[arg(long)]
        owner: String,
        /// Token definition account - valid 32 byte base58 string WITHOUT privacy prefix
        #[arg(long)]
        token_definition: String,
    },
    /// Send tokens from owner's ATA to a recipient
    ///
    /// Only public execution allowed
    Send {
        /// Sender account - valid 32 byte base58 string with privacy prefix
        #[arg(long)]
        from: String,
        /// Token definition account - valid 32 byte base58 string WITHOUT privacy prefix
        #[arg(long)]
        token_definition: String,
        /// Recipient account - valid 32 byte base58 string WITHOUT privacy prefix
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u128,
    },
    /// Burn tokens from holder's ATA
    ///
    /// Only public execution allowed
    Burn {
        /// Holder account - valid 32 byte base58 string with privacy prefix
        #[arg(long)]
        holder: String,
        /// Token definition account - valid 32 byte base58 string WITHOUT privacy prefix
        #[arg(long)]
        token_definition: String,
        #[arg(long)]
        amount: u128,
    },
    /// List all ATAs for a given owner across multiple token definitions
    List {
        /// Owner account - valid 32 byte base58 string (no privacy prefix)
        #[arg(long)]
        owner: String,
        /// Token definition accounts - valid 32 byte base58 strings (no privacy prefix)
        #[arg(long, num_args = 1..)]
        token_definition: Vec<String>,
    },
}

impl WalletSubcommand for AtaSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            AtaSubcommand::Address {
                owner,
                token_definition,
            } => {
                let owner_id: AccountId = owner.parse()?;
                let definition_id: AccountId = token_definition.parse()?;
                let ata_program_id = Program::ata().id();
                let ata_id = ata_core::get_associated_token_account_id(
                    &ata_program_id,
                    owner_id,
                    definition_id,
                );
                println!("{ata_id}");
                Ok(SubcommandReturnValue::Empty)
            }
            AtaSubcommand::Create {
                owner,
                token_definition,
            } => {
                let (owner_str, owner_privacy) = parse_addr_with_privacy_prefix(&owner)?;
                let owner_id: AccountId = owner_str.parse()?;
                let definition_id: AccountId = token_definition.parse()?;

                match owner_privacy {
                    AccountPrivacyKind::Public => {
                        Ata(wallet_core)
                            .send_create(owner_id, definition_id)
                            .await?;
                        Ok(SubcommandReturnValue::Empty)
                    }
                    _ => {
                        anyhow::bail!("Only public execution allowed for ATA calls");
                    }
                }
            }
            AtaSubcommand::Send {
                from,
                token_definition,
                to,
                amount,
            } => {
                let (from_str, from_privacy) = parse_addr_with_privacy_prefix(&from)?;
                let from_id: AccountId = from_str.parse()?;
                let definition_id: AccountId = token_definition.parse()?;
                let to_id: AccountId = to.parse()?;

                match from_privacy {
                    AccountPrivacyKind::Public => {
                        Ata(wallet_core)
                            .send_transfer(from_id, definition_id, to_id, amount)
                            .await?;
                        Ok(SubcommandReturnValue::Empty)
                    }
                    _ => {
                        anyhow::bail!("Only public execution allowed for ATA calls");
                    }
                }
            }
            AtaSubcommand::Burn {
                holder,
                token_definition,
                amount,
            } => {
                let (holder_str, holder_privacy) = parse_addr_with_privacy_prefix(&holder)?;
                let holder_id: AccountId = holder_str.parse()?;
                let definition_id: AccountId = token_definition.parse()?;

                match holder_privacy {
                    AccountPrivacyKind::Public => {
                        Ata(wallet_core)
                            .send_burn(holder_id, definition_id, amount)
                            .await?;
                        Ok(SubcommandReturnValue::Empty)
                    }
                    _ => {
                        anyhow::bail!("Only public execution allowed for ATA calls");
                    }
                }
            }
            AtaSubcommand::List {
                owner,
                token_definition,
            } => {
                let owner_id: AccountId = owner.parse()?;
                let ata_program_id = Program::ata().id();

                for def in &token_definition {
                    let definition_id: AccountId = def.parse()?;
                    let ata_id = ata_core::get_associated_token_account_id(
                        &ata_program_id,
                        owner_id,
                        definition_id,
                    );
                    let account = wallet_core.get_account_public(ata_id).await?;

                    if account == Account::default() {
                        println!("No ATA for definition {definition_id}");
                    } else {
                        let holding = TokenHolding::try_from(&account.data)?;
                        match holding {
                            TokenHolding::Fungible { balance, .. } => {
                                println!(
                                    "ATA {ata_id} (definition {definition_id}): balance {balance}"
                                );
                            }
                            _ => {
                                println!(
                                    "ATA {ata_id} (definition {definition_id}): unsupported token type"
                                );
                            }
                        }
                    }
                }

                Ok(SubcommandReturnValue::Empty)
            }
        }
    }
}
