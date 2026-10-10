use anyhow::Result;
use clap::Subcommand;
use lee::PublicKey;

use crate::{
    WalletCore,
    cli::{CliAccountMention, SubcommandReturnValue, WalletSubcommand, destination},
    program_facades::{CreditDelivery, token::Token},
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
        /// Recipient's public key, for a public account that has not been used yet.
        #[arg(long, conflicts_with_all = ["to", "to_npk", "to_vpk", "to_keys"])]
        to_pk: Option<PublicKey>,
        /// amount - amount of balance to move.
        #[arg(long)]
        amount: u128,
        /// Cast a private recipient's credit as a pending message for a later transaction to
        /// receive, instead of crediting it in this one; a public recipient is credited at once
        /// either way.
        #[arg(long)]
        cast: bool,
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
        let storage = wallet_core.storage();
        let token = Token(wallet_core);
        let (tx_hash, _) = match self {
            Self::New {
                definition_account_id,
                supply_account_id,
                name,
                total_supply,
            } => {
                token
                    .create(
                        definition_account_id.signer(storage)?,
                        supply_account_id.signer(storage)?,
                        name,
                        total_supply,
                    )
                    .await?
            }
            Self::Send {
                from,
                to,
                to_npk,
                to_vpk,
                to_keys,
                to_pk,
                amount,
                cast,
            } => {
                let delivery = if cast {
                    CreditDelivery::DeferredPrivate
                } else {
                    CreditDelivery::Automatic
                };
                token
                    .transfer(
                        from.signer(storage)?,
                        destination(storage, to, to_npk, to_vpk, to_keys, to_pk)?,
                        amount,
                        delivery,
                    )
                    .await?
            }
            Self::Burn {
                definition,
                holder,
                amount,
            } => {
                token
                    .burn(
                        holder.signer(storage)?,
                        definition.unsigned(storage)?,
                        amount,
                    )
                    .await?
            }
            Self::Mint {
                definition,
                holder,
                holder_npk,
                holder_vpk,
                holder_keys,
                amount,
            } => {
                token
                    .mint(
                        definition.signer(storage)?,
                        destination(storage, holder, holder_npk, holder_vpk, holder_keys, None)?,
                        amount,
                        CreditDelivery::Automatic,
                    )
                    .await?
            }
        };
        wallet_core.finish_transaction(tx_hash).await
    }
}
