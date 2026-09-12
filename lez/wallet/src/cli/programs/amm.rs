use anyhow::Result;
use clap::Subcommand;
use lee::AccountId;

use crate::{
    AccountIdentity, WalletCore,
    account::AccountIdWithPrivacy,
    cli::{CliAccountMention, SubcommandReturnValue, WalletSubcommand},
    program_facades::amm::Amm,
};

/// AMM program subcommands. The user's holdings are derived from `user` and the definitions.
///
/// Only public execution is allowed.
#[derive(Subcommand, Debug, Clone)]
pub enum AmmSubcommand {
    /// Produce a new pool.
    New {
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        user: CliAccountMention,
        /// Token definition account - valid 32 byte base58 string WITHOUT privacy prefix.
        #[arg(long)]
        definition_a: AccountId,
        /// Token definition account - valid 32 byte base58 string WITHOUT privacy prefix.
        #[arg(long)]
        definition_b: AccountId,
        #[arg(long)]
        balance_a: u128,
        #[arg(long)]
        balance_b: u128,
    },
    /// Swap specifying exact input amount.
    SwapExactInput {
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        user: CliAccountMention,
        /// Token definition account - valid 32 byte base58 string WITHOUT privacy prefix.
        #[arg(long)]
        definition_in: AccountId,
        /// Token definition account - valid 32 byte base58 string WITHOUT privacy prefix.
        #[arg(long)]
        definition_out: AccountId,
        #[arg(long)]
        amount_in: u128,
        #[arg(long)]
        min_amount_out: u128,
    },
    /// Swap specifying exact output amount.
    SwapExactOutput {
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        user: CliAccountMention,
        /// Token definition account - valid 32 byte base58 string WITHOUT privacy prefix.
        #[arg(long)]
        definition_in: AccountId,
        /// Token definition account - valid 32 byte base58 string WITHOUT privacy prefix.
        #[arg(long)]
        definition_out: AccountId,
        #[arg(long)]
        exact_amount_out: u128,
        #[arg(long)]
        max_amount_in: u128,
    },
    /// Add liquidity. The definitions must be given in the pool's order.
    AddLiquidity {
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        user: CliAccountMention,
        /// Token definition account - valid 32 byte base58 string WITHOUT privacy prefix.
        #[arg(long)]
        definition_a: AccountId,
        /// Token definition account - valid 32 byte base58 string WITHOUT privacy prefix.
        #[arg(long)]
        definition_b: AccountId,
        #[arg(long)]
        min_amount_lp: u128,
        #[arg(long)]
        max_amount_a: u128,
        #[arg(long)]
        max_amount_b: u128,
    },
    /// Remove liquidity. The definitions must be given in the pool's order.
    RemoveLiquidity {
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        user: CliAccountMention,
        /// Token definition account - valid 32 byte base58 string WITHOUT privacy prefix.
        #[arg(long)]
        definition_a: AccountId,
        /// Token definition account - valid 32 byte base58 string WITHOUT privacy prefix.
        #[arg(long)]
        definition_b: AccountId,
        #[arg(long)]
        balance_lp: u128,
        #[arg(long)]
        min_amount_a: u128,
        #[arg(long)]
        min_amount_b: u128,
    },
}

impl WalletSubcommand for AmmSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let amm = Amm(wallet_core);
        let tx_hash = match self {
            Self::New {
                user,
                definition_a,
                definition_b,
                balance_a,
                balance_b,
            } => {
                amm.send_new_definition(
                    public_user(user, wallet_core)?,
                    definition_a,
                    definition_b,
                    balance_a,
                    balance_b,
                )
                .await?
            }
            Self::SwapExactInput {
                user,
                definition_in,
                definition_out,
                amount_in,
                min_amount_out,
            } => {
                amm.send_swap_exact_input(
                    public_user(user, wallet_core)?,
                    definition_in,
                    definition_out,
                    amount_in,
                    min_amount_out,
                )
                .await?
            }
            Self::SwapExactOutput {
                user,
                definition_in,
                definition_out,
                exact_amount_out,
                max_amount_in,
            } => {
                amm.send_swap_exact_output(
                    public_user(user, wallet_core)?,
                    definition_in,
                    definition_out,
                    exact_amount_out,
                    max_amount_in,
                )
                .await?
            }
            Self::AddLiquidity {
                user,
                definition_a,
                definition_b,
                min_amount_lp,
                max_amount_a,
                max_amount_b,
            } => {
                amm.send_add_liquidity(
                    public_user(user, wallet_core)?,
                    definition_a,
                    definition_b,
                    min_amount_lp,
                    max_amount_a,
                    max_amount_b,
                )
                .await?
            }
            Self::RemoveLiquidity {
                user,
                definition_a,
                definition_b,
                balance_lp,
                min_amount_a,
                min_amount_b,
            } => {
                amm.send_remove_liquidity(
                    public_user(user, wallet_core)?,
                    definition_a,
                    definition_b,
                    balance_lp,
                    min_amount_a,
                    min_amount_b,
                )
                .await?
            }
        };
        wallet_core
            .poll_and_finalize_public_transaction(tx_hash)
            .await
    }
}

fn public_user(user: CliAccountMention, wallet_core: &WalletCore) -> Result<AccountIdentity> {
    match user.resolve(wallet_core.storage())? {
        AccountIdWithPrivacy::Public(id) => Ok(user.into_public_identity(id, true)),
        AccountIdWithPrivacy::Private(_) => {
            anyhow::bail!("Only public execution allowed for Amm calls")
        }
    }
}
