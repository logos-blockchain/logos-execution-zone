use anyhow::Result;
use clap::Subcommand;
use lee::AccountId;

use crate::{
    WalletCore,
    cli::{CliAccountMention, SubcommandReturnValue, WalletSubcommand},
    program_facades::amm::{Amm, Payout, QuoteAmount},
};

/// Represents generic CLI subcommand for a wallet working with amm program.
#[derive(Subcommand, Debug, Clone)]
pub enum AmmProgramAgnosticSubcommand {
    /// Produce a new pool.
    ///
    /// `user_holding_a` and `user_holding_b` must be owned.
    New {
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        user_holding_a: CliAccountMention,
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        user_holding_b: CliAccountMention,
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        user_holding_lp: CliAccountMention,
        #[arg(long)]
        balance_a: u128,
        #[arg(long)]
        balance_b: u128,
    },
    /// Pay exactly `amount-in` of the `from` holding's token for whatever the pool's price pays
    /// in its other token when the swap settles.
    ///
    /// If that is less than `min-amount-out`, the swap fails and nothing moves. `from` must be
    /// owned; either holding may be private, but both amounts are public in the pool's reserves.
    Swap {
        /// `pool` - valid 32 byte base58 string WITHOUT privacy prefix.
        #[arg(long)]
        pool: AccountId,
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        from: CliAccountMention,
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        to: CliAccountMention,
        #[arg(long)]
        amount_in: u128,
        #[arg(long)]
        min_amount_out: u128,
        /// Leave a private `to`'s payout pending for a later transaction to receive, at the price
        /// the swap settles at, instead of proving it in this one at today's price.
        #[arg(long)]
        live: bool,
    },
    /// Estimate a swap from the pool's current reserves.
    ///
    /// Give the amount paid in or the amount received out. The price can move before a swap
    /// settles, so an estimate is not an offer.
    Quote {
        /// `pool` - valid 32 byte base58 string WITHOUT privacy prefix.
        #[arg(long)]
        pool: AccountId,
        /// `token_definition` - valid 32 byte base58 string WITHOUT privacy prefix.
        #[arg(long)]
        token_definition: AccountId,
        #[arg(
            long,
            conflicts_with = "amount_out",
            required_unless_present = "amount_out"
        )]
        amount_in: Option<u128>,
        #[arg(long)]
        amount_out: Option<u128>,
    },
    /// Add liquidity.
    ///
    /// `user_holding_a` and `user_holding_b` must be owned.
    AddLiquidity {
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        user_holding_a: CliAccountMention,
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        user_holding_b: CliAccountMention,
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        user_holding_lp: CliAccountMention,
        #[arg(long)]
        min_amount_lp: u128,
        #[arg(long)]
        max_amount_a: u128,
        #[arg(long)]
        max_amount_b: u128,
    },
    /// Remove liquidity.
    ///
    /// `user_holding_lp` must be owned.
    RemoveLiquidity {
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        user_holding_a: CliAccountMention,
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        user_holding_b: CliAccountMention,
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        user_holding_lp: CliAccountMention,
        #[arg(long)]
        balance_lp: u128,
        #[arg(long)]
        min_amount_a: u128,
        #[arg(long)]
        min_amount_b: u128,
    },
}

impl AmmProgramAgnosticSubcommand {
    async fn handle_new(
        user_holding_a: CliAccountMention,
        user_holding_b: CliAccountMention,
        user_holding_lp: CliAccountMention,
        balance_a: u128,
        balance_b: u128,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let storage = wallet_core.storage();
        let [a, b, lp] = [
            user_holding_a.signer(storage)?,
            user_holding_b.signer(storage)?,
            user_holding_lp.signer(storage)?,
        ];
        let (pool_id, tx_hash, _) = Amm(wallet_core)
            .send_new_pool(a, b, lp, balance_a, balance_b)
            .await?;
        println!("Pool account is {pool_id}");
        wallet_core.finish_transaction(tx_hash).await
    }

    async fn handle_swap(
        pool: AccountId,
        from: CliAccountMention,
        to: CliAccountMention,
        amount_in: u128,
        min_amount_out: u128,
        live: bool,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let storage = wallet_core.storage();
        let user_input = from.signer(storage)?;
        let user_output = to.unsigned(storage)?;
        println!(
            "Paying exactly {amount_in} from {} for at least {min_amount_out} into {} through pool {pool}",
            user_input.account_id(),
            user_output.account_id()
        );
        let (tx_hash, _) = Amm(wallet_core)
            .send_swap(
                pool,
                user_input,
                user_output,
                amount_in,
                min_amount_out,
                if live { Payout::Live } else { Payout::Exact },
            )
            .await?;
        wallet_core.finish_transaction(tx_hash).await
    }

    async fn handle_quote(
        pool: AccountId,
        token_definition: AccountId,
        amount_in: Option<u128>,
        amount_out: Option<u128>,
        wallet_core: &WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let amount = match (amount_in, amount_out) {
            (Some(amount_in), None) => QuoteAmount::In(amount_in),
            (None, Some(amount_out)) => QuoteAmount::Out(amount_out),
            _ => anyhow::bail!("Give exactly one of --amount-in and --amount-out"),
        };
        let estimate = Amm(wallet_core)
            .quote(pool, token_definition, amount)
            .await?;
        println!(
            "Estimate at the pool's current reserves: {} in for {} out. The price can move before a swap settles.",
            estimate.amount_in, estimate.amount_out
        );
        Ok(SubcommandReturnValue::Empty)
    }

    async fn handle_add_liquidity(
        user_holding_a: CliAccountMention,
        user_holding_b: CliAccountMention,
        user_holding_lp: CliAccountMention,
        min_amount_lp: u128,
        max_amount_a: u128,
        max_amount_b: u128,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let storage = wallet_core.storage();
        let [a, b, lp] = [
            user_holding_a.signer(storage)?,
            user_holding_b.signer(storage)?,
            user_holding_lp.signer(storage)?,
        ];
        let (tx_hash, _) = Amm(wallet_core)
            .send_add_liquidity(a, b, lp, min_amount_lp, max_amount_a, max_amount_b)
            .await?;
        wallet_core.finish_transaction(tx_hash).await
    }

    async fn handle_remove_liquidity(
        user_holding_a: CliAccountMention,
        user_holding_b: CliAccountMention,
        user_holding_lp: CliAccountMention,
        balance_lp: u128,
        min_amount_a: u128,
        min_amount_b: u128,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let storage = wallet_core.storage();
        let [a, b, lp] = [
            user_holding_a.unsigned(storage)?,
            user_holding_b.unsigned(storage)?,
            user_holding_lp.signer(storage)?,
        ];
        let (tx_hash, _) = Amm(wallet_core)
            .send_remove_liquidity(a, b, lp, balance_lp, min_amount_a, min_amount_b)
            .await?;
        wallet_core.finish_transaction(tx_hash).await
    }
}

impl WalletSubcommand for AmmProgramAgnosticSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::New {
                user_holding_a,
                user_holding_b,
                user_holding_lp,
                balance_a,
                balance_b,
            } => {
                Self::handle_new(
                    user_holding_a,
                    user_holding_b,
                    user_holding_lp,
                    balance_a,
                    balance_b,
                    wallet_core,
                )
                .await
            }
            Self::Swap {
                pool,
                from,
                to,
                amount_in,
                min_amount_out,
                live,
            } => {
                Self::handle_swap(pool, from, to, amount_in, min_amount_out, live, wallet_core)
                    .await
            }
            Self::Quote {
                pool,
                token_definition,
                amount_in,
                amount_out,
            } => {
                Self::handle_quote(pool, token_definition, amount_in, amount_out, wallet_core).await
            }
            Self::AddLiquidity {
                user_holding_a,
                user_holding_b,
                user_holding_lp,
                min_amount_lp,
                max_amount_a,
                max_amount_b,
            } => {
                Self::handle_add_liquidity(
                    user_holding_a,
                    user_holding_b,
                    user_holding_lp,
                    min_amount_lp,
                    max_amount_a,
                    max_amount_b,
                    wallet_core,
                )
                .await
            }
            Self::RemoveLiquidity {
                user_holding_a,
                user_holding_b,
                user_holding_lp,
                balance_lp,
                min_amount_a,
                min_amount_b,
            } => {
                Self::handle_remove_liquidity(
                    user_holding_a,
                    user_holding_b,
                    user_holding_lp,
                    balance_lp,
                    min_amount_a,
                    min_amount_b,
                    wallet_core,
                )
                .await
            }
        }
    }
}
