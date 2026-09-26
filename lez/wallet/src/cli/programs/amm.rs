use anyhow::Result;
use clap::Subcommand;
use lee::AccountId;

use crate::{
    AccDecodeData::Decode,
    AccountIdentity, WalletCore,
    account::AccountIdWithPrivacy,
    cli::{CliAccountMention, SubcommandReturnValue, WalletSubcommand},
    program_facades::amm::{Amm, QuoteAmount},
};

/// Represents generic CLI subcommand for a wallet working with amm program.
#[derive(Subcommand, Debug, Clone)]
pub enum AmmProgramAgnosticSubcommand {
    /// Produce a new pool.
    ///
    /// `user_holding_a` and `user_holding_b` must be owned.
    ///
    /// Only public execution allowed.
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
    /// Pay exactly `amount-in` of the `from` holding's token for exactly `amount-out` of the
    /// pool's other token.
    ///
    /// The pool accepts the offer if its price when the swap settles pays at least `amount-out`,
    /// and keeps whatever more it would have paid for its liquidity providers. Otherwise the swap
    /// fails and nothing moves. `from` must be owned; either holding may be private, but both
    /// amounts are public in the pool's reserves.
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
        amount_out: u128,
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
    ///
    /// Only public execution allowed.
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
    ///
    /// Only public execution allowed.
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
        wallet_core: &WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let a_id = user_holding_a.resolve(wallet_core.storage())?;
        let b_id = user_holding_b.resolve(wallet_core.storage())?;
        let lp_id = user_holding_lp.resolve(wallet_core.storage())?;
        match (a_id, b_id, lp_id) {
            (
                AccountIdWithPrivacy::Public(a),
                AccountIdWithPrivacy::Public(b),
                AccountIdWithPrivacy::Public(lp),
            ) => {
                let (pool_id, tx_hash) = Amm(wallet_core)
                    .send_new_pool(
                        user_holding_a.into_public_identity(a, true),
                        user_holding_b.into_public_identity(b, true),
                        user_holding_lp.into_public_identity(lp, true),
                        balance_a,
                        balance_b,
                    )
                    .await?;
                println!("Pool account is {pool_id}");
                wallet_core
                    .poll_and_finalize_public_transaction(tx_hash)
                    .await
            }
            _ => {
                // ToDo: Implement after private multi-chain calls is available
                anyhow::bail!("Only public execution allowed for Amm calls");
            }
        }
    }

    async fn handle_swap(
        pool: AccountId,
        from: CliAccountMention,
        to: CliAccountMention,
        amount_in: u128,
        amount_out: u128,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let user_input = match from.resolve(wallet_core.storage())? {
            AccountIdWithPrivacy::Public(account_id) => from.into_public_identity(account_id, true),
            AccountIdWithPrivacy::Private(account_id) => private_identity(wallet_core, account_id)?,
        };
        let user_output = match to.resolve(wallet_core.storage())? {
            AccountIdWithPrivacy::Public(account_id) => to.into_public_identity(account_id, false),
            AccountIdWithPrivacy::Private(account_id) => private_identity(wallet_core, account_id)?,
        };
        let private_accounts: Vec<AccountId> = [&user_input, &user_output]
            .into_iter()
            .filter(|identity| identity.is_private())
            .map(AccountIdentity::account_id)
            .collect();

        println!(
            "Paying exactly {amount_in} from {} for exactly {amount_out} into {} through pool {pool}",
            user_input.account_id(),
            user_output.account_id()
        );
        let (tx_hash, secrets) = Amm(wallet_core)
            .send_swap(pool, user_input, user_output, amount_in, amount_out)
            .await?;

        if private_accounts.is_empty() {
            wallet_core
                .poll_and_finalize_public_transaction(tx_hash)
                .await
        } else {
            let decode: Vec<_> = secrets
                .into_iter()
                .zip(private_accounts)
                .map(|(secret, account_id)| Decode(secret, account_id))
                .collect();
            wallet_core
                .poll_and_finalize_pp_transaction(tx_hash, &decode)
                .await
        }
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
        wallet_core: &WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let a_id = user_holding_a.resolve(wallet_core.storage())?;
        let b_id = user_holding_b.resolve(wallet_core.storage())?;
        let lp_id = user_holding_lp.resolve(wallet_core.storage())?;
        match (a_id, b_id, lp_id) {
            (
                AccountIdWithPrivacy::Public(a),
                AccountIdWithPrivacy::Public(b),
                AccountIdWithPrivacy::Public(lp),
            ) => {
                let tx_hash = Amm(wallet_core)
                    .send_add_liquidity(
                        user_holding_a.into_public_identity(a, true),
                        user_holding_b.into_public_identity(b, true),
                        user_holding_lp.into_public_identity(lp, true),
                        min_amount_lp,
                        max_amount_a,
                        max_amount_b,
                    )
                    .await?;
                wallet_core
                    .poll_and_finalize_public_transaction(tx_hash)
                    .await
            }
            _ => {
                // ToDo: Implement after private multi-chain calls is available
                anyhow::bail!("Only public execution allowed for Amm calls");
            }
        }
    }

    async fn handle_remove_liquidity(
        user_holding_a: CliAccountMention,
        user_holding_b: CliAccountMention,
        user_holding_lp: CliAccountMention,
        balance_lp: u128,
        min_amount_a: u128,
        min_amount_b: u128,
        wallet_core: &WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let a_id = user_holding_a.resolve(wallet_core.storage())?;
        let b_id = user_holding_b.resolve(wallet_core.storage())?;
        let lp_id = user_holding_lp.resolve(wallet_core.storage())?;
        match (a_id, b_id, lp_id) {
            (
                AccountIdWithPrivacy::Public(a),
                AccountIdWithPrivacy::Public(b),
                AccountIdWithPrivacy::Public(lp),
            ) => {
                let tx_hash = Amm(wallet_core)
                    .send_remove_liquidity(
                        a,
                        b,
                        user_holding_lp.into_public_identity(lp, true),
                        balance_lp,
                        min_amount_a,
                        min_amount_b,
                    )
                    .await?;
                wallet_core
                    .poll_and_finalize_public_transaction(tx_hash)
                    .await
            }
            _ => {
                // ToDo: Implement after private multi-chain calls is available
                anyhow::bail!("Only public execution allowed for Amm calls");
            }
        }
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
                amount_out,
            } => Self::handle_swap(pool, from, to, amount_in, amount_out, wallet_core).await,
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

fn private_identity(wallet_core: &WalletCore, account_id: AccountId) -> Result<AccountIdentity> {
    wallet_core
        .resolve_private_account(account_id)
        .ok_or_else(|| anyhow::anyhow!("No keys for private account {account_id}"))
}
