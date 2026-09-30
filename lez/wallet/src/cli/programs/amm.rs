use anyhow::Result;
use clap::Subcommand;
use common::HashType;
use lee::AccountId;
use lee_core::SharedSecretKey;

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
        #[arg(
            long,
            conflicts_with = "min_amount_out",
            required_unless_present = "min_amount_out"
        )]
        amount_out: Option<u128>,
        /// Instead of `amount-out`: pay exactly `amount-in` for whatever the pool's price pays
        /// when the swap settles, failing if that is less than this.
        #[arg(long)]
        min_amount_out: Option<u128>,
        /// Cast the payout as a pending message for a later transaction to receive, instead of
        /// crediting `to` in this one. A private `to` requires it.
        #[arg(long, requires = "min_amount_out")]
        cast: bool,
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
        let holdings = [
            identity(user_holding_a, true, wallet_core)?,
            identity(user_holding_b, true, wallet_core)?,
            identity(user_holding_lp, true, wallet_core)?,
        ];
        let [a, b, lp] = holdings.clone();
        let (pool_id, tx_hash, secrets) = Amm(wallet_core)
            .send_new_pool(a, b, lp, balance_a, balance_b)
            .await?;
        println!("Pool account is {pool_id}");
        finalize(wallet_core, tx_hash, secrets, &holdings).await
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "extracted match arm with many destructured fields"
    )]
    async fn handle_swap(
        pool: AccountId,
        from: CliAccountMention,
        to: CliAccountMention,
        amount_in: u128,
        amount_out: Option<u128>,
        min_amount_out: Option<u128>,
        cast: bool,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let user_input = identity(from, true, wallet_core)?;
        let user_output = identity(to, false, wallet_core)?;
        let traders = [user_input.clone(), user_output.clone()];

        let (tx_hash, secrets) = match (amount_out, min_amount_out) {
            (Some(amount_out), None) => {
                println!(
                    "Paying exactly {amount_in} from {} for exactly {amount_out} into {} through pool {pool}",
                    user_input.account_id(),
                    user_output.account_id()
                );
                Amm(wallet_core)
                    .send_swap(pool, user_input, user_output, amount_in, amount_out)
                    .await?
            }
            (None, Some(min_amount_out)) => {
                println!(
                    "Paying exactly {amount_in} from {} for at least {min_amount_out} into {} through pool {pool}",
                    user_input.account_id(),
                    user_output.account_id()
                );
                Amm(wallet_core)
                    .send_swap_exact_input(
                        pool,
                        user_input,
                        user_output,
                        amount_in,
                        min_amount_out,
                        crate::cli::delivery(cast),
                    )
                    .await?
            }
            _ => anyhow::bail!("Give exactly one of --amount-out and --min-amount-out"),
        };
        finalize(wallet_core, tx_hash, secrets, &traders).await
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
        let holdings = [
            identity(user_holding_a, true, wallet_core)?,
            identity(user_holding_b, true, wallet_core)?,
            identity(user_holding_lp, true, wallet_core)?,
        ];
        let [a, b, lp] = holdings.clone();
        let (tx_hash, secrets) = Amm(wallet_core)
            .send_add_liquidity(a, b, lp, min_amount_lp, max_amount_a, max_amount_b)
            .await?;
        finalize(wallet_core, tx_hash, secrets, &holdings).await
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
        let holdings = [
            identity(user_holding_a, false, wallet_core)?,
            identity(user_holding_b, false, wallet_core)?,
            identity(user_holding_lp, true, wallet_core)?,
        ];
        let [a, b, lp] = holdings.clone();
        let (tx_hash, secrets) = Amm(wallet_core)
            .send_remove_liquidity(a, b, lp, balance_lp, min_amount_a, min_amount_b)
            .await?;
        finalize(wallet_core, tx_hash, secrets, &holdings).await
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
                min_amount_out,
                cast,
            } => {
                Self::handle_swap(
                    pool,
                    from,
                    to,
                    amount_in,
                    amount_out,
                    min_amount_out,
                    cast,
                    wallet_core,
                )
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

// A public mention signs when `sign`; a private one needs the wallet's keys for it.
fn identity(
    mention: CliAccountMention,
    sign: bool,
    wallet_core: &WalletCore,
) -> Result<AccountIdentity> {
    match mention.resolve(wallet_core.storage())? {
        AccountIdWithPrivacy::Public(account_id) => {
            Ok(mention.into_public_identity(account_id, sign))
        }
        AccountIdWithPrivacy::Private(account_id) => wallet_core
            .resolve_private_account(account_id)
            .ok_or_else(|| anyhow::anyhow!("No keys for private account {account_id}")),
    }
}

// The shared secrets come back one per private account, in the order the accounts were named.
async fn finalize(
    wallet_core: &mut WalletCore,
    tx_hash: HashType,
    secrets: Vec<SharedSecretKey>,
    named: &[AccountIdentity],
) -> Result<SubcommandReturnValue> {
    let mut private_accounts: Vec<AccountId> = Vec::new();
    for account_id in named
        .iter()
        .filter(|identity| identity.is_private())
        .map(AccountIdentity::account_id)
    {
        if !private_accounts.contains(&account_id) {
            private_accounts.push(account_id);
        }
    }
    if private_accounts.is_empty() {
        return wallet_core
            .poll_and_finalize_public_transaction(tx_hash)
            .await;
    }
    let decode: Vec<_> = secrets
        .into_iter()
        .zip(private_accounts)
        .map(|(secret, account_id)| Decode(secret, account_id))
        .collect();
    wallet_core
        .poll_and_finalize_pp_transaction(tx_hash, &decode)
        .await
}
