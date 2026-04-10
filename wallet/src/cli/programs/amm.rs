use anyhow::Result;
use clap::Subcommand;
use nssa::AccountId;

use crate::{
    WalletCore,
    account::AccountIdWithPrivacy,
    cli::{CliAccountMention, SubcommandReturnValue, WalletSubcommand},
    program_facades::amm::Amm,
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
    /// Swap specifying exact input amount.
    ///
    /// The account associated with swapping token must be owned.
    ///
    /// Only public execution allowed.
    SwapExactInput {
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        user_holding_a: CliAccountMention,
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        user_holding_b: CliAccountMention,
        #[arg(long)]
        amount_in: u128,
        #[arg(long)]
        min_amount_out: u128,
        /// `token_definition` - valid 32 byte base58 string WITHOUT privacy prefix.
        #[arg(long)]
        token_definition: AccountId,
    },
    /// Swap specifying exact output amount.
    ///
    /// The account associated with swapping token must be owned.
    ///
    /// Only public execution allowed.
    SwapExactOutput {
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        user_holding_a: CliAccountMention,
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        user_holding_b: CliAccountMention,
        #[arg(long)]
        exact_amount_out: u128,
        #[arg(long)]
        max_amount_in: u128,
        /// `token_definition` - valid 32 byte base58 string WITHOUT privacy prefix.
        #[arg(long)]
        token_definition: AccountId,
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
                let user_holding_a = user_holding_a.resolve(wallet_core.storage())?;
                let user_holding_b = user_holding_b.resolve(wallet_core.storage())?;
                let user_holding_lp = user_holding_lp.resolve(wallet_core.storage())?;
                match (user_holding_a, user_holding_b, user_holding_lp) {
                    (
                        AccountIdWithPrivacy::Public(user_holding_a),
                        AccountIdWithPrivacy::Public(user_holding_b),
                        AccountIdWithPrivacy::Public(user_holding_lp),
                    ) => {
                        Amm(wallet_core)
                            .send_new_definition(
                                user_holding_a,
                                user_holding_b,
                                user_holding_lp,
                                balance_a,
                                balance_b,
                            )
                            .await?;

                        Ok(SubcommandReturnValue::Empty)
                    }
                    _ => {
                        // ToDo: Implement after private multi-chain calls is available
                        anyhow::bail!("Only public execution allowed for Amm calls");
                    }
                }
            }
            Self::SwapExactInput {
                user_holding_a,
                user_holding_b,
                amount_in,
                min_amount_out,
                token_definition,
            } => {
                let user_holding_a = user_holding_a.resolve(wallet_core.storage())?;
                let user_holding_b = user_holding_b.resolve(wallet_core.storage())?;
                match (user_holding_a, user_holding_b) {
                    (
                        AccountIdWithPrivacy::Public(user_holding_a),
                        AccountIdWithPrivacy::Public(user_holding_b),
                    ) => {
                        Amm(wallet_core)
                            .send_swap_exact_input(
                                user_holding_a,
                                user_holding_b,
                                amount_in,
                                min_amount_out,
                                token_definition,
                            )
                            .await?;

                        Ok(SubcommandReturnValue::Empty)
                    }
                    _ => {
                        // ToDo: Implement after private multi-chain calls is available
                        anyhow::bail!("Only public execution allowed for Amm calls");
                    }
                }
            }
            Self::SwapExactOutput {
                user_holding_a,
                user_holding_b,
                exact_amount_out,
                max_amount_in,
                token_definition,
            } => {
                let user_holding_a = user_holding_a.resolve(wallet_core.storage())?;
                let user_holding_b = user_holding_b.resolve(wallet_core.storage())?;
                match (user_holding_a, user_holding_b) {
                    (
                        AccountIdWithPrivacy::Public(user_holding_a),
                        AccountIdWithPrivacy::Public(user_holding_b),
                    ) => {
                        Amm(wallet_core)
                            .send_swap_exact_output(
                                user_holding_a,
                                user_holding_b,
                                exact_amount_out,
                                max_amount_in,
                                token_definition,
                            )
                            .await?;

                        Ok(SubcommandReturnValue::Empty)
                    }
                    _ => {
                        // ToDo: Implement after private multi-chain calls is available
                        anyhow::bail!("Only public execution allowed for Amm calls");
                    }
                }
            }
            Self::AddLiquidity {
                user_holding_a,
                user_holding_b,
                user_holding_lp,
                min_amount_lp,
                max_amount_a,
                max_amount_b,
            } => {
                let user_holding_a = user_holding_a.resolve(wallet_core.storage())?;
                let user_holding_b = user_holding_b.resolve(wallet_core.storage())?;
                let user_holding_lp = user_holding_lp.resolve(wallet_core.storage())?;
                match (user_holding_a, user_holding_b, user_holding_lp) {
                    (
                        AccountIdWithPrivacy::Public(user_holding_a),
                        AccountIdWithPrivacy::Public(user_holding_b),
                        AccountIdWithPrivacy::Public(user_holding_lp),
                    ) => {
                        Amm(wallet_core)
                            .send_add_liquidity(
                                user_holding_a,
                                user_holding_b,
                                user_holding_lp,
                                min_amount_lp,
                                max_amount_a,
                                max_amount_b,
                            )
                            .await?;

                        Ok(SubcommandReturnValue::Empty)
                    }
                    _ => {
                        // ToDo: Implement after private multi-chain calls is available
                        anyhow::bail!("Only public execution allowed for Amm calls");
                    }
                }
            }
            Self::RemoveLiquidity {
                user_holding_a,
                user_holding_b,
                user_holding_lp,
                balance_lp,
                min_amount_a,
                min_amount_b,
            } => {
                let user_holding_a = user_holding_a.resolve(wallet_core.storage())?;
                let user_holding_b = user_holding_b.resolve(wallet_core.storage())?;
                let user_holding_lp = user_holding_lp.resolve(wallet_core.storage())?;
                match (user_holding_a, user_holding_b, user_holding_lp) {
                    (
                        AccountIdWithPrivacy::Public(user_holding_a),
                        AccountIdWithPrivacy::Public(user_holding_b),
                        AccountIdWithPrivacy::Public(user_holding_lp),
                    ) => {
                        Amm(wallet_core)
                            .send_remove_liquidity(
                                user_holding_a,
                                user_holding_b,
                                user_holding_lp,
                                balance_lp,
                                min_amount_a,
                                min_amount_b,
                            )
                            .await?;

                        Ok(SubcommandReturnValue::Empty)
                    }
                    _ => {
                        // ToDo: Implement after private multi-chain calls is available
                        anyhow::bail!("Only public execution allowed for Amm calls");
                    }
                }
            }
        }
    }
}
