use anyhow::Result;
use clap::Subcommand;
use nssa::AccountId;

use crate::{
    WalletCore,
    cli::{SubcommandReturnValue, WalletSubcommand},
    helperfunctions::{AccountPrivacyKind, parse_addr_with_privacy_prefix},
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
        /// `user_holding_a` - valid 32 byte base58 string with privacy prefix.
        #[arg(long)]
        user_holding_a: String,
        /// `user_holding_b` - valid 32 byte base58 string with privacy prefix.
        #[arg(long)]
        user_holding_b: String,
        /// `user_holding_lp` - valid 32 byte base58 string with privacy prefix.
        #[arg(long)]
        user_holding_lp: String,
        #[arg(long)]
        balance_a: u128,
        #[arg(long)]
        balance_b: u128,
    },
    /// Swap.
    ///
    /// The account associated with swapping token must be owned.
    ///
    /// Only public execution allowed.
    Swap {
        /// `user_holding_a` - valid 32 byte base58 string with privacy prefix.
        #[arg(long)]
        user_holding_a: String,
        /// `user_holding_b` - valid 32 byte base58 string with privacy prefix.
        #[arg(long)]
        user_holding_b: String,
        #[arg(long)]
        amount_in: u128,
        #[arg(long)]
        min_amount_out: u128,
        /// `token_definition` - valid 32 byte base58 string WITHOUT privacy prefix.
        #[arg(long)]
        token_definition: String,
    },
    /// Swap specifying exact output amount.
    ///
    /// The account associated with swapping token must be owned.
    ///
    /// Only public execution allowed.
    SwapExactOutput {
        /// `user_holding_a` - valid 32 byte base58 string with privacy prefix.
        #[arg(long)]
        user_holding_a: String,
        /// `user_holding_b` - valid 32 byte base58 string with privacy prefix.
        #[arg(long)]
        user_holding_b: String,
        #[arg(long)]
        exact_amount_out: u128,
        #[arg(long)]
        max_amount_in: u128,
        /// `token_definition` - valid 32 byte base58 string WITHOUT privacy prefix.
        #[arg(long)]
        token_definition: String,
    },
    /// Add liquidity.
    ///
    /// `user_holding_a` and `user_holding_b` must be owned.
    ///
    /// Only public execution allowed.
    AddLiquidity {
        /// `user_holding_a` - valid 32 byte base58 string with privacy prefix.
        #[arg(long)]
        user_holding_a: String,
        /// `user_holding_b` - valid 32 byte base58 string with privacy prefix.
        #[arg(long)]
        user_holding_b: String,
        /// `user_holding_lp` - valid 32 byte base58 string with privacy prefix.
        #[arg(long)]
        user_holding_lp: String,
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
        /// `user_holding_a` - valid 32 byte base58 string with privacy prefix.
        #[arg(long)]
        user_holding_a: String,
        /// `user_holding_b` - valid 32 byte base58 string with privacy prefix.
        #[arg(long)]
        user_holding_b: String,
        /// `user_holding_lp` - valid 32 byte base58 string with privacy prefix.
        #[arg(long)]
        user_holding_lp: String,
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
                let (user_holding_a, user_holding_a_privacy) =
                    parse_addr_with_privacy_prefix(&user_holding_a)?;
                let (user_holding_b, user_holding_b_privacy) =
                    parse_addr_with_privacy_prefix(&user_holding_b)?;
                let (user_holding_lp, user_holding_lp_privacy) =
                    parse_addr_with_privacy_prefix(&user_holding_lp)?;

                let user_holding_a: AccountId = user_holding_a.parse()?;
                let user_holding_b: AccountId = user_holding_b.parse()?;
                let user_holding_lp: AccountId = user_holding_lp.parse()?;

                match (
                    user_holding_a_privacy,
                    user_holding_b_privacy,
                    user_holding_lp_privacy,
                ) {
                    (
                        AccountPrivacyKind::Public,
                        AccountPrivacyKind::Public,
                        AccountPrivacyKind::Public,
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
            Self::Swap {
                user_holding_a,
                user_holding_b,
                amount_in,
                min_amount_out,
                token_definition,
            } => {
                let (user_holding_a, user_holding_a_privacy) =
                    parse_addr_with_privacy_prefix(&user_holding_a)?;
                let (user_holding_b, user_holding_b_privacy) =
                    parse_addr_with_privacy_prefix(&user_holding_b)?;

                let user_holding_a: AccountId = user_holding_a.parse()?;
                let user_holding_b: AccountId = user_holding_b.parse()?;

                match (user_holding_a_privacy, user_holding_b_privacy) {
                    (AccountPrivacyKind::Public, AccountPrivacyKind::Public) => {
                        Amm(wallet_core)
                            .send_swap(
                                user_holding_a,
                                user_holding_b,
                                amount_in,
                                min_amount_out,
                                token_definition.parse()?,
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
                let (user_holding_a, user_holding_a_privacy) =
                    parse_addr_with_privacy_prefix(&user_holding_a)?;
                let (user_holding_b, user_holding_b_privacy) =
                    parse_addr_with_privacy_prefix(&user_holding_b)?;

                let user_holding_a: AccountId = user_holding_a.parse()?;
                let user_holding_b: AccountId = user_holding_b.parse()?;

                match (user_holding_a_privacy, user_holding_b_privacy) {
                    (AccountPrivacyKind::Public, AccountPrivacyKind::Public) => {
                        Amm(wallet_core)
                            .send_swap_exact_output(
                                user_holding_a,
                                user_holding_b,
                                exact_amount_out,
                                max_amount_in,
                                token_definition.parse()?,
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
                let (user_holding_a, user_holding_a_privacy) =
                    parse_addr_with_privacy_prefix(&user_holding_a)?;
                let (user_holding_b, user_holding_b_privacy) =
                    parse_addr_with_privacy_prefix(&user_holding_b)?;
                let (user_holding_lp, user_holding_lp_privacy) =
                    parse_addr_with_privacy_prefix(&user_holding_lp)?;

                let user_holding_a: AccountId = user_holding_a.parse()?;
                let user_holding_b: AccountId = user_holding_b.parse()?;
                let user_holding_lp: AccountId = user_holding_lp.parse()?;

                match (
                    user_holding_a_privacy,
                    user_holding_b_privacy,
                    user_holding_lp_privacy,
                ) {
                    (
                        AccountPrivacyKind::Public,
                        AccountPrivacyKind::Public,
                        AccountPrivacyKind::Public,
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
                let (user_holding_a, user_holding_a_privacy) =
                    parse_addr_with_privacy_prefix(&user_holding_a)?;
                let (user_holding_b, user_holding_b_privacy) =
                    parse_addr_with_privacy_prefix(&user_holding_b)?;
                let (user_holding_lp, user_holding_lp_privacy) =
                    parse_addr_with_privacy_prefix(&user_holding_lp)?;

                let user_holding_a: AccountId = user_holding_a.parse()?;
                let user_holding_b: AccountId = user_holding_b.parse()?;
                let user_holding_lp: AccountId = user_holding_lp.parse()?;

                match (
                    user_holding_a_privacy,
                    user_holding_b_privacy,
                    user_holding_lp_privacy,
                ) {
                    (
                        AccountPrivacyKind::Public,
                        AccountPrivacyKind::Public,
                        AccountPrivacyKind::Public,
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
