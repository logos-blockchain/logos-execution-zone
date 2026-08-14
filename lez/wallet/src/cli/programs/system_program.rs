use anyhow::Result;
use clap::Subcommand;

use crate::{
    WalletCore,
    account::AccountIdWithPrivacy,
    cli::{CliAccountMention, SubcommandReturnValue, WalletSubcommand},
    program_facades::system_program::SystemProgram,
};

/// Represents generic CLI subcommand for a wallet working with the System Program.
#[derive(Subcommand, Debug, Clone)]
pub enum SystemSubcommand {
    /// !!!WARNING!!! Reclaim an account: reset it to the default owner, wiping all of
    /// its data and bypassing the program that currently owns it. Balance is preserved.
    ///
    /// The account authorizes its own reset. Only public accounts are supported.
    Reclaim {
        /// Account to reclaim. Must have authorization.
        #[arg(long)]
        account_id: CliAccountMention,
    },
}

impl WalletSubcommand for SystemSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::Reclaim { account_id } => {
                let resolved = account_id.resolve(wallet_core.storage())?;
                match resolved {
                    AccountIdWithPrivacy::Public(pub_account_id) => {
                        let tx_hash = SystemProgram(wallet_core)
                            .clear(account_id.into_public_identity(pub_account_id, true))
                            .await?;

                        wallet_core
                            .poll_and_finalize_public_transaction(tx_hash)
                            .await
                    }
                    AccountIdWithPrivacy::Private(_) => anyhow::bail!(
                        "Shielded reclaim is not yet supported; only public accounts can be reclaimed"
                    ),
                }
            }
        }
    }
}
