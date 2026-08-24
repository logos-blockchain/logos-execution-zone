use anyhow::Result;
use clap::Subcommand;
use lee::AccountId;

use crate::{
    WalletCore,
    account::AccountIdWithPrivacy,
    cli::{CliAccountMention, SubcommandReturnValue, WalletSubcommand},
    program_facades::system_program::SystemProgram,
};

/// Represents generic CLI subcommand for a wallet working with the System Program.
#[derive(Subcommand, Debug, Clone)]
pub enum SystemSubcommand {
    /// !!!WARNING!!! Reclaim an account: wipe all of its data and hand it to a new owner,
    /// bypassing the program that currently owns it. Balance is preserved.
    ///
    /// The account authorizes its own reset. Only public accounts are supported.
    Reclaim {
        /// Account to reclaim. Must have authorization.
        #[arg(long)]
        account_id: CliAccountMention,
        /// New owner - valid 32 byte base58 string WITHOUT privacy prefix. Defaults to the
        /// authenticated transfer program, which keeps the balance spendable.
        #[arg(long)]
        new_owner: Option<AccountId>,
    },
}

impl WalletSubcommand for SystemSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::Reclaim {
                account_id,
                new_owner,
            } => {
                let resolved = account_id.resolve(wallet_core.storage())?;
                let AccountIdWithPrivacy::Public(pub_account_id) = resolved else {
                    anyhow::bail!(
                        "Shielded reclaim is not yet supported; only public accounts can be reclaimed"
                    );
                };
                let new_owner = Some(
                    new_owner.unwrap_or_else(|| programs::authenticated_transfer().id().into()),
                );

                let tx_hash = SystemProgram(wallet_core)
                    .clear(
                        account_id.into_public_identity(pub_account_id, true),
                        new_owner,
                    )
                    .await?;

                wallet_core
                    .poll_and_finalize_public_transaction(tx_hash)
                    .await
            }
        }
    }
}
