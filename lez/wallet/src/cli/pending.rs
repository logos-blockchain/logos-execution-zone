use anyhow::{Context as _, Result};
use clap::Subcommand;

use crate::{
    PendingMessage, WalletCore,
    cli::{SubcommandReturnValue, WalletSubcommand},
};

/// Represents generic CLI subcommand for a wallet working with pending messages.
#[derive(Subcommand, Debug, Clone)]
pub enum PendingSubcommand {
    /// List the pending messages cast to this wallet's accounts.
    List,
    /// Receive a pending native or token credit cast to one of this wallet's accounts.
    Receive {
        /// `position` - the pending message's position in the commitment tree.
        #[arg(long)]
        position: u64,
    },
}

impl WalletSubcommand for PendingSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::List => {
                for PendingMessage { position, body, .. } in
                    wallet_core.owned_pending_messages().await?
                {
                    println!(
                        "Message {position}: to {} at program {}, from {} at program {}, {} bytes",
                        body.to.account_id,
                        body.to.program_account_id,
                        body.from.account_id,
                        body.from.program_account_id,
                        body.message.len()
                    );
                }
                Ok(SubcommandReturnValue::Empty)
            }
            Self::Receive { position } => {
                let pending = wallet_core
                    .find_pending_message(position)
                    .await?
                    .context("No pending message at this position")?;
                let (tx_hash, _) = wallet_core.receive_pending_message(pending).await?;
                wallet_core.finish_transaction(tx_hash).await
            }
        }
    }
}
