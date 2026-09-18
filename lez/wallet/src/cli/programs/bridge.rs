use anyhow::{Context as _, Result};
use clap::Subcommand;

use crate::{
    WalletCore,
    account::AccountIdWithPrivacy,
    cli::{CliAccountMention, SubcommandReturnValue, WalletSubcommand},
    program_facades::bridge::Bridge,
};

/// Represents generic CLI subcommand for a wallet working with bridge program.
#[derive(Subcommand, Debug, Clone)]
pub enum BridgeSubcommand {
    /// Withdraw native tokens from a public account to Bedrock through the bridge.
    Withdraw {
        /// Sender account mention - account id with privacy prefix or a label.
        #[arg(long)]
        from: CliAccountMention,
        /// Amount of native tokens to withdraw.
        #[arg(long)]
        amount: u64,
        /// Bedrock account public key encoded as a 32-byte hex string.
        #[arg(long)]
        bedrock_account_pk: String,
    },
}

impl WalletSubcommand for BridgeSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::Withdraw {
                from,
                amount,
                bedrock_account_pk,
            } => {
                let from = from.resolve(wallet_core.storage())?;
                let AccountIdWithPrivacy::Public(sender_account_id) = from else {
                    anyhow::bail!("Bridge withdraw supports only public sender accounts");
                };

                let bedrock_account_pk = parse_bedrock_account_pk(&bedrock_account_pk)?;

                let tx_hash = Bridge(wallet_core)
                    .send_withdraw(sender_account_id, amount, bedrock_account_pk)
                    .await?;

                wallet_core
                    .poll_and_finalize_public_transaction(tx_hash)
                    .await
                    .context("Transaction finalization error")
            }
        }
    }
}

fn parse_bedrock_account_pk(raw: &str) -> Result<[u8; 32]> {
    let raw = raw.strip_prefix("0x").unwrap_or(raw);
    let mut bedrock_account_pk = [0_u8; 32];
    hex::decode_to_slice(raw, &mut bedrock_account_pk)
        .context("Invalid `bedrock-account-pk`: expected hex string of 32 bytes")?;
    Ok(bedrock_account_pk)
}
