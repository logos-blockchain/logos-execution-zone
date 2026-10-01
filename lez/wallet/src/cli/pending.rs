use anyhow::{Context as _, Result};
use clap::Subcommand;
use lee::{AccountId, PublicIdentity, privacy_preserving_transaction::circuit::ProgramCatalog};
use lee_core::{
    native_token::NATIVE_TOKEN_PROGRAM_ID,
    program::{MessageId, PdaSeed},
};

use crate::{
    AccDecodeData::Decode,
    WalletCore,
    account::AccountIdWithPrivacy,
    cli::{CliAccountMention, SubcommandReturnValue, WalletSubcommand},
};

/// Represents generic CLI subcommand for a wallet working with pending messages.
#[derive(Subcommand, Debug, Clone)]
pub enum PendingSubcommand {
    /// List the pending messages cast to this wallet's accounts.
    List,
    /// Receive a pending native or token credit cast to one of this wallet's accounts or to a
    /// public PDA.
    ///
    /// A public destination whose key the wallet holds signs and pays the fee, unless `payer`
    /// pays it instead. A public PDA destination needs `payer`, `pda_program` and `pda_seed`.
    Receive {
        /// `id` - valid 32 byte base58 string.
        #[arg(long)]
        id: String,
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        payer: Option<CliAccountMention>,
        /// `pda_program` - program deriving the destination PDA, valid 32 byte base58 string
        /// WITHOUT privacy prefix.
        #[arg(long, requires = "pda_seed")]
        pda_program: Option<AccountId>,
        /// `pda_seed` - seed of the destination PDA, valid 32 byte base58 string.
        #[arg(long, requires = "pda_program")]
        pda_seed: Option<String>,
    },
}

impl WalletSubcommand for PendingSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::List => {
                for record in wallet_core.owned_pending_messages().await? {
                    println!(
                        "Message {}: sequence {}, to {} at program {}, from program {}, {} bytes",
                        AccountId::new(*record.id().as_bytes()),
                        record.sequence,
                        record.body.to.account_id,
                        record.body.to.program_account_id,
                        record.body.source,
                        record.body.message.len()
                    );
                }
                Ok(SubcommandReturnValue::Empty)
            }
            Self::Receive {
                id,
                payer,
                pda_program,
                pda_seed,
            } => {
                let id = MessageId::new(
                    id.parse::<AccountId>()
                        .context("Message id must be a valid 32 byte base58 string")?
                        .into_value(),
                );
                let payer = match payer
                    .map(|payer| payer.resolve(wallet_core.storage()))
                    .transpose()?
                {
                    None => None,
                    Some(AccountIdWithPrivacy::Public(account_id)) => Some(account_id),
                    Some(AccountIdWithPrivacy::Private(_)) => {
                        anyhow::bail!("Payer must be a public account")
                    }
                };
                let evidence = match pda_program.zip(pda_seed) {
                    None => None,
                    Some((program, seed)) => Some(PublicIdentity::Pda {
                        program,
                        seed: PdaSeed::new(
                            seed.parse::<AccountId>()
                                .context("PDA seed must be a valid 32 byte base58 string")?
                                .into_value(),
                        ),
                    }),
                };
                let record = wallet_core
                    .find_pending_message(id)
                    .await?
                    .context("No pending message with this id")?;
                let to = record.body.to;
                let programs = receipt_programs(to.program_account_id)?;

                let (tx_hash, secrets) = wallet_core
                    .receive_pending_message(record, payer, evidence, &programs)
                    .await?;
                if secrets.is_empty() {
                    return wallet_core
                        .poll_and_finalize_public_transaction(tx_hash)
                        .await;
                }
                let decode: Vec<_> = secrets
                    .into_iter()
                    .map(|secret| Decode(secret, to.account_id))
                    .collect();
                wallet_core
                    .poll_and_finalize_pp_transaction(tx_hash, &decode)
                    .await
            }
        }
    }
}

fn receipt_programs(program: AccountId) -> Result<ProgramCatalog> {
    // The native program runs as protocol code, so its receipt needs no program.
    if program == NATIVE_TOKEN_PROGRAM_ID {
        return Ok(ProgramCatalog::default());
    }
    anyhow::ensure!(
        program == programs::token_account_id(),
        "Program {program} is not one this wallet can receive messages for"
    );
    Ok(ProgramCatalog::from([(program, programs::token())]))
}
