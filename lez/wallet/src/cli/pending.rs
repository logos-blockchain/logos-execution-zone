use std::path::PathBuf;

use anyhow::{Context as _, Result, bail};
use clap::{Args, Subcommand};
use lee::{
    AccountId, PredictedCrossMessages,
    privacy_preserving_transaction::circuit::{Dependency, ProgramCatalog, ProgramKind},
    program::Program,
};
use lee_core::CommitmentPosition;

use crate::{
    AccountIdentity, AccountMention, AsyncDelivery, PendingMessage, Promotions, WalletCore,
    WalletSequencerClient,
    account::AccountIdWithPrivacy,
    cli::{CliAccountMention, SubcommandReturnValue, WalletSubcommand},
    storage::Storage,
};

/// Represents generic CLI subcommand for a wallet working with pending messages.
#[derive(Subcommand, Debug, Clone)]
pub enum PendingSubcommand {
    /// List the pending messages sent to this wallet's accounts.
    List,
    /// Receive a pending message sent to one of this wallet's accounts, executing it as
    /// published.
    Receive {
        /// `position` - the pending message's position in the commitment tree.
        #[arg(long)]
        position: CommitmentPosition,
        #[command(flatten)]
        inputs: Box<ReceiptInputs>,
    },
}

/// The execution inputs a receipt takes beside its pending message.
#[derive(Args, Debug, Clone, Default)]
pub struct ReceiptInputs {
    /// An actor the receipt declares unauthorized: an account and the program whose actor
    /// state it selects.
    #[arg(long, num_args = 2, value_names = ["ACCOUNT", "PROGRAM"])]
    pub actor: Vec<String>,
    /// An actor the receipt declares with its account's authorization, which covers every
    /// delivery to that account, the received message included.
    #[arg(long, num_args = 2, value_names = ["ACCOUNT", "PROGRAM"])]
    pub authorized_actor: Vec<String>,
    /// A program ELF never deployed on chain, run as a shadow program.
    #[arg(long)]
    pub shadow_program: Vec<PathBuf>,
    /// A destination of an async message public execution sends: declared when public, its
    /// recovery binding published when private.
    #[arg(long, num_args = 2, value_names = ["ACCOUNT", "PROGRAM"])]
    pub async_destination: Vec<String>,
    /// A destination of an async message private execution sends: declared when public,
    /// sealing the message when private.
    #[arg(long, num_args = 2, value_names = ["ACCOUNT", "PROGRAM"])]
    pub seal_destination: Vec<String>,
    /// The opening of a blinded address a private account above is reached at, instead of its
    /// canonical address when it is a destination.
    #[arg(long, num_args = 2, value_names = ["ACCOUNT", "OPENING"])]
    pub address_opening: Vec<String>,
    /// The index of an async message from public execution to execute at once.
    #[arg(long)]
    pub promote_public: Vec<u64>,
    /// The index of an async message from private execution to execute at once.
    #[arg(long)]
    pub promote_private: Vec<u64>,
    /// Execute at once only the listed async messages from private execution.
    #[arg(long)]
    pub listed_only: bool,
    /// A JSON file of the deliveries public execution is predicted to send private execution.
    #[arg(long)]
    pub cross_messages: Option<PathBuf>,
}

impl WalletSubcommand for PendingSubcommand {
    async fn handle_subcommand<C: WalletSequencerClient>(
        self,
        wallet_core: &mut WalletCore<C>,
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
            Self::Receive { position, inputs } => {
                let ReceiptInputs {
                    actor,
                    authorized_actor,
                    shadow_program,
                    async_destination,
                    seal_destination,
                    address_opening,
                    promote_public,
                    promote_private,
                    listed_only,
                    cross_messages,
                } = *inputs;
                let pending = wallet_core
                    .find_pending_message(position)
                    .await?
                    .context("No pending message at this position")?;
                let storage = wallet_core.storage();
                let openings = address_openings(&address_opening, storage)?;
                let mut accounts: Vec<AccountMention> =
                    actors(&actor, storage, CliAccountMention::unsigned, &openings)?
                        .into_iter()
                        .map(AccountMention::without_authorization)
                        .collect();
                accounts.extend(actors(
                    &authorized_actor,
                    storage,
                    CliAccountMention::signer,
                    &openings,
                )?);
                let (declared, async_delivery) = wallet_core.async_destinations(
                    actors(
                        &async_destination,
                        storage,
                        CliAccountMention::unsigned,
                        &openings,
                    )?,
                    actors(
                        &seal_destination,
                        storage,
                        CliAccountMention::unsigned,
                        &openings,
                    )?,
                )?;
                accounts.extend(declared);
                let programs = ProgramCatalog {
                    programs: shadow_program
                        .iter()
                        .map(|path| {
                            let elf = std::fs::read(path)
                                .with_context(|| format!("failed to read {}", path.display()))?;
                            let program = Program::new(elf.into())?;
                            Ok((
                                AccountId::for_shadow_program(&program.id()),
                                Dependency {
                                    program,
                                    kind: ProgramKind::Shadow,
                                },
                            ))
                        })
                        .collect::<Result<_>>()?,
                };
                let cross_messages = cross_messages
                    .map(|path| -> Result<PredictedCrossMessages> {
                        Ok(serde_json::from_slice(
                            &std::fs::read(&path)
                                .with_context(|| format!("failed to read {}", path.display()))?,
                        )?)
                    })
                    .transpose()?;
                let (tx_hash, _) = wallet_core
                    .receive_pending_message_with(
                        pending,
                        accounts,
                        &programs,
                        cross_messages,
                        AsyncDelivery {
                            promotions: Promotions {
                                public: promote_public.into_iter().collect(),
                                private: promote_private.into_iter().collect(),
                                listed_only,
                            },
                            ..async_delivery
                        },
                    )
                    .await?;
                wallet_core.finish_transaction(tx_hash).await
            }
        }
    }
}

// The actor of each ACCOUNT PROGRAM pair, its account read by `identity` and reached at the
// blinded addresses `openings` give it.
fn actors(
    pairs: &[String],
    storage: &Storage,
    identity: fn(CliAccountMention, &Storage) -> Result<AccountIdentity>,
    openings: &[(AccountId, [u8; 32])],
) -> Result<Vec<AccountMention>> {
    pairs
        .as_chunks::<2>()
        .0
        .iter()
        .map(|[account, program]| {
            let mention =
                identity(account.parse()?, storage)?.select_program_actor_state(program.parse()?);
            let account_id = mention.identity.account_id();
            Ok(AccountMention {
                address_openings: openings
                    .iter()
                    .filter(|(reached, _)| *reached == account_id)
                    .map(|(_, opening)| *opening)
                    .collect(),
                ..mention
            })
        })
        .collect()
}

// The private account and opening of each ACCOUNT OPENING pair.
fn address_openings(pairs: &[String], storage: &Storage) -> Result<Vec<(AccountId, [u8; 32])>> {
    pairs
        .as_chunks::<2>()
        .0
        .iter()
        .map(|[account, opening]| {
            let AccountIdWithPrivacy::Private(account_id) =
                account.parse::<CliAccountMention>()?.resolve(storage)?
            else {
                bail!("A blinded address belongs to a private account");
            };
            let opening = hex::decode(opening)
                .context("An opening must be valid hex")?
                .try_into()
                .map_err(|v: Vec<u8>| {
                    anyhow::anyhow!("An opening must be exactly 32 bytes, got {}", v.len())
                })?;
            Ok((account_id, opening))
        })
        .collect()
}
