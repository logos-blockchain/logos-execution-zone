use std::str::FromStr;

use anyhow::{Context as _, Result, bail, ensure};
use clap::Subcommand;
use lee::{AccountId, PublicKey};
use lee_core::program::PdaSeed;

use crate::{
    AccountIdentity, AccountMention, WalletCore,
    account::{AccountIdWithPrivacy, Label},
    cli::{CliAccountMention, SubcommandReturnValue, WalletSubcommand},
    storage::Storage,
};

/// Represents CLI subcommand for calling any program.
#[derive(Subcommand, Debug, Clone)]
pub enum ProgramSubcommand {
    /// Send one public transaction to any program, its message already Borsh-encoded.
    ///
    /// Nothing is inferred: the root actor and every other actor the call touches are named, and
    /// so is who signs. An actor is `<account>[@program][:sign]`,
    /// `pda:[<owner>/]<seed>[@program]` for a public PDA (admitted by its seed), or
    /// `pk:<hex>[@program]` for an account known by its public key (admitted by it). `@program`
    /// selects that program's state of the account and defaults to `--program`, as does a PDA's
    /// owner. An account is `Public/<id>`, a label, or a keycard key path; a program or owner is
    /// base58, `Public/<id>`, or a label; a seed is 0x hex or base58.
    Call {
        /// The program the message is for, unless an actor says otherwise.
        #[arg(long)]
        program: String,
        /// The message, Borsh-encoded, as hex.
        #[arg(long)]
        message_hex: String,
        /// The root actor: the message goes to it.
        #[arg(long)]
        to: CliActor,
        /// Another actor to declare. Repeatable.
        #[arg(long)]
        actor: Vec<CliActor>,
        /// A funded account to pay the fee; it signs wherever it's declared. If omitted, the
        /// wallet selects a payer from the transaction's signing accounts.
        #[arg(long)]
        payer: Option<CliAccountMention>,
    },
}

impl WalletSubcommand for ProgramSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::Call {
                program,
                message_hex,
                to,
                actor,
                payer,
            } => {
                let storage = wallet_core.storage();
                let program = public_id(&program, storage)?;
                let payer = payer
                    .map(|payer| match payer.resolve(storage)? {
                        AccountIdWithPrivacy::Public(account_id) => Ok(account_id),
                        AccountIdWithPrivacy::Private(_) => bail!("the payer must be public"),
                    })
                    .transpose()?;
                let message = hex::decode(message_hex.trim_start_matches("0x"))
                    .context("--message-hex isn't hex")?;
                let mentions = std::iter::once(to)
                    .chain(actor)
                    .map(|actor| actor.mention(program, payer, storage))
                    .collect::<Result<Vec<_>>>()?;

                let tx_hash = wallet_core
                    .send_pub_tx_paid_by(mentions, 0, message, payer)
                    .await?;
                wallet_core.finish_transaction(tx_hash).await
            }
        }
    }
}

/// An actor of a call: an account, and the program whose state of it is selected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliActor {
    pub account: CliActorAccount,
    /// `@program`; the call's `--program` when absent.
    pub program: Option<String>,
    /// `:sign`.
    pub sign: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliActorAccount {
    Mention(CliAccountMention),
    /// `pda:[<owner>/]<seed>`; the owner is the call's `--program` when absent.
    Pda {
        owner: Option<String>,
        seed: PdaSeed,
    },
    /// `pk:<hex>`.
    Key(PublicKey),
}

impl FromStr for CliActor {
    type Err = anyhow::Error;

    fn from_str(text: &str) -> Result<Self> {
        let text = text.trim();
        let (text, sign) = text
            .strip_suffix(":sign")
            .map_or((text, false), |text| (text, true));
        let (account, program) = match text.rsplit_once('@') {
            Some((account, program)) => (account, Some(program.to_owned())),
            None => (text, None),
        };
        let account = if let Some(pda) = account.strip_prefix("pda:") {
            // The owner may itself be `Public/<id>`: the seed is after the last `/`.
            let (owner, seed) = match pda.rsplit_once('/') {
                Some((owner, seed)) => (Some(owner.to_owned()), seed),
                None => (None, pda),
            };
            CliActorAccount::Pda {
                owner,
                seed: parse_seed(seed)?,
            }
        } else if let Some(key) = account.strip_prefix("pk:") {
            CliActorAccount::Key(
                key.parse()
                    .with_context(|| format!("{key:?} isn't a public key (64 hex digits)"))?,
            )
        } else {
            let Ok(mention) = CliAccountMention::from_str(account);
            CliActorAccount::Mention(mention)
        };
        Ok(Self {
            account,
            program,
            sign,
        })
    }
}

impl CliActor {
    // The payer signs wherever it's declared: the wallet won't take a non-signing payer.
    fn mention(
        self,
        program: AccountId,
        payer: Option<AccountId>,
        storage: &Storage,
    ) -> Result<AccountMention> {
        let actor_program = match &self.program {
            Some(text) => public_id(text, storage)?,
            None => program,
        };
        let identity = match self.account {
            CliActorAccount::Mention(mention) if mention.key_path().is_some() => {
                if self.sign {
                    mention.signer(storage)?
                } else {
                    mention.unsigned(storage)?
                }
            }
            CliActorAccount::Mention(mention) => match mention.resolve(storage)? {
                AccountIdWithPrivacy::Public(account_id)
                    if self.sign || payer == Some(account_id) =>
                {
                    AccountIdentity::Public(account_id)
                }
                AccountIdWithPrivacy::Public(account_id) => {
                    AccountIdentity::PublicNoSign(account_id)
                }
                AccountIdWithPrivacy::Private(_) => {
                    bail!("{mention} is private: a call is a public transaction")
                }
            },
            CliActorAccount::Pda { owner, seed } => {
                ensure!(!self.sign, "a PDA has no key to sign with");
                AccountIdentity::PublicPda {
                    program: match owner {
                        Some(owner) => public_id(&owner, storage)?,
                        None => program,
                    },
                    seed,
                }
            }
            CliActorAccount::Key(key) if self.sign || payer == Some(AccountId::from(&key)) => {
                AccountIdentity::Public(AccountId::from(&key))
            }
            CliActorAccount::Key(key) => AccountIdentity::PublicForeign(key),
        };
        Ok(identity.select_program_actor_state(actor_program))
    }
}

/// A public account named by base58, `Public/<id>`, or a label.
fn public_id(text: &str, storage: &Storage) -> Result<AccountId> {
    let resolved = AccountIdWithPrivacy::from_str(text).ok().or_else(|| {
        AccountId::from_str(text)
            .ok()
            .map(AccountIdWithPrivacy::Public)
            .or_else(|| storage.resolve_label(&Label::new(text)))
    });
    match resolved {
        Some(AccountIdWithPrivacy::Public(account_id)) => Ok(account_id),
        Some(AccountIdWithPrivacy::Private(_)) => bail!("{text} is private, not a public account"),
        None => bail!("{text} isn't an account id (base58 or Public/<id>) or a label"),
    }
}

/// 0x and 64 hex digits, or base58.
fn parse_seed(text: &str) -> Result<PdaSeed> {
    let mut bytes = [0_u8; 32];
    if let Some(hex) = text.strip_prefix("0x") {
        hex::decode_to_slice(hex, &mut bytes)
            .with_context(|| format!("{text:?} isn't a seed: 0x and 64 hex digits"))?;
    } else {
        bytes = *AccountId::from_str(text)
            .with_context(|| format!("{text:?} isn't a seed: 0x hex or base58"))?
            .value();
    }
    Ok(PdaSeed::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "6iArKUXxhUJqS7kCaPNhwMWt3ro71PDyBj7jwAyE2VQV";

    #[test]
    fn parses_accounts_with_program_and_sign() {
        let actor: CliActor = format!("Public/{ID}@{ID}:sign").parse().unwrap();
        assert!(actor.sign);
        assert_eq!(actor.program.as_deref(), Some(ID));
        assert!(matches!(
            actor.account,
            CliActorAccount::Mention(CliAccountMention::Id(AccountIdWithPrivacy::Public(_)))
        ));

        let actor: CliActor = "alice".parse().unwrap();
        assert!(!actor.sign);
        assert_eq!(actor.program, None);
        assert!(matches!(
            actor.account,
            CliActorAccount::Mention(CliAccountMention::Label(_))
        ));
    }

    #[test]
    fn parses_pdas() {
        let seed = format!("0x{}", "01".repeat(32));
        let actor: CliActor = format!("pda:Public/{ID}/{seed}").parse().unwrap();
        assert_eq!(
            actor.account,
            CliActorAccount::Pda {
                owner: Some(format!("Public/{ID}")),
                seed: PdaSeed::new([1; 32]),
            }
        );

        let actor: CliActor = format!("pda:{ID}@{ID}").parse().unwrap();
        assert_eq!(
            actor.account,
            CliActorAccount::Pda {
                owner: None,
                seed: PdaSeed::new(*AccountId::from_str(ID).unwrap().value()),
            }
        );
        assert_eq!(actor.program.as_deref(), Some(ID));

        assert!("pda:0x01".parse::<CliActor>().is_err());
    }

    #[test]
    fn parses_public_keys() {
        let key = PublicKey::new_from_private_key(&lee::PrivateKey::new_os_random());
        let actor: CliActor = format!("pk:{key}").parse().unwrap();
        assert_eq!(actor.account, CliActorAccount::Key(key));
        assert!("pk:00".parse::<CliActor>().is_err());
    }
}
