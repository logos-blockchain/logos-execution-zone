use anyhow::{Context as _, Result, bail};
use clap::Subcommand;
use lee::AccountId;
use lee_core::PrivateAccountKind;
use token_core::HoldingKind;

use crate::{
    AccountIdentity, WalletCore,
    account::AccountIdWithPrivacy,
    cli::{CliAccountMention, SubcommandReturnValue, WalletSubcommand},
    program_facades::token::Token,
};

/// Token program subcommands. A holding is derived from its owner and the token definition.
#[derive(Subcommand, Debug, Clone)]
pub enum TokenSubcommand {
    /// Print the holding address of `owner` for `definition`.
    Address {
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        owner: CliAccountMention,
        /// Token definition account - valid 32 byte base58 string WITHOUT privacy prefix.
        #[arg(long)]
        definition: AccountId,
        /// Holding kind: fungible, nft-master or nft-printed-copy.
        #[arg(long, default_value = "fungible", value_parser = parse_holding_kind)]
        kind: HoldingKind,
    },
    /// Show the holding of `owner` for `definition`.
    Holding {
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        owner: CliAccountMention,
        /// Token definition account - valid 32 byte base58 string WITHOUT privacy prefix.
        #[arg(long)]
        definition: AccountId,
        /// Holding kind: fungible, nft-master or nft-printed-copy.
        #[arg(long, default_value = "fungible", value_parser = parse_holding_kind)]
        kind: HoldingKind,
    },
    /// Produce a new token whose supply is held by `owner`.
    New {
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        definition: CliAccountMention,
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        owner: CliAccountMention,
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        total_supply: u128,
    },
    /// Initialize the holding of `owner` for `definition`.
    Initialize {
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        definition: CliAccountMention,
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        owner: CliAccountMention,
        /// A funded public account to pay the fee. If omitted, the wallet selects a payer from
        /// the transaction's signing accounts. An explicitly chosen input is also authorized.
        #[arg(long)]
        payer: Option<CliAccountMention>,
    },
    /// Send tokens from the holding of `from` to the holding of the recipient.
    ///
    /// The recipient is either an owner known to the wallet (`to`) or a foreign private owner
    /// given by its public keys.
    Send {
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        from: CliAccountMention,
        /// Token definition account - valid 32 byte base58 string WITHOUT privacy prefix.
        #[arg(long)]
        definition: AccountId,
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        to: Option<CliAccountMention>,
        /// `to_npk` - valid 32 byte hex string.
        #[arg(long, conflicts_with = "to_keys")]
        to_npk: Option<String>,
        /// `to_vpk` - valid hex-encoded ML-KEM-768 encapsulation key (1184 bytes).
        #[arg(long, conflicts_with = "to_keys")]
        to_vpk: Option<String>,
        /// Path to a keys file exported by `wallet account show-keys`, containing npk
        /// and vpk on separate lines. Replaces `--to-npk` and `--to-vpk`.
        #[arg(long, conflicts_with_all = ["to_npk", "to_vpk"])]
        to_keys: Option<String>,
        /// Identifier of the foreign private owner (only used with `--to-npk`/`--to-vpk` or
        /// `--to-keys`).
        #[arg(long)]
        to_identifier: Option<u128>,
        /// Holding kind: fungible, nft-master or nft-printed-copy.
        #[arg(long, default_value = "fungible", value_parser = parse_holding_kind)]
        kind: HoldingKind,
        /// amount - amount of balance to move.
        #[arg(long)]
        amount: u128,
    },
    /// Burn tokens from the holding of `holder`, modify `definition`.
    Burn {
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        definition: CliAccountMention,
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        holder: CliAccountMention,
        /// Holding kind: fungible, nft-master or nft-printed-copy.
        #[arg(long, default_value = "fungible", value_parser = parse_holding_kind)]
        kind: HoldingKind,
        /// amount - amount of balance to burn.
        #[arg(long)]
        amount: u128,
    },
    /// Mint tokens into the holding of the holder, modify `definition`.
    ///
    /// The holder is either an owner known to the wallet (`holder`) or a foreign private owner
    /// given by its public keys.
    Mint {
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        definition: CliAccountMention,
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        holder: Option<CliAccountMention>,
        /// `holder_npk` - valid 32 byte hex string.
        #[arg(long, conflicts_with = "holder_keys")]
        holder_npk: Option<String>,
        /// `holder_vpk` - valid hex-encoded ML-KEM-768 encapsulation key (1184 bytes).
        #[arg(long, conflicts_with = "holder_keys")]
        holder_vpk: Option<String>,
        /// Path to a keys file exported by `wallet account show-keys`, containing npk
        /// and vpk on separate lines. Replaces `--holder-npk` and `--holder-vpk`.
        #[arg(long, conflicts_with_all = ["holder_npk", "holder_vpk"])]
        holder_keys: Option<String>,
        /// Identifier of the foreign private owner (only used with `--holder-npk`/`--holder-vpk`
        /// or `--holder-keys`).
        #[arg(long)]
        holder_identifier: Option<u128>,
        /// amount - amount of balance to mint.
        #[arg(long)]
        amount: u128,
    },
}

impl WalletSubcommand for TokenSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let (tx_hash, decode) = match self {
            Self::Address {
                owner,
                definition,
                kind,
            } => {
                let owner = identity(&owner, wallet_core, false)?;
                println!(
                    "{}",
                    Token(wallet_core).holding_id(&owner, definition, kind)?
                );
                return Ok(SubcommandReturnValue::Empty);
            }
            Self::Holding {
                owner,
                definition,
                kind,
            } => {
                let owner = identity(&owner, wallet_core, false)?;
                match Token(wallet_core).holding(&owner, definition, kind).await? {
                    Some(holding) => println!("{}", serde_json::to_string(&holding)?),
                    None => println!("No holding"),
                }
                return Ok(SubcommandReturnValue::Empty);
            }
            Self::New {
                definition,
                owner,
                name,
                total_supply,
            } => {
                let definition = identity(&definition, wallet_core, true)?;
                let owner = identity(&owner, wallet_core, false)?;
                Token(wallet_core)
                    .send_new_definition(definition, owner, name, total_supply)
                    .await?
            }
            Self::Initialize {
                definition,
                owner,
                payer,
            } => {
                let payer = payer
                    .as_ref()
                    .map(|mention| resolve_public(mention, wallet_core))
                    .transpose()?;
                let definition = match definition.resolve(wallet_core.storage())? {
                    AccountIdWithPrivacy::Public(id) => AccountIdentity::PublicNoSign(id),
                    AccountIdWithPrivacy::Private(id) => wallet_core
                        .resolve_private_account(id)
                        .with_context(|| format!("Private account {id} is not in the wallet"))?,
                };
                let owner = identity(&owner, wallet_core, false)?;
                Token(wallet_core)
                    .send_initialize(definition, owner, payer)
                    .await?
            }
            Self::Send {
                from,
                definition,
                to,
                to_npk,
                to_vpk,
                to_keys,
                to_identifier,
                kind,
                amount,
            } => {
                let sender = identity(&from, wallet_core, true)?;
                let recipient = recipient(to, to_npk, to_vpk, to_keys, to_identifier, wallet_core)?;
                Token(wallet_core)
                    .send_transfer(sender, recipient, definition, kind, amount)
                    .await?
            }
            Self::Burn {
                definition,
                holder,
                kind,
                amount,
            } => {
                let definition = identity(&definition, wallet_core, false)?;
                let holder = identity(&holder, wallet_core, true)?;
                Token(wallet_core)
                    .send_burn(definition, holder, kind, amount)
                    .await?
            }
            Self::Mint {
                definition,
                holder,
                holder_npk,
                holder_vpk,
                holder_keys,
                holder_identifier,
                amount,
            } => {
                let definition = identity(&definition, wallet_core, true)?;
                let holder = recipient(
                    holder,
                    holder_npk,
                    holder_vpk,
                    holder_keys,
                    holder_identifier,
                    wallet_core,
                )?;
                Token(wallet_core)
                    .send_mint(definition, holder, amount)
                    .await?
            }
        };
        wallet_core
            .poll_and_finalize_pp_transaction(tx_hash, &decode)
            .await
    }
}

fn resolve_public(mention: &CliAccountMention, wallet_core: &WalletCore) -> Result<AccountId> {
    match mention.resolve(wallet_core.storage())? {
        AccountIdWithPrivacy::Public(account_id) => Ok(account_id),
        AccountIdWithPrivacy::Private(_) => bail!("expected a public account, got a private one"),
    }
}

fn parse_holding_kind(value: &str) -> Result<HoldingKind, String> {
    match value {
        "fungible" => Ok(HoldingKind::Fungible),
        "nft-master" => Ok(HoldingKind::NftMaster),
        "nft-printed-copy" => Ok(HoldingKind::NftPrintedCopy),
        other => Err(format!(
            "unknown holding kind '{other}', expected fungible, nft-master or nft-printed-copy"
        )),
    }
}

fn identity(
    mention: &CliAccountMention,
    wallet_core: &WalletCore,
    sign: bool,
) -> Result<AccountIdentity> {
    match mention.resolve(wallet_core.storage())? {
        AccountIdWithPrivacy::Public(id) => Ok(mention.clone().into_public_identity(id, sign)),
        AccountIdWithPrivacy::Private(id) => wallet_core
            .resolve_private_account(id)
            .with_context(|| format!("Private account {id} is not in the wallet")),
    }
}

fn recipient(
    mention: Option<CliAccountMention>,
    npk: Option<String>,
    vpk: Option<String>,
    keys: Option<String>,
    identifier: Option<u128>,
    wallet_core: &WalletCore,
) -> Result<AccountIdentity> {
    let (npk, vpk) = match keys {
        Some(path) => {
            let (npk, vpk) = crate::cli::read_keys_file(&path)?;
            (Some(hex::encode(npk)), Some(hex::encode(vpk)))
        }
        None => (npk, vpk),
    };
    match (mention, npk, vpk) {
        (Some(mention), None, None) => identity(&mention, wallet_core, false),
        (None, Some(npk), Some(vpk)) => {
            let (npk, vpk) = crate::cli::decode_npk_vpk(&npk, &vpk)?;
            Ok(AccountIdentity::PrivateForeign {
                npk,
                vpk,
                kind: PrivateAccountKind::Regular(identifier.unwrap_or_else(rand::random)),
            })
        }
        (None, None, None)
        | (Some(_), Some(_), Some(_))
        | (_, Some(_), None)
        | (_, None, Some(_)) => {
            anyhow::bail!("Provide either the recipient's account or their public keys")
        }
    }
}
