use anyhow::Result;
use clap::Subcommand;
use lee::PublicKey;

use crate::{
    AccountIdentity, WalletCore,
    account::AccountIdWithPrivacy,
    cli::{CliAccountMention, SubcommandReturnValue, WalletSubcommand, destination},
    program_facades::{CreditDelivery, native_token_transfer::NativeTokenTransfer},
};

/// Represents generic CLI subcommand for a wallet working with native token transfer program.
#[derive(Subcommand, Debug, Clone)]
pub enum AuthTransferSubcommand {
    /// Send native tokens from one account to another with variable privacy.
    ///
    /// If receiver is private, then `to` and (`to_npk` , `to_vpk`) is a mutually exclusive
    /// patterns.
    ///
    /// First is used for owned accounts, second otherwise.
    Send {
        /// Either 32 byte base58 account id string with privacy prefix or a label.
        #[arg(long)]
        from: CliAccountMention,
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
        /// Recipient's public key, for a public account that has not been used yet.
        #[arg(long, conflicts_with_all = ["to", "to_npk", "to_vpk", "to_keys"])]
        to_pk: Option<PublicKey>,
        /// amount - amount of balance to move.
        #[arg(long)]
        amount: u128,
    },
}

impl WalletSubcommand for AuthTransferSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::Send {
                from,
                to,
                to_npk,
                to_vpk,
                to_keys,
                to_pk,
                amount,
            } => {
                let storage = wallet_core.storage();
                let named = to.is_some();
                let sender = from.signer(storage)?;
                let recipient = destination(storage, to, to_npk, to_vpk, to_keys, to_pk)?;
                let privacy_id = |identity: &AccountIdentity| {
                    if identity.is_private() {
                        AccountIdWithPrivacy::Private(identity.account_id())
                    } else {
                        AccountIdWithPrivacy::Public(identity.account_id())
                    }
                };
                ensure_not_self_transfer(
                    privacy_id(&sender),
                    named.then(|| privacy_id(&recipient)),
                )?;
                let (tx_hash, _) = NativeTokenTransfer(wallet_core)
                    .transfer(sender, recipient, amount, CreditDelivery::Automatic)
                    .await?;
                wallet_core.finish_transaction(tx_hash).await
            }
        }
    }
}

/// Shielding and deshielding to your own account are legitimate, so a transfer
/// is only self-directed when the privacy-qualified identities are equal.
fn ensure_not_self_transfer(
    from: AccountIdWithPrivacy,
    to: Option<AccountIdWithPrivacy>,
) -> Result<()> {
    if to == Some(from) {
        anyhow::bail!("Invalid transfer: --from and --to are the same account ({from})");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID_A: [u8; 32] = [1; 32];
    const ID_B: [u8; 32] = [2; 32];

    #[test]
    fn rejects_transfer_to_the_same_public_account() {
        let account = AccountIdWithPrivacy::Public(AccountId::new(ID_A));

        let result = ensure_not_self_transfer(account, Some(account));

        assert!(result.is_err(), "public self-transfer must be rejected");
    }

    #[test]
    fn rejects_transfer_to_the_same_private_account() {
        let account = AccountIdWithPrivacy::Private(AccountId::new(ID_A));

        let result = ensure_not_self_transfer(account, Some(account));

        assert!(result.is_err(), "private self-transfer must be rejected");
    }

    #[test]
    fn allows_shielding_and_deshielding_your_own_account() {
        let public = AccountIdWithPrivacy::Public(AccountId::new(ID_A));
        let private = AccountIdWithPrivacy::Private(AccountId::new(ID_A));

        assert!(
            ensure_not_self_transfer(public, Some(private)).is_ok(),
            "shielding your own account must stay allowed"
        );
        assert!(
            ensure_not_self_transfer(private, Some(public)).is_ok(),
            "deshielding your own account must stay allowed"
        );
    }

    #[test]
    fn allows_transfer_between_different_accounts() {
        let from = AccountIdWithPrivacy::Public(AccountId::new(ID_A));
        let to = AccountIdWithPrivacy::Public(AccountId::new(ID_B));

        assert!(ensure_not_self_transfer(from, Some(to)).is_ok());
    }

    #[test]
    fn allows_recipient_given_by_public_keys() {
        let from = AccountIdWithPrivacy::Public(AccountId::new(ID_A));

        assert!(
            ensure_not_self_transfer(from, None).is_ok(),
            "recipient given by keys has no resolved id to compare"
        );
    }
}
