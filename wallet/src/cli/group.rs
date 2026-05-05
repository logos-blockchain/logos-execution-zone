use anyhow::{Context as _, Result};
use clap::Subcommand;
use key_protocol::key_management::group_key_holder::GroupKeyHolder;

use crate::{
    WalletCore,
    cli::{SubcommandReturnValue, WalletSubcommand},
};

/// Group key management commands.
#[derive(Subcommand, Debug, Clone)]
pub enum GroupSubcommand {
    /// Create a new group with a fresh random GMS.
    New {
        /// Human-readable name for the group.
        name: String,
    },
    /// Import a group from raw GMS bytes.
    Import {
        /// Human-readable name for the group.
        name: String,
        /// Raw GMS as 64-character hex string.
        #[arg(long)]
        gms: String,
    },
    /// Export the raw GMS hex for backup or manual distribution.
    Export {
        /// Group name.
        name: String,
    },
    /// List all groups.
    #[command(visible_alias = "ls")]
    List,
    /// Remove a group from the wallet.
    Remove {
        /// Group name.
        name: String,
    },
    /// Seal the group's GMS for a recipient (invite).
    Invite {
        /// Group name.
        name: String,
        /// Recipient's sealing public key as hex string.
        #[arg(long)]
        key: String,
    },
    /// Unseal a received GMS and store it (join a group).
    Join {
        /// Human-readable name to store the group under.
        name: String,
        /// Sealed GMS as hex string (from the inviter).
        #[arg(long)]
        sealed: String,
        /// Account ID whose viewing secret key to use for decryption.
        #[arg(long)]
        account: String,
    },
}

impl WalletSubcommand for GroupSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::New { name } => {
                if wallet_core
                    .storage()
                    .user_data
                    .group_key_holder(&name)
                    .is_some()
                {
                    anyhow::bail!("Group '{name}' already exists");
                }

                let holder = GroupKeyHolder::new();
                wallet_core.insert_group_key_holder(name.clone(), holder);
                wallet_core.store_persistent_data().await?;

                println!("Created group '{name}'");
                Ok(SubcommandReturnValue::Empty)
            }

            Self::Import { name, gms } => {
                if wallet_core
                    .storage()
                    .user_data
                    .group_key_holder(&name)
                    .is_some()
                {
                    anyhow::bail!("Group '{name}' already exists");
                }

                let gms_bytes: [u8; 32] = hex::decode(&gms)
                    .context("Invalid GMS hex")?
                    .try_into()
                    .map_err(|_err| anyhow::anyhow!("GMS must be exactly 32 bytes"))?;

                let holder = GroupKeyHolder::from_gms(gms_bytes);
                wallet_core.insert_group_key_holder(name.clone(), holder);
                wallet_core.store_persistent_data().await?;

                println!("Imported group '{name}'");
                Ok(SubcommandReturnValue::Empty)
            }

            Self::Export { name } => {
                let holder = wallet_core
                    .storage()
                    .user_data
                    .group_key_holder(&name)
                    .context(format!("Group '{name}' not found"))?;

                let gms_hex = hex::encode(holder.dangerous_raw_gms());

                println!("Group: {name}");
                println!("GMS: {gms_hex}");
                Ok(SubcommandReturnValue::Empty)
            }

            Self::List => {
                let holders = &wallet_core.storage().user_data.group_key_holders;
                if holders.is_empty() {
                    println!("No groups found");
                } else {
                    for name in holders.keys() {
                        println!("{name}");
                    }
                }
                Ok(SubcommandReturnValue::Empty)
            }

            Self::Remove { name } => {
                if wallet_core.remove_group_key_holder(&name).is_none() {
                    anyhow::bail!("Group '{name}' not found");
                }

                wallet_core.store_persistent_data().await?;
                println!("Removed group '{name}'");
                Ok(SubcommandReturnValue::Empty)
            }

            Self::Invite { name, key } => {
                let holder = wallet_core
                    .storage()
                    .user_data
                    .group_key_holder(&name)
                    .context(format!("Group '{name}' not found"))?;

                let key_bytes = hex::decode(&key).context("Invalid key hex")?;
                let recipient_key =
                    nssa_core::encryption::shared_key_derivation::Secp256k1Point(key_bytes);

                let sealed = holder.seal_for(&recipient_key);
                println!("{}", hex::encode(&sealed));
                Ok(SubcommandReturnValue::Empty)
            }

            Self::Join {
                name,
                sealed,
                account,
            } => {
                if wallet_core
                    .storage()
                    .user_data
                    .group_key_holder(&name)
                    .is_some()
                {
                    anyhow::bail!("Group '{name}' already exists");
                }

                let sealed_bytes = hex::decode(&sealed).context("Invalid sealed hex")?;

                let account_id: nssa::AccountId = account.parse().context("Invalid account ID")?;
                let (keychain, _, _) = wallet_core
                    .storage()
                    .user_data
                    .get_private_account(account_id)
                    .context("Private account not found")?;
                let vsk = keychain.private_key_holder.viewing_secret_key;

                let holder = GroupKeyHolder::unseal(&sealed_bytes, &vsk)
                    .map_err(|e| anyhow::anyhow!("Failed to unseal: {e:?}"))?;

                wallet_core.insert_group_key_holder(name.clone(), holder);
                wallet_core.store_persistent_data().await?;

                println!("Joined group '{name}'");
                Ok(SubcommandReturnValue::Empty)
            }
        }
    }
}
