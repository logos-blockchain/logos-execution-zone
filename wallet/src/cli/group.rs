use anyhow::{Context as _, Result};
use clap::Subcommand;
use key_protocol::key_management::group_key_holder::{GroupKeyHolder, SealingPublicKey};

use crate::{
    WalletCore,
    account::Label,
    cli::{SubcommandReturnValue, WalletSubcommand},
};

/// Group key management commands.
#[derive(Subcommand, Debug, Clone)]
pub enum GroupSubcommand {
    /// Create a new group with a fresh random GMS.
    New {
        /// Human-readable name for the group.
        name: Label,
    },
    /// List all groups.
    #[command(visible_alias = "ls")]
    List,
    /// Remove a group from the wallet.
    Remove {
        /// Group name.
        name: Label,
    },
    /// Seal the group's GMS for a recipient (invite).
    Invite {
        /// Group name.
        name: Label,
        /// Recipient's sealing public key as hex string.
        #[arg(long)]
        key: String,
    },
    /// Unseal a received GMS and store it (join a group).
    /// Uses the wallet's dedicated sealing key (generated via `new-sealing-key`).
    Join {
        /// Human-readable name to store the group under.
        name: Label,
        /// Sealed GMS as hex string (from the inviter).
        #[arg(long)]
        sealed: String,
    },
    /// Generate a dedicated sealing key pair for GMS distribution.
    /// Share the printed public key with group members so they can seal GMS for you.
    NewSealingKey,
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
                    .key_chain()
                    .group_key_holder(&name)
                    .is_some()
                {
                    anyhow::bail!("Group '{name}' already exists");
                }

                let holder = GroupKeyHolder::new();
                wallet_core.insert_group_key_holder(name.clone(), holder);
                wallet_core.store_persistent_data()?;

                println!("Created group '{name}'");
                Ok(SubcommandReturnValue::Empty)
            }

            Self::List => {
                let mut empty = true;
                let holders_iter = wallet_core.storage().key_chain().group_key_holders_iter();
                for (name, _) in holders_iter {
                    empty = false;
                    println!("{name}");
                }
                if empty {
                    println!("No groups found");
                }
                Ok(SubcommandReturnValue::Empty)
            }

            Self::Remove { name } => {
                if wallet_core.remove_group_key_holder(&name).is_none() {
                    anyhow::bail!("Group '{name}' not found");
                }

                wallet_core.store_persistent_data()?;
                println!("Removed group '{name}'");
                Ok(SubcommandReturnValue::Empty)
            }

            Self::Invite { name, key } => {
                let holder = wallet_core
                    .storage()
                    .key_chain()
                    .group_key_holder(&name)
                    .context(format!("Group '{name}' not found"))?;

                let key_bytes = hex::decode(&key).context("Invalid key hex")?;
                let recipient_key =
                    key_protocol::key_management::group_key_holder::SealingPublicKey::from_bytes(
                        key_bytes,
                    );

                let sealed = holder.seal_for(&recipient_key);
                println!("{}", hex::encode(&sealed));
                Ok(SubcommandReturnValue::Empty)
            }

            Self::Join { name, sealed } => {
                if wallet_core
                    .storage()
                    .key_chain()
                    .group_key_holder(&name)
                    .is_some()
                {
                    anyhow::bail!("Group '{name}' already exists");
                }

                let sealing_key = wallet_core
                    .storage()
                    .key_chain()
                    .sealing_secret_key()
                    .context("No sealing key found. Run 'wallet group new-sealing-key' first.")?;

                let sealed_bytes = hex::decode(&sealed).context("Invalid sealed hex")?;

                let holder = GroupKeyHolder::unseal(&sealed_bytes, sealing_key)
                    .map_err(|e| anyhow::anyhow!("Failed to unseal: {e:?}"))?;

                wallet_core.insert_group_key_holder(name.clone(), holder);
                wallet_core.store_persistent_data()?;

                println!("Joined group '{name}'");
                Ok(SubcommandReturnValue::Empty)
            }

            Self::NewSealingKey => {
                if wallet_core
                    .storage()
                    .key_chain()
                    .sealing_secret_key()
                    .is_some()
                {
                    anyhow::bail!("Sealing key already exists. Each wallet has one sealing key.");
                }

                let mut secret: nssa_core::encryption::Scalar = [0_u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);
                let public_key = SealingPublicKey::from_scalar(secret);

                wallet_core.set_sealing_secret_key(secret);
                wallet_core.store_persistent_data()?;

                println!("Sealing key generated.");
                println!("Public key: {}", hex::encode(public_key.to_bytes()));
                println!("Share this public key with group members so they can seal GMS for you.");
                Ok(SubcommandReturnValue::Empty)
            }
        }
    }
}
