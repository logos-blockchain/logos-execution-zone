use anyhow::{Context as _, Result};
use clap::Subcommand;
use key_protocol::key_management::group_key_holder::GroupKeyHolder;
use nssa::AccountId;
use nssa_core::program::PdaSeed;

use crate::{
    WalletCore,
    cli::{SubcommandReturnValue, WalletSubcommand},
};

/// Group PDA management commands.
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
        /// Epoch (defaults to 0).
        #[arg(long, default_value = "0")]
        epoch: u32,
    },
    /// Export the raw GMS hex for backup or manual distribution.
    Export {
        /// Group name.
        name: String,
    },
    /// List all groups with their epochs.
    #[command(visible_alias = "ls")]
    List,
    /// Derive keys for a PDA seed and show the resulting AccountId.
    Derive {
        /// Group name.
        name: String,
        /// PDA seed as 64-character hex string.
        #[arg(long)]
        seed: String,
        /// Program ID as hex string (u32x8 little-endian).
        #[arg(long)]
        program_id: String,
    },
    /// Remove a group from the wallet.
    Remove {
        /// Group name.
        name: String,
    },
    /// Seal the group's GMS for a recipient (invite).
    Invite {
        /// Group name.
        name: String,
        /// Recipient's viewing public key as hex string.
        #[arg(long)]
        vpk: String,
    },
    /// Unseal a received GMS and store it (join a group).
    Join {
        /// Human-readable name to store the group under.
        name: String,
        /// Sealed GMS as hex string (from the inviter).
        #[arg(long)]
        sealed: String,
        /// Account label or Private/<id> whose VSK to use for decryption.
        #[arg(long)]
        account: String,
    },
    /// Ratchet the GMS to exclude removed members.
    Ratchet {
        /// Group name.
        name: String,
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
                    .get_group_key_holder(&name)
                    .is_some()
                {
                    anyhow::bail!("Group '{name}' already exists");
                }

                let holder = GroupKeyHolder::new();
                wallet_core
                    .storage_mut()
                    .user_data
                    .insert_group_key_holder(name.clone(), holder);
                wallet_core.store_persistent_data().await?;

                println!("Created group '{name}' at epoch 0");
                Ok(SubcommandReturnValue::Empty)
            }

            Self::Import { name, gms, epoch } => {
                if wallet_core
                    .storage()
                    .user_data
                    .get_group_key_holder(&name)
                    .is_some()
                {
                    anyhow::bail!("Group '{name}' already exists");
                }

                let gms_bytes: [u8; 32] = hex::decode(&gms)
                    .context("Invalid GMS hex")?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("GMS must be exactly 32 bytes"))?;

                let holder = GroupKeyHolder::from_gms_and_epoch(gms_bytes, epoch);
                wallet_core
                    .storage_mut()
                    .user_data
                    .insert_group_key_holder(name.clone(), holder);
                wallet_core.store_persistent_data().await?;

                println!("Imported group '{name}' at epoch {epoch}");
                Ok(SubcommandReturnValue::Empty)
            }

            Self::Export { name } => {
                let holder = wallet_core
                    .storage()
                    .user_data
                    .get_group_key_holder(&name)
                    .context(format!("Group '{name}' not found"))?;

                let gms_hex = hex::encode(holder.dangerous_raw_gms());
                let epoch = holder.epoch();

                println!("Group: {name}");
                println!("Epoch: {epoch}");
                println!("GMS: {gms_hex}");
                Ok(SubcommandReturnValue::Empty)
            }

            Self::List => {
                let holders = &wallet_core.storage().user_data.group_key_holders;
                if holders.is_empty() {
                    println!("No groups found");
                } else {
                    for (name, holder) in holders {
                        println!("{name} (epoch {})", holder.epoch());
                    }
                }
                Ok(SubcommandReturnValue::Empty)
            }

            Self::Derive {
                name,
                seed,
                program_id,
            } => {
                let holder = wallet_core
                    .storage()
                    .user_data
                    .get_group_key_holder(&name)
                    .context(format!("Group '{name}' not found"))?;

                let seed_bytes: [u8; 32] = hex::decode(&seed)
                    .context("Invalid seed hex")?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Seed must be exactly 32 bytes"))?;
                let pda_seed = PdaSeed::new(seed_bytes);

                let pid_bytes =
                    hex::decode(&program_id).context("Invalid program ID hex")?;
                if pid_bytes.len() != 32 {
                    anyhow::bail!("Program ID must be exactly 32 bytes");
                }
                let mut pid: nssa_core::program::ProgramId = [0; 8];
                for (i, chunk) in pid_bytes.chunks_exact(4).enumerate() {
                    pid[i] = u32::from_le_bytes(chunk.try_into().unwrap());
                }

                let keys = holder.derive_keys_for_pda(&pda_seed);
                let npk = keys.generate_nullifier_public_key();
                let vpk = keys.generate_viewing_public_key();
                let account_id = AccountId::for_private_pda(&pid, &pda_seed, &npk);

                println!("Group: {name}");
                println!("NPK: {}", hex::encode(npk.0));
                println!("VPK: {}", hex::encode(&vpk.0));
                println!("AccountId: {account_id}");
                Ok(SubcommandReturnValue::Empty)
            }

            Self::Remove { name } => {
                if wallet_core
                    .storage_mut()
                    .user_data
                    .group_key_holders
                    .remove(&name)
                    .is_none()
                {
                    anyhow::bail!("Group '{name}' not found");
                }

                wallet_core.store_persistent_data().await?;
                println!("Removed group '{name}'");
                Ok(SubcommandReturnValue::Empty)
            }

            Self::Invite { name, vpk } => {
                let holder = wallet_core
                    .storage()
                    .user_data
                    .get_group_key_holder(&name)
                    .context(format!("Group '{name}' not found"))?;

                let vpk_bytes = hex::decode(&vpk).context("Invalid VPK hex")?;
                let recipient_vpk =
                    nssa_core::encryption::shared_key_derivation::Secp256k1Point(vpk_bytes);

                let sealed = holder.seal_for(&recipient_vpk);
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
                    .get_group_key_holder(&name)
                    .is_some()
                {
                    anyhow::bail!("Group '{name}' already exists");
                }

                let sealed_bytes = hex::decode(&sealed).context("Invalid sealed hex")?;

                // Resolve the account to get the VSK
                let account_id: nssa::AccountId = account
                    .parse()
                    .context("Invalid account ID (use Private/<base58>)")?;
                let (keychain, _) = wallet_core
                    .storage()
                    .user_data
                    .get_private_account(account_id)
                    .context("Private account not found")?;
                let vsk = keychain.private_key_holder.viewing_secret_key;

                let holder = GroupKeyHolder::unseal(&sealed_bytes, &vsk)
                    .map_err(|e| anyhow::anyhow!("Failed to unseal: {e:?}"))?;

                let epoch = holder.epoch();
                wallet_core
                    .storage_mut()
                    .user_data
                    .insert_group_key_holder(name.clone(), holder);
                wallet_core.store_persistent_data().await?;

                println!("Joined group '{name}' at epoch {epoch}");
                Ok(SubcommandReturnValue::Empty)
            }

            Self::Ratchet { name } => {
                let holder = wallet_core
                    .storage_mut()
                    .user_data
                    .group_key_holders
                    .get_mut(&name)
                    .context(format!("Group '{name}' not found"))?;

                let mut salt = [0_u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
                holder.ratchet(salt);

                let epoch = holder.epoch();
                wallet_core.store_persistent_data().await?;

                println!("Ratcheted group '{name}' to epoch {epoch}");
                println!("Re-invite remaining members with 'group invite'");
                Ok(SubcommandReturnValue::Empty)
            }
        }
    }
}
