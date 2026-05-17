use anyhow::Result;
use keycard_wallet::{KeycardWallet, python_path};
use nssa::{AccountId, PrivateKey, PublicKey, Signature};

use crate::{WalletCore, cli::CliAccountMention};

/// Groups transaction signers by type to minimise Python GIL acquisition.
///
/// Local signers are signed in pure Rust; all keycard signers share a single Python session
/// with one `connect` / `close_session` pair.
#[derive(Default)]
pub struct SigningGroups {
    local: Vec<(AccountId, PrivateKey)>,
    keycard: Vec<(AccountId, String)>,
}

impl SigningGroups {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a sender. Keycard paths are queued for the hardware session; local accounts
    /// have their signing key resolved eagerly. Errors if no key is found.
    pub fn add_sender(
        &mut self,
        mention: &CliAccountMention,
        account_id: AccountId,
        wallet_core: &WalletCore,
    ) -> Result<()> {
        if let CliAccountMention::KeyPath(path) = mention {
            self.keycard.push((account_id, path.clone()));
            return Ok(());
        }
        let key = wallet_core
            .storage()
            .key_chain()
            .pub_account_signing_key(account_id)
            .ok_or_else(|| anyhow::anyhow!("signing key not found for account {account_id}"))?
            .clone();
        self.local.push((account_id, key));
        Ok(())
    }

    /// Add a recipient. Same as [`add_sender`] but silently skips accounts with no local
    /// key and no keycard path — they are foreign and require neither a signature nor a nonce.
    pub fn add_recipient(
        &mut self,
        mention: &CliAccountMention,
        account_id: AccountId,
        wallet_core: &WalletCore,
    ) -> Result<()> {
        if let CliAccountMention::KeyPath(path) = mention {
            self.keycard.push((account_id, path.clone()));
            return Ok(());
        }
        if let Some(key) = wallet_core
            .storage()
            .key_chain()
            .pub_account_signing_key(account_id)
        {
            self.local.push((account_id, key.clone()));
        }
        Ok(())
    }

    /// Returns `true` when a PIN is required (at least one keycard signer is present).
    #[must_use]
    pub const fn needs_pin(&self) -> bool {
        !self.keycard.is_empty()
    }

    /// Account IDs that require a nonce (every non-foreign signer).
    #[must_use]
    pub fn signing_ids(&self) -> Vec<AccountId> {
        self.local
            .iter()
            .map(|(id, _)| *id)
            .chain(self.keycard.iter().map(|(id, _)| *id))
            .collect()
    }

    /// Sign `hash` for every account in the group.
    ///
    /// Local accounts are signed in pure Rust. Keycard accounts share one Python session.
    pub fn sign_all(&self, hash: &[u8; 32], pin: &str) -> Result<Vec<(Signature, PublicKey)>> {
        let mut sigs: Vec<(Signature, PublicKey)> = self
            .local
            .iter()
            .map(|(_, key)| {
                (
                    Signature::new(key, hash),
                    PublicKey::new_from_private_key(key),
                )
            })
            .collect();

        if !self.keycard.is_empty() {
            pyo3::Python::with_gil(|py| -> pyo3::PyResult<()> {
                python_path::add_python_path(py)?;
                let wallet = KeycardWallet::new(py)?;
                wallet.connect(py, pin)?;
                for (_, path) in &self.keycard {
                    sigs.push(wallet.sign_message_for_path(py, path, hash)?);
                }
                drop(wallet.close_session(py));
                Ok(())
            })
            .map_err(anyhow::Error::from)?;
        }

        Ok(sigs)
    }
}
