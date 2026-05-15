use anyhow::Result;
use keycard_wallet::{KeycardWallet, python_path};
use nssa::{AccountId, PublicKey, Signature};
use pyo3::Python;

use crate::WalletCore;

/// How a single account participates in signing a transaction.
///
/// Created from [`crate::cli::CliAccountMention`] via `to_signer` / `to_recipient_signer`.
/// Used inside `Python::with_gil` blocks — does not cross async boundaries.
pub enum AccountSigner {
    /// Account is in the local wallet; key is looked up from storage at sign time.
    Local(AccountId),
    /// Account is on a Keycard at the given BIP32 path.
    Keycard(String),
    /// Foreign account — no signature or nonce required.
    Foreign,
}

impl AccountSigner {
    #[must_use]
    pub const fn needs_signature(&self) -> bool {
        !matches!(self, Self::Foreign)
    }

    /// Sign `hash` and return `(Signature, PublicKey)`, or `None` for `Foreign`.
    pub fn sign(
        &self,
        wallet_core: &WalletCore,
        ctx: &mut KeycardSessionContext,
        py: Python<'_>,
        hash: &[u8; 32],
    ) -> Option<Result<(Signature, PublicKey)>> {
        match self {
            Self::Local(id) => {
                let key = wallet_core
                    .storage()
                    .key_chain()
                    .pub_account_signing_key(*id);
                Some(key.map_or_else(
                    || Err(anyhow::anyhow!("signing key not found for account {id}")),
                    |key| {
                        Ok((
                            Signature::new(key, hash),
                            PublicKey::new_from_private_key(key),
                        ))
                    },
                ))
            }
            Self::Keycard(path) => Some(
                ctx.get_or_connect(py)
                    .and_then(|w| w.sign_message_for_path(py, path, hash))
                    .map_err(anyhow::Error::from),
            ),
            Self::Foreign => None,
        }
    }
}

/// Lazily opens and reuses a single Keycard session for all keycard signers in one transaction.
pub struct KeycardSessionContext {
    pin: String,
    wallet: Option<KeycardWallet>,
}

impl KeycardSessionContext {
    pub fn new(pin: impl Into<String>) -> Self {
        Self {
            pin: pin.into(),
            wallet: None,
        }
    }

    pub fn get_or_connect<'py>(
        &'py mut self,
        py: Python<'py>,
    ) -> pyo3::PyResult<&'py KeycardWallet> {
        if self.wallet.is_none() {
            python_path::add_python_path(py)?;
            let wallet = KeycardWallet::new(py)?;
            wallet.connect(py, &self.pin)?;
            self.wallet = Some(wallet);
        }
        Ok(self.wallet.as_ref().unwrap())
    }

    pub fn close(self, py: Python<'_>) {
        if let Some(w) = self.wallet {
            drop(w.close_session(py));
        }
    }
}
