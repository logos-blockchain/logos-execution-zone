use keycard_wallet::{KeycardWallet, python_path};
use pyo3::Python;

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
