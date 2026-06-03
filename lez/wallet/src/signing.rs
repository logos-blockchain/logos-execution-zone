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

    pub fn get_or_connect(&mut self, py: Python<'_>) -> pyo3::PyResult<&KeycardWallet> {
        if self.wallet.is_none() {
            python_path::add_python_path(py)?;
            let wallet = KeycardWallet::new(py)?;
            wallet.connect(py, &self.pin)?;
            self.wallet = Some(wallet);
        }
        Ok(self.wallet.as_ref().expect("wallet was just inserted"))
    }

    pub fn close(self, py: Python<'_>) {
        if let Some(w) = self.wallet {
            let _res = w.close_session(py);
        }
    }
}
