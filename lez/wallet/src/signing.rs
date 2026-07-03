use keycard_wallet::{KeycardWallet, KeycardWalletError};

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

    pub fn get_or_connect(&mut self) -> Result<&mut KeycardWallet, KeycardWalletError> {
        if self.wallet.is_none() {
            let mut wallet = KeycardWallet::new()?;
            wallet.connect(&self.pin)?;
            self.wallet = Some(wallet);
        }
        Ok(self.wallet.as_mut().expect("wallet was just inserted"))
    }

    pub fn close(mut self) {
        if let Some(wallet) = self.wallet.as_mut() {
            drop(wallet.disconnect());
        }
    }
}
