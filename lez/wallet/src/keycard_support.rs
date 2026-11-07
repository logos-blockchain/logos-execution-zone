use anyhow::Result;
pub use imp::*;
use lee::{PublicKey, Signature};

#[cfg(keycard)]
mod imp {
    use keycard_wallet::KeycardWallet;

    use super::{PublicKey, Result, Signature};

    #[expect(
        clippy::unnecessary_wraps,
        reason = "Matches the stub, which always fails"
    )]
    pub const fn ensure_available() -> Result<()> {
        Ok(())
    }

    pub fn public_key(pin: &str, path: &str) -> Result<PublicKey> {
        Ok(KeycardWallet::get_public_key_for_path_with_connect(
            pin, path,
        )?)
    }

    pub fn sign(
        pin: &str,
        paths: &[&str],
        message_hash: &[u8; 32],
    ) -> Result<Vec<(Signature, PublicKey)>> {
        let mut wallet = KeycardWallet::new()?;
        wallet.connect(pin)?;
        paths
            .iter()
            .map(|path| Ok(wallet.sign_message_for_path(path, message_hash)?))
            .collect()
    }
}

#[cfg(not(keycard))]
mod imp {
    use anyhow::anyhow;

    use super::{PublicKey, Result, Signature};

    const UNSUPPORTED: &str = "Keycard support is not built into this wallet";

    pub fn ensure_available() -> Result<()> {
        Err(anyhow!(UNSUPPORTED))
    }

    pub fn public_key(_pin: &str, _path: &str) -> Result<PublicKey> {
        Err(anyhow!(UNSUPPORTED))
    }

    pub fn sign(
        _pin: &str,
        _paths: &[&str],
        _message_hash: &[u8; 32],
    ) -> Result<Vec<(Signature, PublicKey)>> {
        Err(anyhow!(UNSUPPORTED))
    }
}
