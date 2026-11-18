#[cfg(keycard)]
mod imp {
    use anyhow::Result;
    use keycard_wallet::KeycardWallet;
    use lee::PublicKey;

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
}

#[cfg(not(keycard))]
mod imp {
    use anyhow::{Result, anyhow};
    use lee::PublicKey;

    const UNSUPPORTED: &str = "Keycard support is not built into this wallet";

    pub fn ensure_available() -> Result<()> {
        Err(anyhow!(UNSUPPORTED))
    }

    pub fn public_key(_pin: &str, _path: &str) -> Result<PublicKey> {
        Err(anyhow!(UNSUPPORTED))
    }
}

pub use imp::*;
