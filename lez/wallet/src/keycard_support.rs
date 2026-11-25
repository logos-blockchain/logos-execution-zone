use anyhow::{Result, anyhow};

// A Keycard holds one fixed key, so it cannot derive the per-nonce keys an account rotates through.
pub fn unsupported() -> anyhow::Error {
    anyhow!("Keycard accounts are not supported: a Keycard key cannot rotate")
}

pub fn ensure_available() -> Result<()> {
    Err(unsupported())
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_keycard_cannot_sign_whatever_the_build() {
        assert_eq!(
            super::ensure_available().unwrap_err().to_string(),
            "Keycard accounts are not supported: a Keycard key cannot rotate"
        );
    }
}
