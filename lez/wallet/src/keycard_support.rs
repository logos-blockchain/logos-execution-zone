#[cfg(keycard)]
mod imp {
    use anyhow::Result;

    #[expect(
        clippy::unnecessary_wraps,
        reason = "Matches the stub, which always fails"
    )]
    pub const fn ensure_available() -> Result<()> {
        Ok(())
    }
}

#[cfg(not(keycard))]
mod imp {
    use anyhow::{Result, anyhow};

    const UNSUPPORTED: &str = "Keycard support is not built into this wallet";

    pub fn ensure_available() -> Result<()> {
        Err(anyhow!(UNSUPPORTED))
    }
}

pub use imp::*;
