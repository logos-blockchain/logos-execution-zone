use std::{path::PathBuf, str::FromStr as _};

use anyhow::{Context as _, Result};
use nssa_core::account::Nonce;
use rand::{RngCore as _, rngs::OsRng};

use crate::HOME_DIR_ENV_VAR;

/// Get home dir for wallet. Env var `NSSA_WALLET_HOME_DIR` must be set before execution to succeed.
fn get_home_nssa_var() -> Result<PathBuf> {
    Ok(PathBuf::from_str(&std::env::var(HOME_DIR_ENV_VAR)?)?)
}

/// Get home dir for wallet. Env var `HOME` must be set before execution to succeed.
fn get_home_default_path() -> Result<PathBuf> {
    std::env::home_dir()
        .map(|path| path.join(".nssa").join("wallet"))
        .context("Failed to get HOME")
}

/// Get home dir for wallet.
pub fn get_home() -> Result<PathBuf> {
    get_home_nssa_var().or_else(|_| get_home_default_path())
}

/// Fetch config path from default home.
pub fn fetch_config_path() -> Result<PathBuf> {
    let home = get_home()?;
    let config_path = home.join("wallet_config.json");
    Ok(config_path)
}

/// Fetch path to data storage from default home.
///
/// File must be created through setup beforehand.
pub fn fetch_persistent_storage_path() -> Result<PathBuf> {
    let home = get_home()?;
    let accs_path = home.join("storage.json");
    Ok(accs_path)
}

#[expect(dead_code, reason = "Maybe used later")]
pub(crate) fn produce_random_nonces(size: usize) -> Vec<Nonce> {
    let mut result = vec![[0; 16]; size];
    for bytes in &mut result {
        OsRng.fill_bytes(bytes);
    }
    result
        .into_iter()
        .map(|x| Nonce(u128::from_le_bytes(x)))
        .collect()
}
