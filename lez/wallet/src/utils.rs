use std::{
    path::{Path, PathBuf},
    str::FromStr as _,
};

use anyhow::{Context as _, Result, ensure};
use lee_core::account::Nonce;
use rand::{RngCore as _, rngs::OsRng};
use zeroize::Zeroizing;

use crate::{HOME_DIR_ENV_VAR, PASSWORD_ENV_VAR, storage::Storage};

/// Read the password of the existing storage at `storage_path`: empty for an unencrypted one,
/// else a non-empty [`PASSWORD_ENV_VAR`], else a TTY prompt.
pub fn read_password(storage_path: &Path) -> Result<Zeroizing<String>> {
    if !Storage::is_encrypted(storage_path)? {
        return Ok(Zeroizing::default());
    }
    match std::env::var(PASSWORD_ENV_VAR) {
        Ok(password) if !password.is_empty() => Ok(Zeroizing::new(password)),
        _ => prompt_password("Wallet password: "),
    }
}

/// Read the password for a new storage: [`PASSWORD_ENV_VAR`] if set, even empty, else
/// [`prompt_new_password`].
pub fn read_new_password() -> Result<Zeroizing<String>> {
    let Ok(password) = std::env::var(PASSWORD_ENV_VAR) else {
        return prompt_new_password();
    };
    warn_if_unencrypted(&password);
    Ok(Zeroizing::new(password))
}

/// Prompt on the TTY for a storage password, typed twice; an empty one leaves the storage
/// unencrypted.
pub fn prompt_new_password() -> Result<Zeroizing<String>> {
    warn(
        "A forgotten password cannot be recovered; the recovery phrase restores only the \
         accounts generated from it, not imported keys, groups or labels.",
    );
    let password = prompt_password("New wallet password (empty for none): ")?;
    ensure!(
        *prompt_password("Repeat the wallet password: ")? == *password,
        "The passwords do not match"
    );
    warn_if_unencrypted(&password);
    Ok(password)
}

fn warn_if_unencrypted(password: &str) {
    if password.is_empty() {
        warn("The wallet storage will not be encrypted.");
    }
}

#[expect(
    clippy::print_stderr,
    reason = "A warning must not mix into the output of the command"
)]
pub fn warn(message: &str) {
    eprintln!("{message}");
}

fn prompt_password(prompt: &str) -> Result<Zeroizing<String>> {
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .map_err(Into::into)
}

/// Read the Keycard PIN without echoing it.
///
/// Checks `KEYCARD_PIN` first so non-interactive callers (CI, scripts) can
/// supply it via the environment. Falls back to a TTY prompt via `rpassword`
/// so the value never appears in argv, shell history, or `ps` output.
pub fn read_pin() -> anyhow::Result<zeroize::Zeroizing<String>> {
    if let Ok(pin) = std::env::var("KEYCARD_PIN") {
        return Ok(zeroize::Zeroizing::new(pin));
    }
    rpassword::prompt_password("Keycard PIN: ")
        .map(zeroize::Zeroizing::new)
        .map_err(Into::into)
}

/// Read the mnemonic phrase without echoing it.
///
/// Checks `KEYCARD_MNEMONIC` first for non-interactive callers. Falls back to
/// a TTY prompt so the phrase never appears in argv, shell history, or `ps`.
pub fn read_mnemonic() -> anyhow::Result<zeroize::Zeroizing<String>> {
    if let Ok(mnemonic) = std::env::var("KEYCARD_MNEMONIC") {
        return Ok(zeroize::Zeroizing::new(mnemonic));
    }
    rpassword::prompt_password("Mnemonic phrase: ")
        .map(zeroize::Zeroizing::new)
        .map_err(Into::into)
}

/// Get home dir for wallet. Env var `LEE_WALLET_HOME_DIR` must be set before execution to succeed.
fn get_home_lee_var() -> Result<PathBuf> {
    Ok(PathBuf::from_str(&std::env::var(HOME_DIR_ENV_VAR)?)?)
}

/// Get home dir for wallet. Env var `HOME` must be set before execution to succeed.
fn get_home_default_path() -> Result<PathBuf> {
    std::env::home_dir()
        .map(|path| path.join(".lee").join("wallet"))
        .context("Failed to get HOME")
}

/// Get home dir for wallet.
pub fn get_home() -> Result<PathBuf> {
    get_home_lee_var().or_else(|_| get_home_default_path())
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
