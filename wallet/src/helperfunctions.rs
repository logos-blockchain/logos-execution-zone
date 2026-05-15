use std::{path::PathBuf, str::FromStr as _};

use anyhow::{Context as _, Result};
use nssa_core::account::Nonce;
use rand::{RngCore as _, rngs::OsRng};

use crate::HOME_DIR_ENV_VAR;

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
/// Exactly one of `id` or `label` must be `Some`. If `id` is provided it is
/// returned as-is; if `label` is provided it is resolved via
/// [`resolve_account_label`]. Any other combination returns an error.
pub fn resolve_id_or_label(
    id: Option<String>,
    label: Option<String>,
    labels: &HashMap<String, Label>,
    user_data: &NSSAUserData,
    key_path: Option<&str>,
) -> Result<String> {
    match (id, label, key_path) {
        (Some(id), None, None) => Ok(id),
        (None, Some(label), None) => resolve_account_label(&label, labels, user_data),
        (None, None, Some(key_path)) => resolve_keycard_id(key_path),
        _ => anyhow::bail!("provide exactly one of account id, account label or keycard path"),
    }
}

pub fn resolve_keycard_id(key_path: &str) -> Result<String> {
    let pin = read_pin()?;
    KeycardWallet::get_public_account_id_for_path_with_connect(&pin, key_path)
        .map_err(anyhow::Error::from)
}

/// Resolve an account label to its full `Privacy/id` string representation.
///
/// Looks up the label in the labels map and determines whether the account is
/// public or private by checking the user data key trees.
pub fn resolve_account_label(
    label: &str,
    labels: &HashMap<String, Label>,
    user_data: &NSSAUserData,
) -> Result<String> {
    let account_id_str = labels
        .iter()
        .find(|(_, l)| l.to_string() == label)
        .map(|(k, _)| k.clone())
        .ok_or_else(|| anyhow::anyhow!("No account found with label '{label}'"))?;

    let account_id: nssa::AccountId = account_id_str.parse()?;

    let privacy = if user_data
        .public_key_tree
        .account_id_map
        .contains_key(&account_id)
        || user_data
            .default_pub_account_signing_keys
            .contains_key(&account_id)
    {
        "Public"
    } else if user_data
        .private_key_tree
        .account_id_map
        .contains_key(&account_id)
        || user_data
            .default_user_private_accounts
            .contains_key(&account_id)
    {
        "Private"
    } else {
        anyhow::bail!("Account with label '{label}' not found in wallet");
    };

    Ok(format!("{privacy}/{account_id_str}"))
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
