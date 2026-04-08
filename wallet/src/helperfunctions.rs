use std::{collections::HashMap, path::PathBuf, str::FromStr as _};

use anyhow::{Context as _, Result};
use base58::ToBase58 as _;
use key_protocol::key_protocol_core::NSSAUserData;
use nssa::Account;
use nssa_core::account::Nonce;
use rand::{RngCore as _, rngs::OsRng};
use serde::Serialize;
use testnet_initial_state::{PrivateAccountPrivateInitialData, PublicAccountPrivateInitialData};

use crate::{
    HOME_DIR_ENV_VAR,
    config::{
        InitialAccountData, Label, PersistentAccountDataPrivate, PersistentAccountDataPublic,
        PersistentStorage,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountPrivacyKind {
    Public,
    Private,
}

/// Human-readable representation of an account.
#[derive(Serialize)]
pub(crate) struct HumanReadableAccount {
    balance: u128,
    program_owner: String,
    data: String,
    nonce: u128,
}

impl From<Account> for HumanReadableAccount {
    fn from(account: Account) -> Self {
        let program_owner = account
            .program_owner
            .iter()
            .flat_map(|n| n.to_le_bytes())
            .collect::<Vec<u8>>()
            .to_base58();
        let data = hex::encode(account.data);
        Self {
            balance: account.balance,
            program_owner,
            data,
            nonce: account.nonce.0,
        }
    }
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

/// Produces data for storage.
#[must_use]
pub fn produce_data_for_storage(
    user_data: &NSSAUserData,
    last_synced_block: u64,
    labels: HashMap<String, Label>,
) -> PersistentStorage {
    let mut vec_for_storage = vec![];

    for (account_id, key) in &user_data.public_key_tree.account_id_map {
        if let Some(data) = user_data.public_key_tree.key_map.get(key) {
            vec_for_storage.push(
                PersistentAccountDataPublic {
                    account_id: *account_id,
                    chain_index: key.clone(),
                    data: data.clone(),
                }
                .into(),
            );
        }
    }

    for (account_id, key) in &user_data.private_key_tree.account_id_map {
        if let Some(data) = user_data.private_key_tree.key_map.get(key) {
            vec_for_storage.push(
                PersistentAccountDataPrivate {
                    account_id: *account_id,
                    chain_index: key.clone(),
                    data: data.clone(),
                }
                .into(),
            );
        }
    }

    for (account_id, key) in &user_data.default_pub_account_signing_keys {
        vec_for_storage.push(
            InitialAccountData::Public(PublicAccountPrivateInitialData {
                account_id: *account_id,
                pub_sign_key: key.clone(),
            })
            .into(),
        );
    }

    for (account_id, (key_chain, account)) in &user_data.default_user_private_accounts {
        vec_for_storage.push(
            InitialAccountData::Private(Box::new(PrivateAccountPrivateInitialData {
                account_id: *account_id,
                account: account.clone(),
                key_chain: key_chain.clone(),
            }))
            .into(),
        );
    }

    PersistentStorage {
        accounts: vec_for_storage,
        last_synced_block,
        labels,
    }
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

pub(crate) fn parse_addr_with_privacy_prefix(
    account_base58: &str,
) -> Result<(String, AccountPrivacyKind)> {
    if account_base58.starts_with("Public/") {
        Ok((
            account_base58.strip_prefix("Public/").unwrap().to_owned(),
            AccountPrivacyKind::Public,
        ))
    } else if account_base58.starts_with("Private/") {
        Ok((
            account_base58.strip_prefix("Private/").unwrap().to_owned(),
            AccountPrivacyKind::Private,
        ))
    } else {
        anyhow::bail!("Unsupported privacy kind, available variants is Public/ and Private/");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addr_parse_with_privacy() {
        let addr_base58 = "Public/BLgCRDXYdQPMMWVHYRFGQZbgeHx9frkipa8GtpG2Syqy";
        let (_, addr_kind) = parse_addr_with_privacy_prefix(addr_base58).unwrap();

        assert_eq!(addr_kind, AccountPrivacyKind::Public);

        let addr_base58 = "Private/BLgCRDXYdQPMMWVHYRFGQZbgeHx9frkipa8GtpG2Syqy";
        let (_, addr_kind) = parse_addr_with_privacy_prefix(addr_base58).unwrap();

        assert_eq!(addr_kind, AccountPrivacyKind::Private);

        let addr_base58 = "asdsada/BLgCRDXYdQPMMWVHYRFGQZbgeHx9frkipa8GtpG2Syqy";
        assert!(parse_addr_with_privacy_prefix(addr_base58).is_err());
    }
}
