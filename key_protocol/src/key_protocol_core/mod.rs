use std::collections::BTreeMap;

use anyhow::Result;
use k256::AffinePoint;
use serde::{Deserialize, Serialize};

use crate::key_management::{
    KeyChain,
    key_tree::{KeyTreePrivate, KeyTreePublic, chain_index::ChainIndex},
    secret_holders::SeedHolder,
};

pub type PublicKey = AffinePoint;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NSSAUserData {
    /// Default public accounts.
    pub default_pub_account_signing_keys: BTreeMap<nssa::AccountId, PublicBundle>,
    /// Default private accounts.
    pub default_user_private_accounts: BTreeMap<nssa::AccountId, PrivateBundle>,
    /// Tree of public keys.
    pub public_key_tree: KeyTreePublic,
    /// Tree of private keys.
    pub private_key_tree: KeyTreePrivate,
}

/// TODO: eventually, this should have `sign_key: Option<PrivateKey>` and `pub_key: PublicKey`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicBundle {
    pub sign_key: nssa::PrivateKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateBundle {
    pub key_chain: KeyChain,
    pub account: nssa_core::account::Account,
}

impl NSSAUserData {
    fn valid_public_key_transaction_pairing_check(
        accounts_keys_map: &BTreeMap<nssa::AccountId, PublicBundle>,
    ) -> bool {
        let mut check_res = true;
        for (account_id, public_bundle) in accounts_keys_map {
            let expected_account_id = nssa::AccountId::from(
                &nssa::PublicKey::new_from_private_key(&public_bundle.sign_key),
            );
            if &expected_account_id != account_id {
                println!("{expected_account_id}, {account_id}");
                check_res = false;
            }
        }
        check_res
    }

    fn valid_private_key_transaction_pairing_check(
        accounts_keys_map: &BTreeMap<nssa::AccountId, PrivateBundle>,
    ) -> bool {
        let mut check_res = true;
        for (account_id, bundle) in accounts_keys_map {
            let expected_account_id = nssa::AccountId::from(&bundle.key_chain.nullifier_public_key);
            if expected_account_id != *account_id {
                println!("{expected_account_id}, {account_id}");
                check_res = false;
            }
        }
        check_res
    }

    pub fn new_with_accounts(
        default_accounts_keys: BTreeMap<nssa::AccountId, PublicBundle>,
        default_accounts_key_chains: BTreeMap<
            nssa::AccountId,
            PrivateBundle,
        >,
        public_key_tree: KeyTreePublic,
        private_key_tree: KeyTreePrivate,
    ) -> Result<Self> {
        if !Self::valid_public_key_transaction_pairing_check(&default_accounts_keys) {
            anyhow::bail!(
                "Key transaction pairing check not satisfied, there are public account_ids, which are not derived from keys"
            );
        }

        if !Self::valid_private_key_transaction_pairing_check(&default_accounts_key_chains) {
            anyhow::bail!(
                "Key transaction pairing check not satisfied, there are private account_ids, which are not derived from keys"
            );
        }

        Ok(Self {
            default_pub_account_signing_keys: default_accounts_keys,
            default_user_private_accounts: default_accounts_key_chains,
            public_key_tree,
            private_key_tree,
        })
    }

    /// Generated new private key for public transaction signatures.
    ///
    /// Returns the `account_id` of new account.
    pub fn generate_new_public_transaction_private_key(
        &mut self,
        parent_cci: Option<ChainIndex>,
    ) -> (nssa::AccountId, ChainIndex) {
        match parent_cci {
            Some(parent_cci) => self
                .public_key_tree
                .generate_new_node(&parent_cci)
                .expect("Parent must be present in a tree"),
            None => self
                .public_key_tree
                .generate_new_node_layered()
                .expect("Search for new node slot failed"),
        }
    }

    /// Returns the signing key for public transaction signatures.
    #[must_use]
    pub fn get_pub_account_signing_key(
        &self,
        account_id: nssa::AccountId,
    ) -> Option<&nssa::PrivateKey> {
        self.default_pub_account_signing_keys
            .get(&account_id)
            .map(|bundle| &bundle.sign_key)
            .or_else(|| self.public_key_tree.get_node(account_id).map(Into::into))
    }

    /// Generated new private key for privacy preserving transactions.
    ///
    /// Returns the `account_id` of new account.
    pub fn generate_new_privacy_preserving_transaction_key_chain(
        &mut self,
        parent_cci: Option<ChainIndex>,
    ) -> (nssa::AccountId, ChainIndex) {
        match parent_cci {
            Some(parent_cci) => self
                .private_key_tree
                .generate_new_node(&parent_cci)
                .expect("Parent must be present in a tree"),
            None => self
                .private_key_tree
                .generate_new_node_layered()
                .expect("Search for new node slot failed"),
        }
    }

    /// Returns the signing key for public transaction signatures.
    #[must_use] //Marvin: double check TODO
    pub fn get_private_account(&self, account_id: nssa::AccountId) -> Option<PrivateBundle> {
        // self.default_user_private_accounts
        // .get(&account_id)
        // .or_else(|| self.private_key_tree.get_node(account_id).map(Into::into))
        self.default_user_private_accounts
            .get(&account_id)
            .cloned()
            .or_else(|| {
                self.private_key_tree
                    .get_node(account_id)
                    .map(|child_keys_private| PrivateBundle {
                        key_chain: child_keys_private.value.0.clone(),
                        account: child_keys_private.value.1.clone(),
                    })
            })
    }

    /// Returns the signing key for public transaction signatures.
    /// TODO: fix this comment (Marvin)
    pub fn get_private_account_mut(
        &mut self,
        account_id: &nssa::AccountId,
    ) -> Option<PrivateBundle> {
        // First seek in defaults
        if let Some(bundle) = self.default_user_private_accounts.get(account_id) {
            Some(bundle).cloned()
        // Then seek in tree
        } else {
            self.private_key_tree
                .get_node_mut(*account_id)
                .map(Into::into)
        }
    }

    pub fn account_ids(&self) -> impl Iterator<Item = nssa::AccountId> {
        self.public_account_ids().chain(self.private_account_ids())
    }

    pub fn public_account_ids(&self) -> impl Iterator<Item = nssa::AccountId> {
        self.default_pub_account_signing_keys
            .keys()
            .copied()
            .chain(self.public_key_tree.account_id_map.keys().copied())
    }

    pub fn private_account_ids(&self) -> impl Iterator<Item = nssa::AccountId> {
        self.default_user_private_accounts
            .keys()
            .copied()
            .chain(self.private_key_tree.account_id_map.keys().copied())
    }
}

impl Default for NSSAUserData {
    fn default() -> Self {
        let (seed_holder, _mnemonic) = SeedHolder::new_mnemonic("");
        Self::new_with_accounts(
            BTreeMap::new(),
            BTreeMap::new(),
            KeyTreePublic::new(&seed_holder),
            KeyTreePrivate::new(&seed_holder),
        )
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_account() {
        let mut user_data = NSSAUserData::default();

        let (account_id_private, _) = user_data
            .generate_new_privacy_preserving_transaction_key_chain(Some(ChainIndex::root()));

        let is_key_chain_generated = user_data.get_private_account(account_id_private).is_some();

        assert!(is_key_chain_generated);

        let account_id_private_str = account_id_private.to_string();
        println!("{account_id_private_str:#?}");
        let key_chain = &user_data.get_private_account(account_id_private).unwrap().key_chain;
        println!("{key_chain:#?}");
    }
}
