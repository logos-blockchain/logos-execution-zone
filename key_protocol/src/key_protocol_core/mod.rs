use std::collections::BTreeMap;

use anyhow::Result;
use k256::AffinePoint;
use nssa_core::Identifier;
use serde::{Deserialize, Serialize};

use crate::key_management::{
    KeyChain,
    key_tree::{KeyTreePrivate, KeyTreePublic, chain_index::ChainIndex},
    secret_holders::SeedHolder,
};

pub type PublicKey = AffinePoint;
pub type DefaultPrivateAccountsMap =
    BTreeMap<nssa::AccountId, (KeyChain, Vec<(Identifier, nssa_core::account::Account)>)>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NSSAUserData {
    /// Default public accounts.
    pub default_pub_account_signing_keys: BTreeMap<nssa::AccountId, nssa::PrivateKey>,
    /// Default private accounts.
    pub default_user_private_accounts: DefaultPrivateAccountsMap,
    /// Tree of public keys.
    pub public_key_tree: KeyTreePublic,
    /// Tree of private keys.
    pub private_key_tree: KeyTreePrivate,
}

impl NSSAUserData {
    fn valid_public_key_transaction_pairing_check(
        accounts_keys_map: &BTreeMap<nssa::AccountId, nssa::PrivateKey>,
    ) -> bool {
        let mut check_res = true;
        for (account_id, key) in accounts_keys_map {
            let expected_account_id =
                nssa::AccountId::from(&nssa::PublicKey::new_from_private_key(key));
            if &expected_account_id != account_id {
                println!("{expected_account_id}, {account_id}");
                check_res = false;
            }
        }
        check_res
    }

    fn valid_private_key_transaction_pairing_check(
        accounts_keys_map: &DefaultPrivateAccountsMap,
    ) -> bool {
        let mut check_res = true;
        for (account_id, (key, entries)) in accounts_keys_map {
            let any_match = entries.iter().any(|(identifier, _)| {
                nssa::AccountId::from((&key.nullifier_public_key, *identifier)) == *account_id
            });
            if !any_match {
                println!("No matching entry found for account_id {account_id}");
                check_res = false;
            }
        }
        check_res
    }

    pub fn new_with_accounts(
        default_accounts_keys: BTreeMap<nssa::AccountId, nssa::PrivateKey>,
        default_accounts_key_chains: DefaultPrivateAccountsMap,
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
                .generate_new_public_node(&parent_cci)
                .expect("Parent must be present in a tree"),
            None => self
                .public_key_tree
                .generate_new_public_node_layered()
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
            .or_else(|| self.public_key_tree.get_node(account_id).map(Into::into))
    }

    /// Creates a new receiving key node and returns its `ChainIndex`.
    pub fn create_private_accounts_key(&mut self, parent_cci: Option<ChainIndex>) -> ChainIndex {
        match parent_cci {
            Some(parent_cci) => self
                .private_key_tree
                .create_private_accounts_key_node(&parent_cci)
                .expect("Parent must be present in a tree"),
            None => self
                .private_key_tree
                .create_private_accounts_key_node_layered()
                .expect("Search for new node slot failed"),
        }
    }

    /// Registers an additional identifier on an existing private key node, deriving and recording
    /// the corresponding `AccountId`. Returns `None` if the node does not exist or the identifier
    /// is already registered.
    pub fn register_identifier_on_private_key_chain(
        &mut self,
        cci: &ChainIndex,
        identifier: Identifier,
    ) -> Option<nssa::AccountId> {
        self.private_key_tree
            .register_identifier_on_node(cci, identifier)
    }

    /// Returns the key chain and account data for the given private account ID.
    #[must_use]
    pub fn get_private_account(
        &self,
        account_id: nssa::AccountId,
    ) -> Option<(KeyChain, nssa_core::account::Account, Identifier)> {
        // Check default accounts
        if let Some((key_chain, entries)) = self.default_user_private_accounts.get(&account_id) {
            for (identifier, account) in entries {
                let expected_id =
                    nssa::AccountId::from((&key_chain.nullifier_public_key, *identifier));
                if expected_id == account_id {
                    return Some((key_chain.clone(), account.clone(), *identifier));
                }
            }
            return None;
        }
        // Check tree
        if let Some(node) = self.private_key_tree.get_node(account_id) {
            let key_chain = &node.value.0;
            for (identifier, account) in &node.value.1 {
                let expected_id =
                    nssa::AccountId::from((&key_chain.nullifier_public_key, *identifier));
                if expected_id == account_id {
                    return Some((key_chain.clone(), account.clone(), *identifier));
                }
            }
        }
        None
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

        let chain_index = user_data.create_private_accounts_key(Some(ChainIndex::root()));

        let is_key_chain_generated = user_data
            .private_key_tree
            .key_map
            .contains_key(&chain_index);
        assert!(is_key_chain_generated);

        let key_chain = &user_data.private_key_tree.key_map[&chain_index].value.0;
        println!("{key_chain:#?}");
    }
}
