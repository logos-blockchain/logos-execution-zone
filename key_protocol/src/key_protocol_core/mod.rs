use std::collections::BTreeMap;

use anyhow::Result;
use k256::AffinePoint;
use nssa::{Account, AccountId};
use nssa_core::{Identifier, PrivateAccountKind};
use serde::{Deserialize, Serialize};

use crate::key_management::{
    KeyChain,
    group_key_holder::GroupKeyHolder,
    key_tree::{KeyTreePrivate, KeyTreePublic, chain_index::ChainIndex},
    secret_holders::SeedHolder,
};

pub type PublicKey = AffinePoint;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserPrivateAccountData {
    pub key_chain: KeyChain,
    pub accounts: Vec<(PrivateAccountKind, Account)>,
}

/// Metadata for a shared account (GMS-derived), stored alongside the cached plaintext state.
/// The group label and identifier (or PDA seed) are needed to re-derive keys during sync.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharedAccountEntry {
    pub group_label: String,
    pub identifier: Identifier,
    /// For PDA accounts, the seed and program ID used to derive keys via `derive_keys_for_pda`.
    /// `None` for regular shared accounts (keys derived from identifier via derivation seed).
    #[serde(default)]
    pub pda_seed: Option<nssa_core::program::PdaSeed>,
    #[serde(default)]
    pub pda_program_id: Option<nssa_core::program::ProgramId>,
    pub account: Account,
}

#[derive(Clone, Debug)]
pub struct NSSAUserData {
    /// Default public accounts.
    pub default_pub_account_signing_keys: BTreeMap<nssa::AccountId, nssa::PrivateKey>,
    /// Default private accounts.
    pub default_user_private_accounts: BTreeMap<AccountId, UserPrivateAccountData>,
    /// Tree of public keys.
    pub public_key_tree: KeyTreePublic,
    /// Tree of private keys.
    pub private_key_tree: KeyTreePrivate,
    /// Group key holders for shared account management, keyed by a human-readable label.
    pub group_key_holders: BTreeMap<String, GroupKeyHolder>,
    /// Cached plaintext state of shared private accounts (PDAs and regular shared accounts),
    /// keyed by `AccountId`. Each entry stores the group label and identifier needed
    /// to re-derive keys during sync.
    pub shared_private_accounts: BTreeMap<nssa::AccountId, SharedAccountEntry>,
    /// Dedicated sealing secret key for GMS distribution. Generated once via
    /// `wallet group new-sealing-key`. The corresponding public key is shared with
    /// group members so they can seal GMS for this wallet.
    pub sealing_secret_key: Option<nssa_core::encryption::Scalar>,
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
        accounts_keys_map: &BTreeMap<AccountId, UserPrivateAccountData>,
    ) -> bool {
        let mut check_res = true;
        for (account_id, entry) in accounts_keys_map {
            let npk = &entry.key_chain.nullifier_public_key;
            let any_match = entry
                .accounts
                .iter()
                .any(|(kind, _)| nssa::AccountId::for_private_account(npk, kind) == *account_id);
            if !any_match {
                println!("No matching entry found for account_id {account_id}");
                check_res = false;
            }
        }
        check_res
    }

    pub fn new_with_accounts(
        default_accounts_keys: BTreeMap<nssa::AccountId, nssa::PrivateKey>,
        default_accounts_key_chains: BTreeMap<AccountId, UserPrivateAccountData>,
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
            group_key_holders: BTreeMap::new(),
            shared_private_accounts: BTreeMap::new(),
            sealing_secret_key: None,
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
    /// Does not cover shared private accounts — use `shared_private_account` for those.
    #[must_use]
    pub fn get_private_account(
        &self,
        account_id: nssa::AccountId,
    ) -> Option<(KeyChain, nssa_core::account::Account, Identifier)> {
        // Check default accounts
        if let Some(entry) = self.default_user_private_accounts.get(&account_id) {
            let npk = &entry.key_chain.nullifier_public_key;
            if let Some((kind, account)) = entry
                .accounts
                .iter()
                .find(|(kind, _)| nssa::AccountId::for_private_account(npk, kind) == account_id)
            {
                return Some((entry.key_chain.clone(), account.clone(), kind.identifier()));
            }
            return None;
        }
        // Check tree
        if let Some(node) = self.private_key_tree.get_node(account_id) {
            let key_chain = &node.value.0;
            let npk = &key_chain.nullifier_public_key;
            if let Some((kind, account)) = node
                .value
                .1
                .iter()
                .find(|(kind, _)| nssa::AccountId::for_private_account(npk, kind) == account_id)
            {
                return Some((key_chain.clone(), account.clone(), kind.identifier()));
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

    /// Returns the `GroupKeyHolder` for the given label, if it exists.
    #[must_use]
    pub fn group_key_holder(&self, label: &str) -> Option<&GroupKeyHolder> {
        self.group_key_holders.get(label)
    }

    /// Inserts or replaces a `GroupKeyHolder` under the given label.
    ///
    /// If a holder already exists under this label, it is silently replaced and the old
    /// GMS is lost. Callers must ensure label uniqueness across groups.
    pub fn insert_group_key_holder(&mut self, label: String, holder: GroupKeyHolder) {
        self.group_key_holders.insert(label, holder);
    }

    /// Returns the cached account for a shared private account, if it exists.
    #[must_use]
    pub fn shared_private_account(
        &self,
        account_id: &nssa::AccountId,
    ) -> Option<&SharedAccountEntry> {
        self.shared_private_accounts.get(account_id)
    }

    /// Inserts or replaces a shared private account entry.
    pub fn insert_shared_private_account(
        &mut self,
        account_id: nssa::AccountId,
        entry: SharedAccountEntry,
    ) {
        self.shared_private_accounts.insert(account_id, entry);
    }

    /// Updates the cached account state for a shared private account.
    pub fn update_shared_private_account_state(
        &mut self,
        account_id: &nssa::AccountId,
        account: nssa_core::account::Account,
    ) {
        if let Some(entry) = self.shared_private_accounts.get_mut(account_id) {
            entry.account = account;
        }
    }

    /// Iterates over all shared private accounts.
    pub fn shared_private_accounts_iter(
        &self,
    ) -> impl Iterator<Item = (&nssa::AccountId, &SharedAccountEntry)> {
        self.shared_private_accounts.iter()
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
    fn group_key_holder_storage_round_trip() {
        let mut user_data = NSSAUserData::default();
        assert!(user_data.group_key_holder("test-group").is_none());

        let holder = GroupKeyHolder::from_gms([42_u8; 32]);
        user_data.insert_group_key_holder(String::from("test-group"), holder.clone());

        let retrieved = user_data
            .group_key_holder("test-group")
            .expect("should exist");
        assert_eq!(retrieved.dangerous_raw_gms(), holder.dangerous_raw_gms());
    }

    #[test]
    fn group_key_holders_default_empty() {
        let user_data = NSSAUserData::default();
        assert!(user_data.group_key_holders.is_empty());
        assert!(user_data.shared_private_accounts.is_empty());
    }

    #[test]
    fn shared_account_entry_serde_round_trip() {
        use nssa_core::program::PdaSeed;

        let entry = SharedAccountEntry {
            group_label: String::from("test-group"),
            identifier: 42,
            pda_seed: None,
            pda_program_id: None,
            account: nssa_core::account::Account::default(),
        };
        let encoded = bincode::serialize(&entry).expect("serialize");
        let decoded: SharedAccountEntry = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(decoded.group_label, "test-group");
        assert_eq!(decoded.identifier, 42);
        assert!(decoded.pda_seed.is_none());

        let pda_entry = SharedAccountEntry {
            group_label: String::from("pda-group"),
            identifier: u128::MAX,
            pda_seed: Some(PdaSeed::new([7_u8; 32])),
            pda_program_id: Some([9; 8]),
            account: nssa_core::account::Account::default(),
        };
        let pda_encoded = bincode::serialize(&pda_entry).expect("serialize pda");
        let pda_decoded: SharedAccountEntry =
            bincode::deserialize(&pda_encoded).expect("deserialize pda");
        assert_eq!(pda_decoded.group_label, "pda-group");
        assert_eq!(pda_decoded.identifier, u128::MAX);
        assert_eq!(pda_decoded.pda_seed.unwrap(), PdaSeed::new([7_u8; 32]));
    }

    #[test]
    fn shared_account_entry_none_pda_seed_round_trips() {
        // Verify that an entry with pda_seed=None serializes and deserializes correctly,
        // confirming the #[serde(default)] attribute works for backward compatibility.
        let entry = SharedAccountEntry {
            group_label: String::from("old"),
            identifier: 1,
            pda_seed: None,
            pda_program_id: None,
            account: nssa_core::account::Account::default(),
        };
        let encoded = bincode::serialize(&entry).expect("serialize");
        let decoded: SharedAccountEntry = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(decoded.group_label, "old");
        assert_eq!(decoded.identifier, 1);
        assert!(decoded.pda_seed.is_none());
    }

    #[test]
    fn shared_account_derives_consistent_keys_from_group() {
        use nssa_core::program::PdaSeed;

        let mut user_data = NSSAUserData::default();
        let gms_holder = GroupKeyHolder::from_gms([42_u8; 32]);
        user_data.insert_group_key_holder(String::from("my-group"), gms_holder);

        let holder = user_data.group_key_holder("my-group").unwrap();

        // Regular shared account: derive via tag
        let tag = [1_u8; 32];
        let keys_a = holder.derive_keys_for_shared_account(&tag);
        let keys_b = holder.derive_keys_for_shared_account(&tag);
        assert_eq!(
            keys_a.generate_nullifier_public_key(),
            keys_b.generate_nullifier_public_key(),
        );

        // PDA shared account: derive via seed
        let seed = PdaSeed::new([2_u8; 32]);
        let pda_keys_a = holder.derive_keys_for_pda(&[9; 8], &seed);
        let pda_keys_b = holder.derive_keys_for_pda(&[9; 8], &seed);
        assert_eq!(
            pda_keys_a.generate_nullifier_public_key(),
            pda_keys_b.generate_nullifier_public_key(),
        );

        // PDA and shared derivations don't collide
        assert_ne!(
            keys_a.generate_nullifier_public_key(),
            pda_keys_a.generate_nullifier_public_key(),
        );
    }

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
