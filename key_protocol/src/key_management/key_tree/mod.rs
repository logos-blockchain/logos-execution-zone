use std::collections::BTreeMap;

use anyhow::Result;
use nssa::{Account, AccountId};
use nssa_core::Identifier;
use serde::{Deserialize, Serialize};

use crate::key_management::{
    key_tree::{
        chain_index::ChainIndex, keys_private::ChildKeysPrivate, keys_public::ChildKeysPublic,
        traits::KeyTreeNode,
    },
    secret_holders::SeedHolder,
};

pub mod chain_index;
pub mod keys_private;
pub mod keys_public;
pub mod traits;

pub const DEPTH_SOFT_CAP: u32 = 20;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeyTree<N: KeyTreeNode> {
    pub key_map: BTreeMap<ChainIndex, N>,
    pub account_id_map: BTreeMap<nssa::AccountId, ChainIndex>,
}

pub type KeyTreePublic = KeyTree<ChildKeysPublic>;
pub type KeyTreePrivate = KeyTree<ChildKeysPrivate>;

impl<N: KeyTreeNode> KeyTree<N> {
    #[must_use]
    pub fn new(seed: &SeedHolder) -> Self {
        let seed_fit: [u8; 64] = seed
            .seed
            .clone()
            .try_into()
            .expect("SeedHolder seed is 64 bytes long");

        let root_keys = N::from_seed(seed_fit);
        let account_id_map = root_keys
            .account_ids()
            .into_iter()
            .map(|id| (id, ChainIndex::root()))
            .collect();

        Self {
            key_map: BTreeMap::from_iter([(ChainIndex::root(), root_keys)]),
            account_id_map,
        }
    }

    pub fn new_from_root(root: N) -> Self {
        let account_id_map = root
            .account_ids()
            .into_iter()
            .map(|id| (id, ChainIndex::root()))
            .collect();

        Self {
            key_map: BTreeMap::from_iter([(ChainIndex::root(), root)]),
            account_id_map,
        }
    }

    pub fn generate_new_node(&mut self, parent_cci: &ChainIndex) -> Option<ChainIndex> {
        let parent_keys = self.key_map.get(parent_cci)?;
        let next_child_id = self
            .find_next_last_child_of_id(parent_cci)
            .expect("Can be None only if parent is not present");
        let next_cci = parent_cci.nth_child(next_child_id);

        let child_keys = parent_keys.derive_child(next_child_id);
        let account_ids = child_keys.account_ids();

        for account_id in account_ids {
            self.account_id_map.insert(account_id, next_cci.clone());
        }
        self.key_map.insert(next_cci.clone(), child_keys);

        Some(next_cci)
    }

    pub fn fill_node(&mut self, chain_index: &ChainIndex) -> Option<ChainIndex> {
        let parent_keys = self.key_map.get(&chain_index.parent()?)?;
        let child_id = *chain_index.chain().last()?;

        let child_keys = parent_keys.derive_child(child_id);
        let account_ids = child_keys.account_ids();

        for account_id in account_ids {
            self.account_id_map.insert(account_id, chain_index.clone());
        }
        self.key_map.insert(chain_index.clone(), child_keys);

        Some(chain_index.clone())
    }

    #[must_use]
    pub fn find_next_last_child_of_id(&self, parent_id: &ChainIndex) -> Option<u32> {
        if !self.key_map.contains_key(parent_id) {
            return None;
        }

        let leftmost_child = parent_id.nth_child(u32::MIN);

        if !self.key_map.contains_key(&leftmost_child) {
            return Some(0);
        }

        let mut right = u32::MAX - 1;
        let mut left_border = u32::MIN;
        let mut right_border = u32::MAX;

        loop {
            let rightmost_child = parent_id.nth_child(right);

            let rightmost_ref = self.key_map.get(&rightmost_child);
            let rightmost_ref_next = self.key_map.get(&rightmost_child.next_in_line()?);

            match (&rightmost_ref, &rightmost_ref_next) {
                (Some(_), Some(_)) => {
                    left_border = right;
                    right = u32::midpoint(right, right_border);
                }
                (Some(_), None) => {
                    break Some(right.checked_add(1)?);
                }
                (None, None) => {
                    right_border = right;
                    right = u32::midpoint(left_border, right);
                }
                (None, Some(_)) => {
                    unreachable!();
                }
            }
        }
    }

    fn find_next_slot_layered(&self) -> ChainIndex {
        let mut depth = 1;

        'outer: loop {
            for chain_id in ChainIndex::chain_ids_at_depth_rev(depth) {
                if !self.key_map.contains_key(&chain_id) {
                    break 'outer chain_id;
                }
            }
            depth = depth.checked_add(1).expect("Max depth reached");
        }
    }

    pub fn generate_new_node_layered(&mut self) -> Option<ChainIndex> {
        self.fill_node(&self.find_next_slot_layered())
    }

    /// Populates tree with children.
    ///
    /// For given `depth` adds children to a tree such that their `ChainIndex::depth(&self) <
    /// depth`.
    ///
    /// Tree must be empty before start.
    pub fn generate_tree_for_depth(&mut self, depth: u32) {
        let mut id_stack = vec![ChainIndex::root()];

        while let Some(curr_id) = id_stack.pop() {
            let mut next_id = curr_id.nth_child(0);

            while (next_id.depth()) < depth {
                self.generate_new_node(&curr_id);
                id_stack.push(next_id.clone());
                next_id = match next_id.next_in_line() {
                    Some(id) => id,
                    None => break,
                };
            }
        }
    }

    #[must_use]
    pub fn get_node(&self, account_id: nssa::AccountId) -> Option<&N> {
        let chain_id = self.account_id_map.get(&account_id)?;
        self.key_map.get(chain_id)
    }

    pub fn get_node_mut(&mut self, account_id: nssa::AccountId) -> Option<&mut N> {
        let chain_id = self.account_id_map.get(&account_id)?;
        self.key_map.get_mut(chain_id)
    }

    pub fn insert(&mut self, account_id: nssa::AccountId, chain_index: ChainIndex, node: N) {
        self.account_id_map.insert(account_id, chain_index.clone());
        self.key_map.insert(chain_index, node);
    }

    pub fn remove(&mut self, addr: nssa::AccountId) -> Option<N> {
        let chain_index = self.account_id_map.remove(&addr)?;
        self.key_map.remove(&chain_index)
    }
}

impl KeyTree<ChildKeysPublic> {
    /// Generate a new public key node, returning the account ID and chain index.
    pub fn generate_new_public_node(
        &mut self,
        parent_cci: &ChainIndex,
    ) -> Option<(nssa::AccountId, ChainIndex)> {
        let cci = self.generate_new_node(parent_cci)?;
        let node = self.key_map.get(&cci)?;
        let account_id = node.account_ids().next()?;
        Some((account_id, cci))
    }

    /// Generate a new public key node using layered placement, returning the account ID and chain
    /// index.
    pub fn generate_new_public_node_layered(&mut self) -> Option<(nssa::AccountId, ChainIndex)> {
        let cci = self.generate_new_node_layered()?;
        let node = self.key_map.get(&cci)?;
        let account_id = node.account_ids().next()?;
        Some((account_id, cci))
    }

    /// Cleanup of non-initialized accounts in a public tree.
    ///
    /// If account is default, removes them, stops at first non-default account.
    ///
    /// Walks through tree in layers of same depth using `ChainIndex::chain_ids_at_depth()`.
    ///
    /// Slow, maintains tree consistency.
    pub async fn cleanup_tree_remove_uninit_layered<F: Future<Output = Result<Account>>>(
        &mut self,
        depth: u32,
        get_account: impl Fn(AccountId) -> F,
    ) -> Result<()> {
        let depth = usize::try_from(depth).expect("Depth is expected to fit in usize");
        'outer: for i in (1..depth).rev() {
            println!("Cleanup of tree at depth {i}");
            for id in ChainIndex::chain_ids_at_depth(i) {
                if let Some(node) = self.key_map.get(&id) {
                    let address = node.account_id();
                    let node_acc = get_account(address).await?;

                    if node_acc == nssa::Account::default() {
                        let addr = node.account_id();
                        self.remove(addr);
                    } else {
                        break 'outer;
                    }
                }
            }
        }

        Ok(())
    }
}

impl KeyTree<ChildKeysPrivate> {
    pub fn create_private_accounts_key_node(
        &mut self,
        parent_cci: &ChainIndex,
    ) -> Option<ChainIndex> {
        self.generate_new_node(parent_cci)
    }

    pub fn create_private_accounts_key_node_layered(&mut self) -> Option<ChainIndex> {
        self.generate_new_node_layered()
    }

    /// Register an additional identifier on an existing private key node, inserting the derived
    /// `AccountId` into `account_id_map`. Returns `None` if the node does not exist or the
    /// `AccountId` is already registered.
    pub fn register_identifier_on_node(
        &mut self,
        cci: &ChainIndex,
        identifier: Identifier,
    ) -> Option<nssa::AccountId> {
        let node = self.key_map.get(cci)?;
        let account_id = nssa::AccountId::from((&node.value.0.nullifier_public_key, identifier));
        if self.account_id_map.contains_key(&account_id) {
            return None;
        }
        self.account_id_map.insert(account_id, cci.clone());
        Some(account_id)
    }

    /// Cleanup of non-initialized accounts in a private tree.
    ///
    /// If account has no synced entries, removes it, stops at first initialized account.
    ///
    /// Walks through tree in layers of same depth using `ChainIndex::chain_ids_at_depth()`.
    ///
    /// Chain must be parsed for accounts beforehand.
    ///
    /// Slow, maintains tree consistency.
    pub fn cleanup_tree_remove_uninit_layered(&mut self, depth: u32) {
        let depth = usize::try_from(depth).expect("Depth is expected to fit in usize");
        'outer: for i in (1..depth).rev() {
            println!("Cleanup of tree at depth {i}");
            for id in ChainIndex::chain_ids_at_depth(i) {
                if let Some(node) = self.key_map.get(&id).cloned() {
                    if node.value.1.is_empty() {
                        let account_ids = node.account_ids();
                        self.key_map.remove(&id);
                        for addr in account_ids {
                            self.account_id_map.remove(&addr);
                        }
                    } else {
                        break 'outer;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::shadow_unrelated, reason = "We don't care about this in tests")]

    use std::{collections::HashSet, str::FromStr as _};

    use nssa::AccountId;

    use super::*;

    fn seed_holder_for_tests() -> SeedHolder {
        SeedHolder {
            seed: [42; 64].to_vec(),
        }
    }

    #[test]
    fn simple_key_tree() {
        let seed_holder = seed_holder_for_tests();

        let tree = KeyTreePublic::new(&seed_holder);

        assert!(tree.key_map.contains_key(&ChainIndex::root()));
        assert!(tree.account_id_map.contains_key(&AccountId::new([
            172, 82, 222, 249, 164, 16, 148, 184, 219, 56, 92, 145, 203, 220, 251, 89, 214, 178,
            38, 30, 108, 202, 251, 241, 148, 200, 125, 185, 93, 227, 189, 247
        ])));
    }

    #[test]
    fn small_key_tree() {
        let seed_holder = seed_holder_for_tests();

        let mut tree = KeyTreePrivate::new(&seed_holder);

        let next_last_child_for_parent_id = tree
            .find_next_last_child_of_id(&ChainIndex::root())
            .unwrap();

        assert_eq!(next_last_child_for_parent_id, 0);

        tree.generate_new_node(&ChainIndex::root()).unwrap();

        assert!(
            tree.key_map
                .contains_key(&ChainIndex::from_str("/0").unwrap())
        );

        let next_last_child_for_parent_id = tree
            .find_next_last_child_of_id(&ChainIndex::root())
            .unwrap();

        assert_eq!(next_last_child_for_parent_id, 1);

        tree.generate_new_node(&ChainIndex::root()).unwrap();
        tree.generate_new_node(&ChainIndex::root()).unwrap();
        tree.generate_new_node(&ChainIndex::root()).unwrap();
        tree.generate_new_node(&ChainIndex::root()).unwrap();
        tree.generate_new_node(&ChainIndex::root()).unwrap();
        tree.generate_new_node(&ChainIndex::root()).unwrap();

        let next_last_child_for_parent_id = tree
            .find_next_last_child_of_id(&ChainIndex::root())
            .unwrap();

        assert_eq!(next_last_child_for_parent_id, 7);
    }

    #[test]
    fn key_tree_can_not_make_child_keys() {
        let seed_holder = seed_holder_for_tests();

        let mut tree = KeyTreePrivate::new(&seed_holder);

        let next_last_child_for_parent_id = tree
            .find_next_last_child_of_id(&ChainIndex::root())
            .unwrap();

        assert_eq!(next_last_child_for_parent_id, 0);

        tree.generate_new_node(&ChainIndex::root()).unwrap();

        assert!(
            tree.key_map
                .contains_key(&ChainIndex::from_str("/0").unwrap())
        );

        let next_last_child_for_parent_id = tree
            .find_next_last_child_of_id(&ChainIndex::root())
            .unwrap();

        assert_eq!(next_last_child_for_parent_id, 1);

        let key_opt = tree.generate_new_node(&ChainIndex::from_str("/3").unwrap());

        assert_eq!(key_opt, None);
    }

    #[test]
    fn key_tree_complex_structure() {
        let seed_holder = seed_holder_for_tests();

        let mut tree = KeyTreePublic::new(&seed_holder);

        let next_last_child_for_parent_id = tree
            .find_next_last_child_of_id(&ChainIndex::root())
            .unwrap();

        assert_eq!(next_last_child_for_parent_id, 0);

        tree.generate_new_node(&ChainIndex::root()).unwrap();

        assert!(
            tree.key_map
                .contains_key(&ChainIndex::from_str("/0").unwrap())
        );

        let next_last_child_for_parent_id = tree
            .find_next_last_child_of_id(&ChainIndex::root())
            .unwrap();

        assert_eq!(next_last_child_for_parent_id, 1);

        tree.generate_new_node(&ChainIndex::root()).unwrap();

        assert!(
            tree.key_map
                .contains_key(&ChainIndex::from_str("/1").unwrap())
        );

        let next_last_child_for_parent_id = tree
            .find_next_last_child_of_id(&ChainIndex::root())
            .unwrap();

        assert_eq!(next_last_child_for_parent_id, 2);

        tree.generate_new_node(&ChainIndex::from_str("/0").unwrap())
            .unwrap();

        let next_last_child_for_parent_id = tree
            .find_next_last_child_of_id(&ChainIndex::from_str("/0").unwrap())
            .unwrap();

        assert_eq!(next_last_child_for_parent_id, 1);

        assert!(
            tree.key_map
                .contains_key(&ChainIndex::from_str("/0/0").unwrap())
        );

        tree.generate_new_node(&ChainIndex::from_str("/0").unwrap())
            .unwrap();

        let next_last_child_for_parent_id = tree
            .find_next_last_child_of_id(&ChainIndex::from_str("/0").unwrap())
            .unwrap();

        assert_eq!(next_last_child_for_parent_id, 2);

        assert!(
            tree.key_map
                .contains_key(&ChainIndex::from_str("/0/1").unwrap())
        );

        tree.generate_new_node(&ChainIndex::from_str("/0").unwrap())
            .unwrap();

        let next_last_child_for_parent_id = tree
            .find_next_last_child_of_id(&ChainIndex::from_str("/0").unwrap())
            .unwrap();

        assert_eq!(next_last_child_for_parent_id, 3);

        assert!(
            tree.key_map
                .contains_key(&ChainIndex::from_str("/0/2").unwrap())
        );

        tree.generate_new_node(&ChainIndex::from_str("/0/1").unwrap())
            .unwrap();

        assert!(
            tree.key_map
                .contains_key(&ChainIndex::from_str("/0/1/0").unwrap())
        );

        let next_last_child_for_parent_id = tree
            .find_next_last_child_of_id(&ChainIndex::from_str("/0/1").unwrap())
            .unwrap();

        assert_eq!(next_last_child_for_parent_id, 1);
    }

    #[test]
    fn tree_balancing_automatic() {
        let seed_holder = seed_holder_for_tests();

        let mut tree = KeyTreePublic::new(&seed_holder);

        for _ in 0..100 {
            tree.generate_new_node_layered().unwrap();
        }

        let next_slot = tree.find_next_slot_layered();

        assert_eq!(next_slot, ChainIndex::from_str("/0/0/2/1").unwrap());
    }

    #[test]
    fn cleanup() {
        let seed_holder = seed_holder_for_tests();

        let mut tree = KeyTreePrivate::new(&seed_holder);
        tree.generate_tree_for_depth(10);

        let acc = tree
            .key_map
            .get_mut(&ChainIndex::from_str("/1").unwrap())
            .unwrap();
        acc.value.1.push((
            0,
            nssa::Account {
                balance: 2,
                ..nssa::Account::default()
            },
        ));

        let acc = tree
            .key_map
            .get_mut(&ChainIndex::from_str("/2").unwrap())
            .unwrap();
        acc.value.1.push((
            0,
            nssa::Account {
                balance: 3,
                ..nssa::Account::default()
            },
        ));

        let acc = tree
            .key_map
            .get_mut(&ChainIndex::from_str("/0/1").unwrap())
            .unwrap();
        acc.value.1.push((
            0,
            nssa::Account {
                balance: 5,
                ..nssa::Account::default()
            },
        ));

        let acc = tree
            .key_map
            .get_mut(&ChainIndex::from_str("/1/0").unwrap())
            .unwrap();
        acc.value.1.push((
            0,
            nssa::Account {
                balance: 6,
                ..nssa::Account::default()
            },
        ));

        // Update account_id_map for nodes that now have entries
        for chain_index_str in ["/1", "/2", "/0/1", "/1/0"] {
            let id = ChainIndex::from_str(chain_index_str).unwrap();
            if let Some(node) = tree.key_map.get(&id) {
                for account_id in node.account_ids() {
                    tree.account_id_map.insert(account_id, id.clone());
                }
            }
        }

        tree.cleanup_tree_remove_uninit_layered(10);

        let mut key_set_res = HashSet::new();
        key_set_res.insert("/0".to_owned());
        key_set_res.insert("/1".to_owned());
        key_set_res.insert("/2".to_owned());
        key_set_res.insert("/".to_owned());
        key_set_res.insert("/0/0".to_owned());
        key_set_res.insert("/0/1".to_owned());
        key_set_res.insert("/1/0".to_owned());

        let mut key_set = HashSet::new();

        for key in tree.key_map.keys() {
            key_set.insert(key.to_string());
        }

        assert_eq!(key_set, key_set_res);

        let acc = &tree.key_map[&ChainIndex::from_str("/1").unwrap()];
        assert_eq!(acc.value.1[0].1.balance, 2);

        let acc = &tree.key_map[&ChainIndex::from_str("/2").unwrap()];
        assert_eq!(acc.value.1[0].1.balance, 3);

        let acc = &tree.key_map[&ChainIndex::from_str("/0/1").unwrap()];
        assert_eq!(acc.value.1[0].1.balance, 5);

        let acc = &tree.key_map[&ChainIndex::from_str("/1/0").unwrap()];
        assert_eq!(acc.value.1[0].1.balance, 6);
    }
}
