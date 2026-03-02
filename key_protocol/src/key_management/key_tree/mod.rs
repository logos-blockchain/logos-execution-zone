use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use anyhow::Result;
use common::sequencer_client::SequencerClient;
use serde::{Deserialize, Serialize};

use crate::key_management::{
    key_tree::{
        chain_index::ChainIndex, keys_private::ChildKeysPrivate, keys_public::ChildKeysPublic,
        traits::KeyNode,
    },
    secret_holders::SeedHolder,
};

pub mod chain_index;
pub mod keys_private;
pub mod keys_public;
pub mod traits;

pub const DEPTH_SOFT_CAP: u32 = 20;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeyTree<N: KeyNode> {
    pub key_map: BTreeMap<ChainIndex, N>,
    pub account_id_map: HashMap<nssa::AccountId, ChainIndex>,
}

pub type KeyTreePublic = KeyTree<ChildKeysPublic>;
pub type KeyTreePrivate = KeyTree<ChildKeysPrivate>;

impl<N: KeyNode> KeyTree<N> {
    pub fn new(seed: &SeedHolder) -> Self {
        let seed_fit: [u8; 64] = seed
            .seed
            .clone()
            .try_into()
            .expect("SeedHolder seed is 64 bytes long");

        let root_keys = N::root(seed_fit);
        let account_id = root_keys.account_id();

        let key_map = BTreeMap::from_iter([(ChainIndex::root(), root_keys)]);
        let account_id_map = HashMap::from_iter([(account_id, ChainIndex::root())]);

        Self {
            key_map,
            account_id_map,
        }
    }

    pub fn new_from_root(root: N) -> Self {
        let account_id_map = HashMap::from_iter([(root.account_id(), ChainIndex::root())]);
        let key_map = BTreeMap::from_iter([(ChainIndex::root(), root)]);

        Self {
            key_map,
            account_id_map,
        }
    }

    // ToDo: Add function to create a tree from list of nodes with consistency check.

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
            let rightmost_ref_next = self.key_map.get(&rightmost_child.next_in_line());

            match (&rightmost_ref, &rightmost_ref_next) {
                (Some(_), Some(_)) => {
                    left_border = right;
                    right = (right + right_border) / 2;
                }
                (Some(_), None) => {
                    break Some(right + 1);
                }
                (None, None) => {
                    right_border = right;
                    right = (left_border + right) / 2;
                }
                (None, Some(_)) => {
                    unreachable!();
                }
            }
        }
    }

    pub fn generate_new_node(
        &mut self,
        parent_cci: &ChainIndex,
    ) -> Option<(nssa::AccountId, ChainIndex)> {
        let parent_keys = self.key_map.get(parent_cci)?;
        let next_child_id = self
            .find_next_last_child_of_id(parent_cci)
            .expect("Can be None only if parent is not present");
        let next_cci = parent_cci.nth_child(next_child_id);

        let child_keys = parent_keys.nth_child(next_child_id);
        let account_id = child_keys.account_id();

        self.key_map.insert(next_cci.clone(), child_keys);
        self.account_id_map.insert(account_id, next_cci.clone());

        Some((account_id, next_cci))
    }

    fn find_next_slot_layered(&self) -> ChainIndex {
        let mut depth = 1;

        'outer: loop {
            for chain_id in ChainIndex::chain_ids_at_depth_rev(depth) {
                if !self.key_map.contains_key(&chain_id) {
                    break 'outer chain_id;
                }
            }
            depth += 1;
        }
    }

    pub fn fill_node(&mut self, chain_index: &ChainIndex) -> Option<(nssa::AccountId, ChainIndex)> {
        let parent_keys = self.key_map.get(&chain_index.parent()?)?;
        let child_id = *chain_index.chain().last()?;

        let child_keys = parent_keys.nth_child(child_id);
        let account_id = child_keys.account_id();

        self.key_map.insert(chain_index.clone(), child_keys);
        self.account_id_map.insert(account_id, chain_index.clone());

        Some((account_id, chain_index.clone()))
    }

    pub fn generate_new_node_layered(&mut self) -> Option<(nssa::AccountId, ChainIndex)> {
        self.fill_node(&self.find_next_slot_layered())
    }

    pub fn get_node(&self, account_id: nssa::AccountId) -> Option<&N> {
        self.account_id_map
            .get(&account_id)
            .and_then(|chain_id| self.key_map.get(chain_id))
    }

    pub fn get_node_mut(&mut self, account_id: nssa::AccountId) -> Option<&mut N> {
        self.account_id_map
            .get(&account_id)
            .and_then(|chain_id| self.key_map.get_mut(chain_id))
    }

    pub fn insert(&mut self, account_id: nssa::AccountId, chain_index: ChainIndex, node: N) {
        self.account_id_map.insert(account_id, chain_index.clone());
        self.key_map.insert(chain_index, node);
    }

    pub fn remove(&mut self, addr: nssa::AccountId) -> Option<N> {
        let chain_index = self.account_id_map.remove(&addr).unwrap();
        self.key_map.remove(&chain_index)
    }

    /// Populates tree with children.
    ///
    /// For given `depth` adds children to a tree such that their `ChainIndex::depth(&self) <
    /// depth`.
    ///
    /// Tree must be empty before start
    pub fn generate_tree_for_depth(&mut self, depth: u32) {
        let mut id_stack = vec![ChainIndex::root()];

        while let Some(curr_id) = id_stack.pop() {
            let mut next_id = curr_id.nth_child(0);

            while (next_id.depth()) < depth {
                self.generate_new_node(&curr_id);
                id_stack.push(next_id.clone());
                next_id = next_id.next_in_line();
            }
        }
    }
}

impl KeyTree<ChildKeysPrivate> {
    /// Cleanup of all non-initialized accounts in a private tree
    ///
    /// For given `depth` checks children to a tree such that their `ChainIndex::depth(&self) <
    /// depth`.
    ///
    /// If account is default, removes them.
    ///
    /// Chain must be parsed for accounts beforehand
    ///
    /// Fast, leaves gaps between accounts
    pub fn cleanup_tree_remove_uninit_for_depth(&mut self, depth: u32) {
        let mut id_stack = vec![ChainIndex::root()];

        while let Some(curr_id) = id_stack.pop() {
            if let Some(node) = self.key_map.get(&curr_id)
                && node.value.1 == nssa::Account::default()
                && curr_id != ChainIndex::root()
            {
                let addr = node.account_id();
                self.remove(addr);
            }

            let mut next_id = curr_id.nth_child(0);

            while (next_id.depth()) < depth {
                id_stack.push(next_id.clone());
                next_id = next_id.next_in_line();
            }
        }
    }

    /// Cleanup of non-initialized accounts in a private tree
    ///
    /// If account is default, removes them, stops at first non-default account.
    ///
    /// Walks through tree in lairs of same depth using `ChainIndex::chain_ids_at_depth()`
    ///
    /// Chain must be parsed for accounts beforehand
    ///
    /// Slow, maintains tree consistency.
    pub fn cleanup_tree_remove_uninit_layered(&mut self, depth: u32) {
        'outer: for i in (1..(depth as usize)).rev() {
            println!("Cleanup of tree at depth {i}");
            for id in ChainIndex::chain_ids_at_depth(i) {
                if let Some(node) = self.key_map.get(&id) {
                    if node.value.1 == nssa::Account::default() {
                        let addr = node.account_id();
                        self.remove(addr);
                    } else {
                        break 'outer;
                    }
                }
            }
        }
    }
}

impl KeyTree<ChildKeysPublic> {
    /// Cleanup of all non-initialized accounts in a public tree
    ///
    /// For given `depth` checks children to a tree such that their `ChainIndex::depth(&self) <
    /// depth`.
    ///
    /// If account is default, removes them.
    ///
    /// Fast, leaves gaps between accounts
    pub async fn cleanup_tree_remove_ininit_for_depth(
        &mut self,
        depth: u32,
        client: Arc<SequencerClient>,
    ) -> Result<()> {
        let mut id_stack = vec![ChainIndex::root()];

        while let Some(curr_id) = id_stack.pop() {
            if let Some(node) = self.key_map.get(&curr_id) {
                let address = node.account_id();
                let node_acc = client.get_account(address).await?.account;

                if node_acc == nssa::Account::default() && curr_id != ChainIndex::root() {
                    self.remove(address);
                }
            }

            let mut next_id = curr_id.nth_child(0);

            while (next_id.depth()) < depth {
                id_stack.push(next_id.clone());
                next_id = next_id.next_in_line();
            }
        }

        Ok(())
    }

    /// Cleanup of non-initialized accounts in a public tree
    ///
    /// If account is default, removes them, stops at first non-default account.
    ///
    /// Walks through tree in lairs of same depth using `ChainIndex::chain_ids_at_depth()`
    ///
    /// Slow, maintains tree consistency.
    pub async fn cleanup_tree_remove_uninit_layered(
        &mut self,
        depth: u32,
        client: Arc<SequencerClient>,
    ) -> Result<()> {
        'outer: for i in (1..(depth as usize)).rev() {
            println!("Cleanup of tree at depth {i}");
            for id in ChainIndex::chain_ids_at_depth(i) {
                if let Some(node) = self.key_map.get(&id) {
                    let address = node.account_id();
                    let node_acc = client.get_account(address).await?.account;

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

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, str::FromStr};

    use nssa::AccountId;

    use super::*;

    fn seed_holder_for_tests() -> SeedHolder {
        SeedHolder {
            seed: [42; 64].to_vec(),
        }
    }

    #[test]
    fn test_simple_key_tree() {
        let seed_holder = seed_holder_for_tests();

        let tree = KeyTreePublic::new(&seed_holder);

        assert!(tree.key_map.contains_key(&ChainIndex::root()));
        assert!(tree.account_id_map.contains_key(&AccountId::new([
            10, 231, 159, 65, 236, 46, 205, 5, 172, 89, 250, 29, 123, 195, 212, 137, 155, 111, 40,
            120, 53, 28, 124, 54, 224, 170, 119, 208, 2, 72, 75, 50
        ])));
    }

    #[test]
    fn test_small_key_tree() {
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
    fn test_key_tree_can_not_make_child_keys() {
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
    fn test_key_tree_complex_structure() {
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
    fn test_tree_balancing_automatic() {
        let seed_holder = seed_holder_for_tests();

        let mut tree = KeyTreePublic::new(&seed_holder);

        for _ in 0..100 {
            tree.generate_new_node_layered().unwrap();
        }

        let next_slot = tree.find_next_slot_layered();

        assert_eq!(next_slot, ChainIndex::from_str("/0/0/2/1").unwrap());
    }

    #[test]
    fn test_cleanup() {
        let seed_holder = seed_holder_for_tests();

        let mut tree = KeyTreePrivate::new(&seed_holder);
        tree.generate_tree_for_depth(10);

        let acc = tree
            .key_map
            .get_mut(&ChainIndex::from_str("/1").unwrap())
            .unwrap();
        acc.value.1.balance = 2;

        let acc = tree
            .key_map
            .get_mut(&ChainIndex::from_str("/2").unwrap())
            .unwrap();
        acc.value.1.balance = 3;

        let acc = tree
            .key_map
            .get_mut(&ChainIndex::from_str("/0/1").unwrap())
            .unwrap();
        acc.value.1.balance = 5;

        let acc = tree
            .key_map
            .get_mut(&ChainIndex::from_str("/1/0").unwrap())
            .unwrap();
        acc.value.1.balance = 6;

        tree.cleanup_tree_remove_uninit_layered(10);

        let mut key_set_res = HashSet::new();
        key_set_res.insert("/0".to_string());
        key_set_res.insert("/1".to_string());
        key_set_res.insert("/2".to_string());
        key_set_res.insert("/".to_string());
        key_set_res.insert("/0/0".to_string());
        key_set_res.insert("/0/1".to_string());
        key_set_res.insert("/1/0".to_string());

        let mut key_set = HashSet::new();

        for key in tree.key_map.keys() {
            key_set.insert(key.to_string());
        }

        assert_eq!(key_set, key_set_res);

        let acc = tree
            .key_map
            .get(&ChainIndex::from_str("/1").unwrap())
            .unwrap();
        assert_eq!(acc.value.1.balance, 2);

        let acc = tree
            .key_map
            .get(&ChainIndex::from_str("/2").unwrap())
            .unwrap();
        assert_eq!(acc.value.1.balance, 3);

        let acc = tree
            .key_map
            .get(&ChainIndex::from_str("/0/1").unwrap())
            .unwrap();
        assert_eq!(acc.value.1.balance, 5);

        let acc = tree
            .key_map
            .get(&ChainIndex::from_str("/1/0").unwrap())
            .unwrap();
        assert_eq!(acc.value.1.balance, 6);
    }
}
