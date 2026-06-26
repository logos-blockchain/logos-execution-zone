#![expect(clippy::arithmetic_side_effects, reason = "TODO: fix later")]

use borsh::{BorshDeserialize, BorshSerialize};
use sha2::{Digest as _, Sha256};

mod default_values;

type Value = [u8; 32];
type Node = [u8; 32];

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct MerkleTree {
    nodes: Vec<Node>,
    capacity: usize,
    length: usize,
}

impl MerkleTree {
    pub fn with_capacity(capacity: usize) -> Self {
        // Adjust capacity to ensure power of two
        let capacity = capacity.next_power_of_two();
        let total_depth = usize::try_from(capacity.trailing_zeros()).expect("u32 fits in usize");

        let nodes = default_values::DEFAULT_VALUES[..=total_depth]
            .iter()
            .rev()
            .enumerate()
            .flat_map(|(level, default_value)| std::iter::repeat_n(default_value, 1 << level))
            .copied()
            .collect();

        Self {
            nodes,
            capacity,
            length: 0,
        }
    }

    pub fn root(&self) -> Node {
        let root_index = self.root_index();
        *self.get_node(root_index)
    }

    fn root_index(&self) -> usize {
        let tree_depth = self.depth();
        let capacity_depth =
            usize::try_from(self.capacity.trailing_zeros()).expect("u32 fits in usize");

        if tree_depth == capacity_depth {
            0
        } else {
            // 2^(capacity_depth - tree_depth) - 1
            (1 << (capacity_depth - tree_depth)) - 1
        }
    }

    /// Number of levels required to hold all nodes.
    fn depth(&self) -> usize {
        usize::try_from(self.length.next_power_of_two().trailing_zeros())
            .expect("u32 fits in usize")
    }

    fn get_node(&self, index: usize) -> &Node {
        &self.nodes[index]
    }

    fn set_node(&mut self, index: usize, node: Node) {
        self.nodes[index] = node;
    }

    /// Reallocates storage of Merkle tree for double capacity.
    /// The current tree is embedded into the new tree as a subtree.
    fn reallocate_to_double_capacity(&mut self) {
        let old_capacity = self.capacity;
        let new_capacity = old_capacity << 1;

        let mut this = Self::with_capacity(new_capacity);

        for (index, value) in self.nodes.iter().enumerate() {
            let offset = prev_power_of_two(index + 1);
            let new_index = index + offset;
            this.set_node(new_index, *value);
        }

        this.length = self.length;

        *self = this;
    }

    pub fn insert(&mut self, value: Value) -> usize {
        if self.length == self.capacity {
            self.reallocate_to_double_capacity();
        }

        let new_index = self.length;

        let mut node_index = new_index + self.capacity - 1;
        let mut node_hash = hash_value(&value);

        // Insert the new node at the bottom layer
        self.set_node(node_index, node_hash);
        self.length += 1;

        // Update upper levels for the newly inserted node
        for _ in 0..self.depth() {
            let parent_index = (node_index - 1) >> 1;
            let left_child = self.get_node((parent_index << 1) + 1);
            let right_child = self.get_node((parent_index << 1) + 2);
            node_hash = hash_two(left_child, right_child);
            self.set_node(parent_index, node_hash);
            node_index = parent_index;
        }

        new_index
    }

    pub fn get_authentication_path_for(&self, index: usize) -> Option<Vec<Node>> {
        if index >= self.length {
            return None;
        }

        let mut path = Vec::with_capacity(self.depth());

        let mut node_index = self.capacity + index - 1;
        let root_index = self.root_index();

        while node_index != root_index {
            let parent_index = (node_index - 1) >> 1;
            // Left children have odd indices, and right children have even indices
            let is_left_child = node_index & 1 == 1;
            let sibling_index = if is_left_child {
                node_index + 1
            } else {
                node_index - 1
            };
            path.push(*self.get_node(sibling_index));
            node_index = parent_index;
        }

        Some(path)
    }
}

/// Compute parent as the hash of two child nodes.
fn hash_two(left: &Node, right: &Node) -> Node {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn hash_value(value: &Value) -> Node {
    let mut hasher = Sha256::new();
    hasher.update(value);
    hasher.finalize().into()
}

const fn prev_power_of_two(x: usize) -> usize {
    if x == 0 {
        return 0;
    }
    1 << (usize::BITS - x.leading_zeros() - 1)
}

#[cfg(test)]
mod tests;
