//! Compact sparse Merkle tree over 256-bit keys, for the STF prototype.
//!
//! An empty subtree hashes to zero, a subtree holding one leaf is that leaf, and a subtree holding
//! more is an internal node, so the root is a function of the key set alone. Keys are only ever
//! inserted or updated, never removed.

use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::sha::{Digest, Impl, Sha256 as _};

pub type Key = [u8; 32];
pub type Hash = [u8; 32];

pub const EMPTY: Hash = [0; 32];

/// A tree, or the part of one a block's guest needs: untouched subtrees are cut to their hash.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum Node {
    Empty,
    Pruned(Hash),
    Leaf { key: Key, value: Hash },
    Internal(Box<Node>, Box<Node>),
}

/// What a lookup in a partial tree shows about a key.
#[derive(Debug, PartialEq, Eq)]
pub enum Lookup {
    Found(Hash),
    Absent,
    /// The key's path runs into a pruned subtree.
    Unknown,
}

fn bit(key: &Key, depth: usize) -> bool {
    (key[depth / 8] >> (7 - depth % 8)) & 1 == 1
}

fn to_hash(digest: &Digest) -> Hash {
    digest.as_bytes().try_into().expect("a digest is 32 bytes")
}

/// SHA-256 of `0x00 || key || value`.
#[must_use]
pub fn leaf_hash(key: &Key, value: &Hash) -> Hash {
    let mut buf = [0_u8; 65];
    buf[1..33].copy_from_slice(key);
    buf[33..].copy_from_slice(value);
    to_hash(&Impl::hash_bytes(&buf))
}

/// One SHA-256 compression of `left || right`, unpadded, so it never equals a leaf hash.
#[must_use]
pub fn internal_hash(left: &Hash, right: &Hash) -> Hash {
    to_hash(&Impl::hash_pair(
        &Digest::from_bytes(*left),
        &Digest::from_bytes(*right),
    ))
}

/// SHA-256 of `bytes`, used for leaf values.
#[must_use]
pub fn value_hash(bytes: &[u8]) -> Hash {
    to_hash(&Impl::hash_bytes(bytes))
}

impl Node {
    #[must_use]
    pub fn hash(&self) -> Hash {
        match self {
            Self::Empty => EMPTY,
            Self::Pruned(hash) => *hash,
            Self::Leaf { key, value } => leaf_hash(key, value),
            Self::Internal(left, right) => internal_hash(&left.hash(), &right.hash()),
        }
    }

    #[must_use]
    pub fn get(&self, key: &Key) -> Lookup {
        let mut node = self;
        let mut depth = 0;
        loop {
            match node {
                Self::Empty => return Lookup::Absent,
                Self::Pruned(_) => return Lookup::Unknown,
                Self::Leaf { key: at, value } => {
                    return if at == key {
                        Lookup::Found(*value)
                    } else {
                        Lookup::Absent
                    };
                }
                Self::Internal(left, right) => {
                    node = if bit(key, depth) { right } else { left };
                    depth += 1;
                }
            }
        }
    }

    /// Sets `key` to `value`, inserting it if absent.
    ///
    /// # Panics
    /// If the key's path runs into a pruned subtree.
    pub fn upsert(&mut self, key: Key, value: Hash) {
        self.upsert_at(key, value, 0);
    }

    fn upsert_at(&mut self, key: Key, value: Hash, depth: usize) {
        match self {
            Self::Empty => *self = Self::Leaf { key, value },
            Self::Pruned(_) => panic!("the witness does not cover this key's path"),
            Self::Leaf { key: at, value: old } if *at == key => *old = value,
            Self::Leaf { key: at, value: old } => {
                *self = Self::split((*at, *old), (key, value), depth);
            }
            Self::Internal(left, right) => {
                if bit(&key, depth) {
                    right.upsert_at(key, value, depth + 1);
                } else {
                    left.upsert_at(key, value, depth + 1);
                }
            }
        }
    }

    fn split(a: (Key, Hash), b: (Key, Hash), depth: usize) -> Self {
        let leaf = |(key, value): (Key, Hash)| Box::new(Self::Leaf { key, value });
        match (bit(&a.0, depth), bit(&b.0, depth)) {
            (false, true) => Self::Internal(leaf(a), leaf(b)),
            (true, false) => Self::Internal(leaf(b), leaf(a)),
            (false, false) => Self::Internal(Box::new(Self::split(a, b, depth + 1)), Box::new(Self::Empty)),
            (true, true) => Self::Internal(Box::new(Self::Empty), Box::new(Self::split(a, b, depth + 1))),
        }
    }
}

/// The root of the tree over `entries`, which must be sorted by key and distinct.
#[must_use]
pub fn root(entries: &[(Key, Hash)]) -> Hash {
    subtree_hash(entries, 0)
}

fn subtree_hash(entries: &[(Key, Hash)], depth: usize) -> Hash {
    match entries {
        [] => EMPTY,
        [(key, value)] => leaf_hash(key, value),
        _ => {
            let mid = entries.partition_point(|(key, _)| !bit(key, depth));
            internal_hash(
                &subtree_hash(&entries[..mid], depth + 1),
                &subtree_hash(&entries[mid..], depth + 1),
            )
        }
    }
}

/// The part of the tree over `entries` that covers the paths of `touched`; both sorted.
#[must_use]
pub fn witness(entries: &[(Key, Hash)], touched: &[Key]) -> Node {
    witness_at(entries, touched, 0)
}

fn witness_at(entries: &[(Key, Hash)], touched: &[Key], depth: usize) -> Node {
    if touched.is_empty() {
        return if entries.is_empty() {
            Node::Empty
        } else {
            Node::Pruned(subtree_hash(entries, depth))
        };
    }
    match entries {
        [] => Node::Empty,
        [(key, value)] => Node::Leaf {
            key: *key,
            value: *value,
        },
        _ => {
            let mid = entries.partition_point(|(key, _)| !bit(key, depth));
            let touched_mid = touched.partition_point(|key| !bit(key, depth));
            Node::Internal(
                Box::new(witness_at(&entries[..mid], &touched[..touched_mid], depth + 1)),
                Box::new(witness_at(&entries[mid..], &touched[touched_mid..], depth + 1)),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u32) -> Key {
        to_hash(&Impl::hash_bytes(&n.to_le_bytes()))
    }

    #[test]
    fn witness_updates_match_a_rebuilt_tree() {
        let mut entries: Vec<(Key, Hash)> = (0..200).map(|n| (key(n), [n as u8; 32])).collect();
        entries.sort();
        let touched_ids = [3_u32, 77, 150, 500, 501];
        let mut touched: Vec<Key> = touched_ids.iter().map(|&n| key(n)).collect();
        touched.sort();

        let mut partial = witness(&entries, &touched);
        assert_eq!(partial.hash(), root(&entries));
        assert_eq!(partial.get(&key(3)), Lookup::Found([3; 32]));
        assert_eq!(partial.get(&key(500)), Lookup::Absent);

        for &n in &touched_ids {
            partial.upsert(key(n), [0xAA; 32]);
            match entries.binary_search_by_key(&key(n), |(k, _)| *k) {
                Ok(i) => entries[i].1 = [0xAA; 32],
                Err(i) => entries.insert(i, (key(n), [0xAA; 32])),
            }
        }
        assert_eq!(partial.hash(), root(&entries));
    }
}
