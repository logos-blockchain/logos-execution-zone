//! Compact sparse Merkle tree over 256-bit keys, for the STF prototype.
//!
//! An empty subtree hashes to zero, a subtree holding one leaf is that leaf, and a subtree holding
//! more is an internal node, so the root is a function of the key set alone. Keys are only ever
//! inserted or updated, never removed.
//!
//! A block's guest gets a multiproof, the old tree cut to the touched keys' paths as little-endian
//! words read in place: an untouched position is its 8-word hash, a touched one a tag word and then
//! a leaf's key and value or an internal node's two children, with the keys choosing each
//! direction.

use risc0_zkvm::sha::{Digest, Impl, Sha256 as _};

pub type Key = [u8; 32];
pub type Hash = [u8; 32];

pub const EMPTY: Hash = [0; 32];

const TAG_EMPTY: u32 = 0;
const TAG_LEAF: u32 = 1;
const TAG_INTERNAL: u32 = 2;

/// A key's value before the block and after it; `None` is absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Update {
    pub key: Key,
    pub old: Option<Hash>,
    pub new: Option<Hash>,
}

fn bit(key: &Key, depth: usize) -> bool {
    (key[depth / 8] >> (7 - depth % 8)) & 1 == 1
}

fn to_hash(digest: &Digest) -> Hash {
    digest.as_bytes().try_into().expect("a digest is 32 bytes")
}

fn leaf_digest(key: &Key, value: &Hash) -> Digest {
    let mut buf = [0_u8; 65];
    buf[1..33].copy_from_slice(key);
    buf[33..].copy_from_slice(value);
    *Impl::hash_bytes(&buf)
}

fn internal_digest(left: &Digest, right: &Digest) -> Digest {
    *Impl::hash_pair(left, right)
}

/// SHA-256 of `0x00 || key || value`.
#[must_use]
pub fn leaf_hash(key: &Key, value: &Hash) -> Hash {
    to_hash(&leaf_digest(key, value))
}

/// One SHA-256 compression of `left || right`, unpadded, so it never equals a leaf hash.
#[must_use]
pub fn internal_hash(left: &Hash, right: &Hash) -> Hash {
    to_hash(&internal_digest(
        &Digest::from_bytes(*left),
        &Digest::from_bytes(*right),
    ))
}

/// SHA-256 of `bytes`, used for leaf values.
#[must_use]
pub fn value_hash(bytes: &[u8]) -> Hash {
    to_hash(&Impl::hash_bytes(bytes))
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

/// The multiproof of `keys` in the tree over `entries`, both sorted and distinct, as bytes.
#[must_use]
pub fn multiproof(entries: &[(Key, Hash)], keys: &[Key]) -> Vec<u8> {
    let mut out = Vec::new();
    encode(entries, keys, 0, &mut out);
    out
}

fn encode(entries: &[(Key, Hash)], keys: &[Key], depth: usize, out: &mut Vec<u8>) {
    if keys.is_empty() {
        out.extend_from_slice(&subtree_hash(entries, depth));
        return;
    }
    match entries {
        [] => out.extend_from_slice(&TAG_EMPTY.to_le_bytes()),
        [(key, value)] => {
            out.extend_from_slice(&TAG_LEAF.to_le_bytes());
            out.extend_from_slice(key);
            out.extend_from_slice(value);
        }
        _ => {
            out.extend_from_slice(&TAG_INTERNAL.to_le_bytes());
            let mid = entries.partition_point(|(key, _)| !bit(key, depth));
            let keys_mid = keys.partition_point(|key| !bit(key, depth));
            encode(&entries[..mid], &keys[..keys_mid], depth + 1, out);
            encode(&entries[mid..], &keys[keys_mid..], depth + 1, out);
        }
    }
}

/// Checks every update's old value against the tree `proof` describes and returns the old and
/// new roots.
///
/// # Panics
/// If `updates` are not sorted and distinct, the proof does not cover exactly their paths, an old
/// value disagrees with the tree, or an update removes a key.
#[must_use]
pub fn verify_and_update(proof: &[u32], updates: &[Update]) -> (Hash, Hash) {
    assert!(
        updates.windows(2).all(|pair| pair[0].key < pair[1].key),
        "updates must be sorted and distinct"
    );
    let mut words = Words(proof);
    let (old, new) = walk(&mut words, updates, 0);
    assert!(words.0.is_empty(), "the proof has trailing words");
    (to_hash(&old), to_hash(&new.unwrap_or(old)))
}

struct Words<'a>(&'a [u32]);

impl Words<'_> {
    fn tag(&mut self) -> u32 {
        let (&tag, tail) = self.0.split_first().expect("the proof is truncated");
        self.0 = tail;
        tag
    }

    fn digest(&mut self) -> Digest {
        let (head, tail) = self
            .0
            .split_first_chunk::<8>()
            .expect("the proof is truncated");
        self.0 = tail;
        Digest::new(*head)
    }
}

/// A subtree's old hash, and its new one if any update changed it.
fn walk(words: &mut Words<'_>, updates: &[Update], depth: usize) -> (Digest, Option<Digest>) {
    if updates.is_empty() {
        return (words.digest(), None);
    }
    match words.tag() {
        TAG_EMPTY => {
            assert!(
                updates.iter().all(|update| update.old.is_none()),
                "an old value disagrees with the tree"
            );
            let inserted = updates.iter().any(|update| update.new.is_some());
            (
                Digest::ZERO,
                inserted.then(|| Digest::from_bytes(rebuild(None, updates, depth))),
            )
        }
        TAG_LEAF => {
            let key = to_hash(&words.digest());
            let value = to_hash(&words.digest());
            for update in updates {
                assert_eq!(
                    update.old,
                    (update.key == key).then_some(value),
                    "an old value disagrees with the tree"
                );
            }
            let old = leaf_digest(&key, &value);
            if updates.len() == 1 && updates[0].key == key {
                let new = updates[0].new.expect("a key is never removed");
                return (old, (new != value).then(|| leaf_digest(&key, &new)));
            }
            (
                old,
                Some(Digest::from_bytes(rebuild(
                    Some((key, value)),
                    updates,
                    depth,
                ))),
            )
        }
        TAG_INTERNAL => {
            let mid = updates.partition_point(|update| !bit(&update.key, depth));
            let (old_left, new_left) = walk(words, &updates[..mid], depth + 1);
            let (old_right, new_right) = walk(words, &updates[mid..], depth + 1);
            let new = (new_left.is_some() || new_right.is_some()).then(|| {
                internal_digest(
                    &new_left.unwrap_or(old_left),
                    &new_right.unwrap_or(old_right),
                )
            });
            (internal_digest(&old_left, &old_right), new)
        }
        tag => panic!("unknown proof tag {tag}"),
    }
}

/// The new hash of a subtree at `depth` that held only `kept` before `updates`.
fn rebuild(kept: Option<(Key, Hash)>, updates: &[Update], depth: usize) -> Hash {
    let mut entries: Vec<(Key, Hash)> = kept
        .filter(|(key, _)| {
            updates
                .binary_search_by_key(key, |update| update.key)
                .is_err()
        })
        .into_iter()
        .collect();
    for update in updates {
        match (update.old, update.new) {
            (_, Some(new)) => entries.push((update.key, new)),
            (Some(_), None) => panic!("a key is never removed"),
            (None, None) => {}
        }
    }
    entries.sort_unstable_by_key(|(key, _)| *key);
    subtree_hash(&entries, depth)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u32) -> Key {
        to_hash(&Impl::hash_bytes(&n.to_le_bytes()))
    }

    fn tree(ids: impl IntoIterator<Item = u32>) -> Vec<(Key, Hash)> {
        let mut entries: Vec<(Key, Hash)> =
            ids.into_iter().map(|n| (key(n), [n as u8; 32])).collect();
        entries.sort();
        entries
    }

    fn words(bytes: &[u8]) -> Vec<u32> {
        bytes
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("four bytes")))
            .collect()
    }

    fn proof(entries: &[(Key, Hash)], keys: &[Key]) -> Vec<u32> {
        let bytes = multiproof(entries, keys);
        assert_eq!(bytes.len() % 4, 0);
        words(&bytes)
    }

    fn apply(entries: &mut Vec<(Key, Hash)>, updates: &[Update]) {
        for update in updates {
            if let Some(new) = update.new {
                match entries.binary_search_by_key(&update.key, |(k, _)| *k) {
                    Ok(i) => entries[i].1 = new,
                    Err(i) => entries.insert(i, (update.key, new)),
                }
            }
        }
    }

    fn check(mut entries: Vec<(Key, Hash)>, mut updates: Vec<Update>) {
        updates.sort_by_key(|update| update.key);
        let keys: Vec<Key> = updates.iter().map(|update| update.key).collect();
        let proof = proof(&entries, &keys);
        let old_root = root(&entries);
        apply(&mut entries, &updates);
        assert_eq!(
            verify_and_update(&proof, &updates),
            (old_root, root(&entries))
        );
    }

    fn update(n: u32, old: Option<u8>, new: Option<u8>) -> Update {
        Update {
            key: key(n),
            old: old.map(|byte| [byte; 32]),
            new: new.map(|byte| [byte; 32]),
        }
    }

    #[test]
    fn updates_inserts_and_absent_reads_match_a_rebuilt_tree() {
        check(
            tree(0..200),
            vec![
                update(3, Some(3), Some(0xAA)),
                update(77, Some(77), Some(77)),
                update(150, Some(150), Some(0xBB)),
                update(500, None, Some(0xCC)),
                update(501, None, Some(0xDD)),
                update(502, None, None),
            ],
        );
    }

    #[test]
    fn inserts_into_an_empty_tree_and_a_lone_leaf() {
        check(
            tree([]),
            vec![update(1, None, Some(1)), update(2, None, Some(2))],
        );
        check(
            tree([7]),
            vec![update(8, None, Some(8)), update(9, None, None)],
        );
        check(
            tree([7]),
            vec![update(7, Some(7), Some(0xEE)), update(8, None, Some(8))],
        );
    }

    #[test]
    fn untouched_tree_keeps_its_root() {
        check(
            tree(0..50),
            vec![update(10, Some(10), Some(10)), update(99, None, None)],
        );
    }

    #[test]
    #[should_panic(expected = "an old value disagrees with the tree")]
    fn rejects_a_wrong_old_value() {
        let entries = tree(0..20);
        let proof = proof(&entries, &[key(5)]);
        let _ = verify_and_update(&proof, &[update(5, Some(6), Some(6))]);
    }

    #[test]
    #[should_panic(expected = "an old value disagrees with the tree")]
    fn rejects_a_present_key_claimed_absent() {
        let entries = tree(0..20);
        let proof = proof(&entries, &[key(5)]);
        let _ = verify_and_update(&proof, &[update(5, None, Some(6))]);
    }

    #[test]
    fn a_proof_for_other_keys_never_gives_the_old_root() {
        let entries = tree(0..20);
        let mut updates: Vec<Update> = [5, 6]
            .map(|n| update(n, Some(n as u8), Some(n as u8)))
            .to_vec();
        updates.sort_by_key(|update| update.key);
        let proof = proof(&entries, &[updates[0].key]);
        let result = std::panic::catch_unwind(|| verify_and_update(&proof, &updates));
        assert!(result.map_or(true, |(old, _)| old != root(&entries)));
    }
}
