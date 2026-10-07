//! Borsh encodings of the persistent collections the state is built on, byte-identical to the
//! `HashMap`, `HashSet` and `Vec` each one replaced, so stored states keep decoding.

use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    io::{Read, Result, Write},
};

use borsh::{BorshDeserialize, BorshSerialize};
use rpds::{HashTrieMapSync, HashTrieSetSync, VectorSync};

pub fn serialize_map<K, V, W>(map: &HashTrieMapSync<K, V>, writer: &mut W) -> Result<()>
where
    K: BorshSerialize + Eq + Hash + Ord,
    V: BorshSerialize,
    W: Write,
{
    let mut entries: Vec<(&K, &V)> = map.iter().collect();
    entries.sort_unstable_by_key(|&(key, _)| key);
    entries.serialize(writer)
}

pub fn deserialize_map<K, V, R>(reader: &mut R) -> Result<HashTrieMapSync<K, V>>
where
    K: BorshDeserialize + Eq + Hash + Ord,
    V: BorshDeserialize,
    R: Read,
{
    Ok(HashMap::<K, V>::deserialize_reader(reader)?
        .into_iter()
        .collect())
}

pub fn serialize_set<T, W>(set: &HashTrieSetSync<T>, writer: &mut W) -> Result<()>
where
    T: BorshSerialize + Eq + Hash + Ord,
    W: Write,
{
    let mut items: Vec<&T> = set.iter().collect();
    items.sort_unstable();
    items.serialize(writer)
}

pub fn deserialize_set<T, R>(reader: &mut R) -> Result<HashTrieSetSync<T>>
where
    T: BorshDeserialize + Eq + Hash + Ord,
    R: Read,
{
    Ok(HashSet::<T>::deserialize_reader(reader)?
        .into_iter()
        .collect())
}

pub fn serialize_vector<T, W>(vector: &VectorSync<T>, writer: &mut W) -> Result<()>
where
    T: BorshSerialize,
    W: Write,
{
    vector.iter().collect::<Vec<&T>>().serialize(writer)
}

pub fn deserialize_vector<T, R>(reader: &mut R) -> Result<VectorSync<T>>
where
    T: BorshDeserialize,
    R: Read,
{
    Ok(Vec::<T>::deserialize_reader(reader)?.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(serialize: impl FnOnce(&mut Vec<u8>) -> Result<()>) -> Vec<u8> {
        let mut bytes = Vec::new();
        serialize(&mut bytes).expect("serializes");
        bytes
    }

    #[test]
    fn a_map_encodes_and_decodes_as_a_hash_map() {
        let std: HashMap<u32, u64> = (0..100).map(|key| (key, u64::from(key))).collect();
        let map: HashTrieMapSync<u32, u64> = std.clone().into_iter().collect();

        let bytes = encoded(|writer| serialize_map(&map, writer));
        assert_eq!(bytes, borsh::to_vec(&std).unwrap());
        assert_eq!(
            deserialize_map::<u32, u64, _>(&mut bytes.as_slice()).unwrap(),
            map
        );
    }

    #[test]
    fn a_set_encodes_and_decodes_as_a_hash_set() {
        let std: HashSet<u32> = (0..100).collect();
        let set: HashTrieSetSync<u32> = std.clone().into_iter().collect();

        let bytes = encoded(|writer| serialize_set(&set, writer));
        assert_eq!(bytes, borsh::to_vec(&std).unwrap());
        assert_eq!(
            deserialize_set::<u32, _>(&mut bytes.as_slice()).unwrap(),
            set
        );
    }

    #[test]
    fn a_vector_encodes_and_decodes_as_a_vec() {
        let std: Vec<[u8; 32]> = (0..100_u8).map(|item| [item; 32]).collect();
        let vector: VectorSync<[u8; 32]> = std.clone().into_iter().collect();

        let bytes = encoded(|writer| serialize_vector(&vector, writer));
        assert_eq!(bytes, borsh::to_vec(&std).unwrap());
        assert_eq!(
            deserialize_vector::<[u8; 32], _>(&mut bytes.as_slice()).unwrap(),
            vector
        );
    }
}
