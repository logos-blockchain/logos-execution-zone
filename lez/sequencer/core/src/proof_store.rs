use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex, PoisonError},
};

use lee::privacy_preserving_transaction::circuit::{Proof, ProofDigest};

#[derive(Clone)]
pub struct ProofStore(Arc<Mutex<ProofStoreInner>>);

struct ProofStoreInner {
    proofs: HashMap<ProofDigest, Vec<u8>>,
    order: VecDeque<ProofDigest>,
    total_bytes: usize,
    capacity_bytes: usize,
}

impl ProofStore {
    #[must_use]
    pub fn new(capacity_bytes: usize) -> Self {
        Self(Arc::new(Mutex::new(ProofStoreInner {
            proofs: HashMap::new(),
            order: VecDeque::new(),
            total_bytes: 0,
            capacity_bytes,
        })))
    }

    pub fn insert(&self, proof: &Proof) -> ProofDigest {
        let digest = proof.digest();
        let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if held.proofs.contains_key(&digest) {
            return digest;
        }
        let bytes = proof.clone().into_inner();
        if bytes.len() > held.capacity_bytes {
            return digest;
        }
        held.total_bytes = held.total_bytes.saturating_add(bytes.len());
        held.proofs.insert(digest, bytes);
        held.order.push_back(digest);
        while held.total_bytes > held.capacity_bytes
            && let Some(oldest) = held.order.pop_front()
            && let Some(evicted) = held.proofs.remove(&oldest)
        {
            held.total_bytes = held.total_bytes.saturating_sub(evicted.len());
        }
        digest
    }

    #[must_use]
    pub fn contains(&self, digest: &ProofDigest) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .proofs
            .contains_key(digest)
    }

    #[must_use]
    pub fn get(&self, digest: &ProofDigest) -> Option<Proof> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .proofs
            .get(digest)
            .cloned()
            .map(Proof::from_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof(fill: u8) -> Proof {
        Proof::from_inner(vec![fill; 32])
    }

    #[test]
    fn an_inserted_proof_is_returned_by_its_digest() {
        let store = ProofStore::new(64);

        let digest = store.insert(&proof(0));

        assert_eq!(digest, proof(0).digest());
        assert_eq!(store.get(&digest), Some(proof(0)));
        assert_eq!(store.get(&proof(1).digest()), None);
    }

    #[test]
    fn the_oldest_proof_is_evicted_once_the_bytes_exceed_the_capacity() {
        let store = ProofStore::new(64);

        store.insert(&proof(0));
        store.insert(&proof(1));
        store.insert(&proof(2));

        assert_eq!(store.get(&proof(0).digest()), None);
        assert_eq!(store.get(&proof(1).digest()), Some(proof(1)));
        assert_eq!(store.get(&proof(2).digest()), Some(proof(2)));
    }

    #[test]
    fn inserting_a_held_proof_again_neither_counts_its_bytes_twice_nor_refreshes_it() {
        let store = ProofStore::new(64);

        store.insert(&proof(0));
        store.insert(&proof(0));
        store.insert(&proof(1));
        assert_eq!(store.get(&proof(0).digest()), Some(proof(0)));
        assert_eq!(store.get(&proof(1).digest()), Some(proof(1)));

        store.insert(&proof(0));
        store.insert(&proof(2));
        assert_eq!(store.get(&proof(0).digest()), None);
        assert_eq!(store.get(&proof(1).digest()), Some(proof(1)));
    }

    #[test]
    fn a_proof_larger_than_the_capacity_is_not_kept_and_evicts_nothing() {
        let store = ProofStore::new(32);
        let oversized = Proof::from_inner(vec![1; 33]);

        store.insert(&proof(0));
        let digest = store.insert(&oversized);

        assert_eq!(digest, oversized.digest());
        assert_eq!(store.get(&digest), None);
        assert_eq!(store.get(&proof(0).digest()), Some(proof(0)));
    }
}
