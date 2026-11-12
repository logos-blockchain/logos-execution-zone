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
    pinned: HashMap<ProofDigest, (usize, Vec<u8>)>,
}

impl ProofStore {
    #[must_use]
    pub fn new(capacity_bytes: usize) -> Self {
        Self(Arc::new(Mutex::new(ProofStoreInner {
            proofs: HashMap::new(),
            order: VecDeque::new(),
            total_bytes: 0,
            capacity_bytes,
            pinned: HashMap::new(),
        })))
    }

    pub fn insert(&self, proof: &Proof) -> ProofDigest {
        let digest = proof.digest();
        let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if !held.proofs.contains_key(&digest) && !held.pinned.contains_key(&digest) {
            held.admit(digest, proof.clone().into_inner());
        }
        digest
    }

    pub fn pin(&self, proof: &Proof) {
        let digest = proof.digest();
        let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((pins, _)) = held.pinned.get_mut(&digest) {
            *pins = pins.saturating_add(1);
            return;
        }
        let bytes = held.proofs.remove(&digest).map_or_else(
            || proof.clone().into_inner(),
            |bytes| {
                held.order.retain(|queued| *queued != digest);
                held.total_bytes = held.total_bytes.saturating_sub(bytes.len());
                bytes
            },
        );
        held.pinned.insert(digest, (1, bytes));
    }

    pub fn unpin(&self, digest: &ProofDigest) {
        let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let Some((pins, _)) = held.pinned.get_mut(digest) else {
            return;
        };
        *pins = pins.saturating_sub(1);
        if *pins == 0
            && let Some((_, bytes)) = held.pinned.remove(digest)
        {
            held.admit(*digest, bytes);
        }
    }

    #[must_use]
    pub fn contains(&self, digest: &ProofDigest) -> bool {
        let held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        held.proofs.contains_key(digest) || held.pinned.contains_key(digest)
    }

    #[must_use]
    pub fn get(&self, digest: &ProofDigest) -> Option<Proof> {
        let held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        held.proofs
            .get(digest)
            .or_else(|| held.pinned.get(digest).map(|(_, bytes)| bytes))
            .cloned()
            .map(Proof::from_inner)
    }
}

impl ProofStoreInner {
    fn admit(&mut self, digest: ProofDigest, bytes: Vec<u8>) {
        if bytes.len() > self.capacity_bytes {
            return;
        }
        self.total_bytes = self.total_bytes.saturating_add(bytes.len());
        self.proofs.insert(digest, bytes);
        self.order.push_back(digest);
        while self.total_bytes > self.capacity_bytes
            && let Some(oldest) = self.order.pop_front()
            && let Some(evicted) = self.proofs.remove(&oldest)
        {
            self.total_bytes = self.total_bytes.saturating_sub(evicted.len());
        }
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
    fn inserting_a_held_or_pinned_proof_again_neither_counts_its_bytes_twice_nor_refreshes_it() {
        let store = ProofStore::new(64);

        store.pin(&proof(0));
        store.insert(&proof(1));
        store.insert(&proof(1));
        store.insert(&proof(0));
        store.insert(&proof(2));
        assert_eq!(store.get(&proof(0).digest()), Some(proof(0)));
        assert_eq!(store.get(&proof(1).digest()), Some(proof(1)));
        assert_eq!(store.get(&proof(2).digest()), Some(proof(2)));

        store.insert(&proof(1));
        store.insert(&proof(3));
        assert_eq!(store.get(&proof(1).digest()), None);
        assert_eq!(store.get(&proof(2).digest()), Some(proof(2)));
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

    #[test]
    fn a_held_proof_pinned_twice_stays_pinned_after_one_unpin_and_becomes_the_newest_evictable_entry_after_the_second()
     {
        let store = ProofStore::new(64);

        store.insert(&proof(1));
        store.insert(&proof(0));
        store.pin(&proof(0));
        store.pin(&proof(0));
        store.unpin(&proof(0).digest());
        store.insert(&proof(2));
        assert_eq!(store.get(&proof(1).digest()), Some(proof(1)));
        store.insert(&proof(3));
        assert_eq!(store.get(&proof(1).digest()), None);
        assert_eq!(store.get(&proof(0).digest()), Some(proof(0)));

        store.unpin(&proof(0).digest());
        assert_eq!(store.get(&proof(2).digest()), None);
        assert_eq!(store.get(&proof(0).digest()), Some(proof(0)));
        assert_eq!(store.get(&proof(3).digest()), Some(proof(3)));
        store.insert(&proof(4));
        store.insert(&proof(5));
        assert_eq!(store.get(&proof(0).digest()), None);
    }
}
