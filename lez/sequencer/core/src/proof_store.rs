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
