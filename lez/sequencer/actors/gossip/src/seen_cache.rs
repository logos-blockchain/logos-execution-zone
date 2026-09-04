use std::collections::{HashSet, VecDeque};

use common::HashType;

/// Bounded, FIFO-eviction membership cache over transaction hashes.
///
/// The mempool is a plain channel with no dedup, so the gossip layer tracks
/// recently seen transactions here to avoid re-admitting duplicates that
/// arrive from multiple peers or echo back after a local publish.
///
/// TODO: expose counters to `metrics` later.
pub struct SeenCache {
    capacity: usize,
    order: VecDeque<HashType>,
    set: HashSet<HashType>,
    hits: u64,
    inserts: u64,
    evictions: u64,
}

impl SeenCache {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            order: VecDeque::new(),
            set: HashSet::new(),
            hits: 0,
            inserts: 0,
            evictions: 0,
        }
    }

    /// Records `hash` as seen. Returns `true` if it was newly inserted,
    /// `false` if already present (a hit). Evicts the oldest entry when full.
    pub fn insert(&mut self, hash: HashType) -> bool {
        if self.set.contains(&hash) {
            self.hits = self.hits.saturating_add(1);
            return false;
        }
        if self.order.len() >= self.capacity
            && let Some(oldest) = self.order.pop_front()
        {
            self.set.remove(&oldest);
            self.evictions = self.evictions.saturating_add(1);
        }
        self.set.insert(hash);
        self.order.push_back(hash);
        self.inserts = self.inserts.saturating_add(1);
        true
    }

    #[must_use]
    pub fn contains(&self, hash: &HashType) -> bool {
        self.set.contains(hash)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.order.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    #[must_use]
    pub const fn hits(&self) -> u64 {
        self.hits
    }

    #[must_use]
    pub const fn inserts(&self) -> u64 {
        self.inserts
    }

    #[must_use]
    pub const fn evictions(&self) -> u64 {
        self.evictions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u8) -> HashType {
        HashType([n; 32])
    }

    #[test]
    fn insert_reports_novelty_and_contains() {
        let mut cache = SeenCache::new(4);
        assert!(cache.insert(h(1)));
        assert!(!cache.insert(h(1)));
        assert!(cache.contains(&h(1)));
        assert!(!cache.contains(&h(2)));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.inserts(), 1);
        assert_eq!(cache.hits(), 1);
    }

    #[test]
    fn evicts_oldest_past_capacity() {
        let mut cache = SeenCache::new(2);
        assert!(cache.insert(h(1)));
        assert!(cache.insert(h(2)));
        assert!(cache.insert(h(3))); // evicts h(1)
        assert!(!cache.contains(&h(1)));
        assert!(cache.contains(&h(2)));
        assert!(cache.contains(&h(3)));
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.evictions(), 1);
    }
}
