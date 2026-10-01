//! Private transactions that failed settlement, refused at intake for a while.
//!
//! A private transaction that fails settlement is dropped without paying a fee or spending its
//! nullifiers, so the identical transaction stays valid to resubmit, and every attempt costs a
//! proof check plus its deferred applies. Remembering it closes that loop until private
//! transactions pay fees. Entries expire, since a failure can be temporary: a validity window not
//! yet open, or a public balance topped up since.

use std::collections::{HashMap, VecDeque};

use common::HashType;

/// Blocks a failed private transaction stays refused for.
const REFUSAL_BLOCKS: u64 = 100;

/// Hashes remembered at once; the oldest is forgotten first.
const MAX_REFUSED: usize = 10_000;

#[derive(Debug, Default)]
pub struct RefusedTransactions {
    failed_at: HashMap<HashType, u64>,
    order: VecDeque<HashType>,
}

impl RefusedTransactions {
    /// Records that the transaction `hash` failed settlement while building `block_id`.
    pub fn record(&mut self, hash: HashType, block_id: u64) {
        if self.failed_at.insert(hash, block_id).is_none() {
            self.order.push_back(hash);
        }
        while self.order.len() > MAX_REFUSED {
            if let Some(oldest) = self.order.pop_front() {
                self.failed_at.remove(&oldest);
            }
        }
    }

    /// Whether the transaction `hash` is still refused when building `block_id`.
    #[must_use]
    pub fn refuses(&self, hash: &HashType, block_id: u64) -> bool {
        self.failed_at
            .get(hash)
            .is_some_and(|&failed| block_id < failed.saturating_add(REFUSAL_BLOCKS))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(n: u8) -> HashType {
        HashType([n; 32])
    }

    #[test]
    fn a_recorded_failure_is_refused_until_it_expires() {
        let mut refused = RefusedTransactions::default();
        refused.record(hash(1), 10);

        assert!(refused.refuses(&hash(1), 10));
        assert!(refused.refuses(&hash(1), 10 + REFUSAL_BLOCKS - 1));
        assert!(!refused.refuses(&hash(1), 10 + REFUSAL_BLOCKS));
        assert!(!refused.refuses(&hash(2), 10));
    }

    #[test]
    fn a_repeated_failure_restarts_the_refusal() {
        let mut refused = RefusedTransactions::default();
        refused.record(hash(1), 10);
        refused.record(hash(1), 50);

        assert!(refused.refuses(&hash(1), 50 + REFUSAL_BLOCKS - 1));
    }

    #[test]
    fn the_oldest_failure_is_forgotten_past_the_cap() {
        let mut refused = RefusedTransactions::default();
        for n in 0..=MAX_REFUSED {
            let mut bytes = [0; 32];
            bytes[..8].copy_from_slice(&u64::try_from(n).unwrap().to_le_bytes());
            refused.record(HashType(bytes), 1);
        }

        assert!(!refused.refuses(&HashType([0; 32]), 1));
        assert_eq!(refused.order.len(), MAX_REFUSED);
        assert_eq!(refused.failed_at.len(), MAX_REFUSED);
    }
}
