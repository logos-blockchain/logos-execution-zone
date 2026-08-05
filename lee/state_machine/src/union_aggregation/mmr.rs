//! Merkle Mountain Accumulator mirroring risc0-zkvm's private implementation.
//!
//! risc0-zkvm 3.0.5 ships `MerkleMountainAccumulator` + `UnionPeak`/`GuestPeak` in
//! `src/mmr.rs` / `src/host/server/prove/union_peak.rs`, but keeps them crate-private,
//! so they are re-implemented here with identical semantics (checked against the 3.0.5
//! sources; 3.0.6 is byte-identical). The accumulator fixes the *shape* of the union
//! tree, which is consensus-critical: the prover folds receipts and the verifier folds
//! assumption digests through the same structure, and the two must agree bit for bit.
//!
//! Shape, for the record: `insert` merges equal-height peaks from the back of the peak
//! list, so after inserting `n` leaves the peaks are balanced binary trees over
//! consecutive leaf chunks whose sizes are the powers of two of `n`'s binary
//! decomposition, most significant first. `root` then folds the peaks front to back
//! (tallest into smallest). Within every merge the two children are ordered by
//! `risc0_zkvm::Digest`'s derived `Ord` (lexicographic over its `[u32; 8]` words, which
//! hold little-endian-loaded bytes; the lesser is `left`), exactly as the recursion
//! circuit's union program does — so only the pairing shape matters, not the operand
//! order of a merge.

use std::collections::VecDeque;

use risc0_zkvm::{ALLOWED_CONTROL_ROOT, Assumption, UnionClaim, sha::Digestible as _};

use crate::error::LeeError;

/// One peak of the accumulator: a perfect binary tree over `2^height` leaves.
pub trait Peak {
    type Item;

    fn new(item: Self::Item) -> Self;
    fn new_with_height(item: Self::Item, height: u32) -> Self;
    fn height(&self) -> u32;
    fn item(self) -> Self::Item;

    /// Merges `b` into `a`, leaving the merged node in `a`.
    fn merge_item(a: &mut Self::Item, b: Self::Item) -> Result<(), LeeError>;

    /// Merges two peaks of equal height into one peak of height + 1.
    fn merge(a: Self, b: Self) -> Result<Self, LeeError>
    where
        Self: Sized,
    {
        crate::ensure!(
            a.height() == b.height(),
            LeeError::UnionAggregation("merge attempted on peaks of different heights".into())
        );
        let height = a.height();
        let mut item = a.item();
        Self::merge_item(&mut item, b.item())?;
        Ok(Self::new_with_height(
            item,
            height
                .checked_add(1)
                .ok_or_else(|| LeeError::UnionAggregation("peak height overflow".into()))?,
        ))
    }
}

/// Append-only accumulator folding leaves into a single root.
///
/// Mirror of risc0-zkvm 3.0.5 `MerkleMountainAccumulator`.
pub struct MerkleMountainAccumulator<T: Peak> {
    peaks: VecDeque<T>,
}

impl<T: Peak> MerkleMountainAccumulator<T> {
    pub const fn new() -> Self {
        Self {
            peaks: VecDeque::new(),
        }
    }

    /// Appends one leaf, merging equal-height peaks from the back of the peak list.
    pub fn insert(&mut self, item: T::Item) -> Result<(), LeeError> {
        let mut to_add = T::new(item);
        while let Some(back) = self.peaks.back() {
            if back.height() != to_add.height() {
                break;
            }
            let to_merge = self
                .peaks
                .pop_back()
                .expect("peaks.back() was Some, so pop_back() must succeed");
            to_add = T::merge(to_add, to_merge)?;
        }
        self.peaks.push_back(to_add);
        Ok(())
    }

    /// Folds all peaks front to back into the root item.
    pub fn root(mut self) -> Result<T::Item, LeeError> {
        let Some(front) = self.peaks.pop_front() else {
            return Err(LeeError::UnionAggregation(
                "cannot compute the root of an empty accumulator".into(),
            ));
        };
        let mut item = front.item();
        for peak in self.peaks {
            T::merge_item(&mut item, peak.item())?;
        }
        Ok(item)
    }
}

/// Digest-only peak: folds [`Assumption`]s the way the union program folds receipts.
///
/// Mirror of risc0-zkvm 3.0.5 `GuestPeak`. This is what lets a verifier recompute the
/// union-tree root natively, in microseconds, from public data alone.
pub struct AssumptionPeak {
    item: Assumption,
    height: u32,
}

impl Peak for AssumptionPeak {
    type Item = Assumption;

    fn new(item: Self::Item) -> Self {
        Self::new_with_height(item, 0)
    }

    fn new_with_height(item: Self::Item, height: u32) -> Self {
        Self { item, height }
    }

    fn height(&self) -> u32 {
        self.height
    }

    fn item(self) -> Self::Item {
        self.item
    }

    fn merge_item(a: &mut Self::Item, b: Self::Item) -> Result<(), LeeError> {
        let a_digest = a.digest();
        let b_digest = b.digest();
        // The union program orders children by Digest's derived Ord (lexicographic
        // over the [u32; 8] words), lesser first — mirror it exactly.
        let (left, right) = if a_digest <= b_digest {
            (a_digest, b_digest)
        } else {
            (b_digest, a_digest)
        };
        *a = Assumption {
            claim: UnionClaim { left, right }.digest(),
            control_root: ALLOWED_CONTROL_ROOT,
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use risc0_zkvm::Digest;

    use super::*;

    fn synthetic_assumption(i: u32) -> Assumption {
        let mut words = [0_u32; 8];
        words[0] = i;
        words[7] = i.wrapping_mul(0x9E37_79B9);
        Assumption {
            claim: Digest::from(words),
            control_root: ALLOWED_CONTROL_ROOT,
        }
    }

    /// Reference fold: the explicit chunk decomposition the parallel prover uses.
    ///
    /// Splits the leaves into consecutive chunks sized by the powers of two of
    /// `n`'s binary decomposition (most significant first), reduces each chunk
    /// level-synchronously by adjacent pairs, then folds chunk roots left to right.
    fn reference_root(leaves: &[Assumption]) -> Assumption {
        let mut chunk_roots = Vec::new();
        let mut rest = leaves;
        while !rest.is_empty() {
            let size = 1_usize << rest.len().ilog2();
            let (chunk, remainder) = rest.split_at(size);
            rest = remainder;

            let mut level: Vec<Assumption> = chunk.to_vec();
            while level.len() > 1 {
                level = level
                    .chunks_exact(2)
                    .map(|pair| {
                        let [a, b] = pair else {
                            unreachable!("chunks_exact(2) yields two-element slices")
                        };
                        let mut merged = a.clone();
                        AssumptionPeak::merge_item(&mut merged, b.clone())
                            .expect("digest merge cannot fail");
                        merged
                    })
                    .collect();
            }
            chunk_roots.push(level.remove(0));
        }

        let mut root = chunk_roots.remove(0);
        for next in chunk_roots {
            AssumptionPeak::merge_item(&mut root, next).expect("digest merge cannot fail");
        }
        root
    }

    /// The accumulator must produce the same root as the explicit chunk
    /// decomposition for every n — this is the shape equality the parallel
    /// prover schedule relies on.
    #[test]
    fn accumulator_root_matches_reference_fold() {
        for n in 1..=17_u32 {
            let leaves: Vec<Assumption> = (0..n).map(synthetic_assumption).collect();

            let mut mmr = MerkleMountainAccumulator::<AssumptionPeak>::new();
            for leaf in &leaves {
                mmr.insert(leaf.clone()).expect("insert cannot fail");
            }
            let root = mmr.root().expect("non-empty accumulator has a root");

            assert_eq!(root, reference_root(&leaves), "shape mismatch at n={n}");
        }
    }

    /// Merging is order-independent within a pair (children are sorted by digest),
    /// mirroring the union program's behaviour.
    #[test]
    fn merge_item_is_commutative() {
        let a = synthetic_assumption(1);
        let b = synthetic_assumption(2);

        let mut ab = a.clone();
        AssumptionPeak::merge_item(&mut ab, b.clone()).expect("digest merge cannot fail");
        let mut ba = b;
        AssumptionPeak::merge_item(&mut ba, a).expect("digest merge cannot fail");

        assert_eq!(ab, ba);
    }

    #[test]
    fn empty_accumulator_has_no_root() {
        let mmr = MerkleMountainAccumulator::<AssumptionPeak>::new();
        assert!(mmr.root().is_err());
    }
}
