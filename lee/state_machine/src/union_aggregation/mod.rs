//! Union-based aggregation of privacy-preserving-execution (PPE) proofs.
//!
//! Alternative to the [`crate::sequencer_aggregator`] guest circuit, kept side by side
//! for benchmarking. Instead of re-verifying every PPE receipt inside a zkVM guest
//! (paying guest execution, segment proving, lift/join and one resolve per assumption),
//! the `n` succinct PPE receipts are merged pairwise with the recursion circuit's
//! `union` program: `n - 1` fixed-size recursion proofs produce a single succinct root
//! receipt of constant size, with no guest execution at all.
//!
//! The cross-transaction checks the aggregation guest used to make (nullifier and
//! commitment uniqueness across the batch, at most one update per public account,
//! validity-window containment) operate purely on public data, so they move to native
//! verifier code: [`verify_union_aggregation`] re-executes them and then checks the root
//! receipt against a natively recomputed union-tree digest. Verification needs only
//! public data plus the root receipt — no prover state and no `prove` feature — so it
//! can be outsourced to (i.e. re-executed by) any node validating a block.
//!
//! Binding chain: journal bytes ([`lee_core::PrivacyPreservingCircuitOutput::to_bytes`])
//! → leaf [`risc0_zkvm::ReceiptClaim`] (PPE image id + journal) → leaf
//! [`risc0_zkvm::Assumption`] (claim digest + recursion control root) → union-tree root
//! digest → one STARK verification of the root receipt.

#[cfg(feature = "prove")]
pub use prover::{UnionAggregation, aggregate_union, aggregate_union_parallel};
pub use verifier::{check_batch_constraints, expected_root_claim_digest, verify_union_aggregation};

mod mmr;
#[cfg(feature = "prove")]
mod prover;
mod verifier;
