//! Aggregator Circuit.
//!
//! Verifies N privacy-preserving circuit proofs and enforces:
//! - Intra-batch uniqueness of nullifiers and commitments.
//! - No public account is updated by more than one transaction in the batch.
//!
//! The full `PrivacyPreservingCircuitOutput` for each transaction is committed to the
//! journal so observers can perform state-dependent checks independently.

use std::convert::Infallible;

use lee_core::{AggregatorCircuitInput, AggregatorCircuitOutput, Commitment, Nullifier, account::AccountId};
use risc0_zkvm::{guest::env, serde::to_vec};

fn main() {
    let AggregatorCircuitInput {
        privacy_preserving_circuit_id,
        block_id,
        timestamp,
        circuit_outputs,
    } = env::read();

    for output in &circuit_outputs {
        let output_words =
            to_vec(output).expect("PrivacyPreservingCircuitOutput serialization should not fail");
        env::verify(privacy_preserving_circuit_id, &output_words)
            .unwrap_or_else(|_: Infallible| unreachable!("Infallible error is never constructed"));
    }

    // Linear-scan dedup: batches are small (n is bounded), so a `Vec` + `contains` check
    // avoids the per-element hashing cost of `HashSet` in the zkVM.
    let mut seen_nullifiers: Vec<Nullifier> = Vec::new();
    for output in &circuit_outputs {
        for (nullifier, _) in &output.new_nullifiers {
            assert!(
                !seen_nullifiers.contains(nullifier),
                "Duplicate nullifier across transactions in batch"
            );
            seen_nullifiers.push(*nullifier);
        }
    }

    let mut seen_commitments: Vec<Commitment> = Vec::new();
    for output in &circuit_outputs {
        for commitment in &output.new_commitments {
            assert!(
                !seen_commitments.contains(commitment),
                "Duplicate commitment across transactions in batch"
            );
            seen_commitments.push(commitment.clone());
        }
    }

    let mut seen_updated_account_ids: Vec<AccountId> = Vec::new();
    for output in &circuit_outputs {
        for (pre_state, post_state) in
            output.public_pre_states.iter().zip(output.public_post_states.iter())
        {
            if pre_state.account != *post_state {
                assert!(
                    !seen_updated_account_ids.contains(&pre_state.account_id),
                    "Public account updated by multiple transactions in batch"
                );
                seen_updated_account_ids.push(pre_state.account_id);
            }
        }
    }

    env::commit(&AggregatorCircuitOutput {
        block_id,
        timestamp,
        circuit_outputs,
    });
}
