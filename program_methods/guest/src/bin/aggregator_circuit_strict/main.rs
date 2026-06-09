//! Aggregator Circuit (Strict).
//!
//! Extends the core aggregator circuit with one additional check proven inside RISC0:
//! - Each transaction's validity window contains the provided `block_id` and `timestamp`.

use std::{collections::HashSet, convert::Infallible};

use lee_core::{
    AggregatorCircuitInput, AggregatorCircuitOutput, Commitment, Nullifier, account::AccountId,
};
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

    let mut seen_nullifiers: HashSet<Nullifier> = HashSet::new();
    for output in &circuit_outputs {
        for (nullifier, _) in &output.new_nullifiers {
            assert!(
                seen_nullifiers.insert(*nullifier),
                "Duplicate nullifier across transactions in batch"
            );
        }
    }

    let mut seen_commitments: HashSet<Commitment> = HashSet::new();
    for output in &circuit_outputs {
        for commitment in &output.new_commitments {
            assert!(
                seen_commitments.insert(commitment.clone()),
                "Duplicate commitment across transactions in batch"
            );
        }
    }

    for output in &circuit_outputs {
        assert!(
            output.block_validity_window.is_valid_for(block_id),
            "Transaction block validity window does not include the block id"
        );
        assert!(
            output.timestamp_validity_window.is_valid_for(timestamp),
            "Transaction timestamp validity window does not include the timestamp"
        );
    }

    let mut seen_updated_account_ids: HashSet<AccountId> = HashSet::new();
    for output in &circuit_outputs {
        for (pre_state, post_state) in
            output.public_pre_states.iter().zip(output.public_post_states.iter())
        {
            if pre_state.account != *post_state {
                assert!(
                    seen_updated_account_ids.insert(pre_state.account_id),
                    "Public account updated by multiple transactions in batch"
                );
            }
        }
    }

    env::commit(&AggregatorCircuitOutput {
        block_id,
        timestamp,
        circuit_outputs,
    });
}
