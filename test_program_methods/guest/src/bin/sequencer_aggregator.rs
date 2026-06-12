use std::convert::Infallible;

use lee_core::{
    BlockId, Commitment, Nullifier, SequencerAggregatorOutput, Timestamp,
    account::{AccountId, AccountWithMetadata},
    message::Message,
};
use risc0_zkvm::{guest::env, serde::to_vec};

/// Sequencer aggregator circuit.
///
/// The host writes:
///   1. The PPE circuit image ID (`[u32; 8]`)
///   2. `block_id: BlockId`
///   3. `timestamp: Timestamp`
///   4. `Vec<Message>` — the `lee_core`-resident mirror of each transaction's `Message`
///   5. `Vec<Vec<AccountWithMetadata>>` — `public_pre_states` for each message's
///      `public_account_ids`, in the same order
///
/// It also adds each transaction's PPE receipt as an assumption before running this guest.
///
/// Checks:
///   1. Nullifiers and commitments are unique across all messages in the batch.
///   2. Each public account is updated by at most one transaction in the batch.
///   3. `block_id`/`timestamp` fall within each message's validity window.
///   4. Each message's PPE proof verifies (`Message::into_circuit_output` + `env::verify`).
///      The host filters out transactions that would fail any of these checks before
///      building this input, so failures here should never occur.
///
/// Journal: [`SequencerAggregatorOutput`] — `block_id`, `timestamp`, and the verified
/// messages.
fn main() {
    let ppe_image_id: [u32; 8] = env::read();
    let block_id: BlockId = env::read();
    let timestamp: Timestamp = env::read();
    let messages: Vec<Message> = env::read();
    let public_pre_states: Vec<Vec<AccountWithMetadata>> = env::read();

    assert_eq!(
        messages.len(),
        public_pre_states.len(),
        "sequencer_aggregator: messages and public_pre_states length mismatch"
    );

    // 1. Nullifiers and commitments are unique across all messages in the batch.
    let mut seen_nullifiers: Vec<Nullifier> = Vec::new();
    let mut seen_commitments: Vec<Commitment> = Vec::new();
    for message in &messages {
        for (nullifier, _) in &message.new_nullifiers {
            assert!(
                !seen_nullifiers.contains(nullifier),
                "Duplicate nullifier across transactions in batch"
            );
            seen_nullifiers.push(*nullifier);
        }
        for commitment in &message.new_commitments {
            assert!(
                !seen_commitments.contains(commitment),
                "Duplicate commitment across transactions in batch"
            );
            seen_commitments.push(commitment.clone());
        }
    }

    // 2. Each public account is updated by at most one transaction in the batch.
    let mut seen_updated_account_ids: Vec<AccountId> = Vec::new();
    for (message, pre_states) in messages.iter().zip(&public_pre_states) {
        for (pre_state, post_state) in pre_states.iter().zip(&message.public_post_states) {
            if pre_state.account != *post_state {
                assert!(
                    !seen_updated_account_ids.contains(&pre_state.account_id),
                    "Public account updated by multiple transactions in batch"
                );
                seen_updated_account_ids.push(pre_state.account_id);
            }
        }
    }

    // 3. `block_id`/`timestamp` fall within each message's validity window.
    for message in &messages {
        assert!(
            message.block_validity_window.is_valid_for(block_id),
            "Transaction block validity window does not include the block id"
        );
        assert!(
            message.timestamp_validity_window.is_valid_for(timestamp),
            "Transaction timestamp validity window does not include the timestamp"
        );
    }

    let output = SequencerAggregatorOutput {
        block_id,
        timestamp,
        messages,
    };
    env::commit(&output);

    // 4. Each message's PPE proof verifies.
    for (message, pre_states) in output.messages.into_iter().zip(public_pre_states) {
        let circuit_output = message.into_circuit_output(pre_states);
        let output_words = to_vec(&circuit_output)
            .expect("PrivacyPreservingCircuitOutput serialization should not fail");
        env::verify(ppe_image_id, &output_words)
            .unwrap_or_else(|_: Infallible| unreachable!("Infallible error is never constructed"));
    }
}
