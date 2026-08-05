//! Native, outsourceable verification of a union-aggregated PPE proof batch.
//!
//! Everything in this module operates on public data (the per-transaction
//! [`PrivacyPreservingCircuitOutput`]s, the block id and timestamp) plus the single
//! root receipt. It needs no prover state and no `prove` feature, so any node — or any
//! third party a node outsources validation to — can run it independently.
//!
//! Caller contract, security-critical: each output's `public_pre_states` MUST be
//! resolved from the verifier's own chain state (and its `is_authorized` flags from
//! signature-verified signers), exactly as `circuit_output_for_message` does for the
//! per-transaction path — never taken from prover-supplied storage. That local
//! reconstruction is what binds the aggregated proofs to the verifier's state: a proof
//! generated against different pre-states yields a different journal, hence a different
//! leaf digest, hence a root mismatch.

use lee_core::{
    BlockId, Commitment, Nullifier, PrivacyPreservingCircuitOutput, Timestamp, account::AccountId,
};
use risc0_zkvm::{
    ALLOWED_CONTROL_ROOT, Assumption, Digest, ReceiptClaim, SuccinctReceipt, Unknown,
    sha::Digestible as _,
};

use super::mmr::{AssumptionPeak, MerkleMountainAccumulator};
use crate::{PRIVACY_PRESERVING_CIRCUIT_ID, error::LeeError};

/// Re-executes, natively, the batch-level checks the `sequencer_aggregator` guest makes
/// (its checks 1–3), assertion for assertion:
///
/// 1. Nullifiers and commitments are unique across all outputs in the batch.
/// 2. Each public account is updated by at most one transaction in the batch.
/// 3. `block_id`/`timestamp` fall within each output's validity window.
///
/// These predicates range over public data already stored in the block, so proving them
/// in-circuit added no assurance: every verifier recomputes them here identically. The
/// per-proof `env::verify` the guest performed (its check 4) is replaced by the union
/// root check in [`verify_union_aggregation`].
///
/// State-dependent checks (global nullifier/commitment set membership, nonces,
/// signatures) are unchanged from the per-transaction design and stay in
/// [`crate::ValidatedStateDiff`].
pub fn check_batch_constraints(
    outputs: &[PrivacyPreservingCircuitOutput],
    block_id: BlockId,
    timestamp: Timestamp,
) -> Result<(), LeeError> {
    // 1. Nullifiers and commitments are unique across all outputs in the batch.
    let mut seen_nullifiers: Vec<Nullifier> = Vec::new();
    let mut seen_commitments: Vec<Commitment> = Vec::new();
    for output in outputs {
        for (nullifier, _) in &output.new_nullifiers {
            crate::ensure!(
                !seen_nullifiers.contains(nullifier),
                LeeError::UnionAggregation(
                    "duplicate nullifier across transactions in batch".into()
                )
            );
            seen_nullifiers.push(*nullifier);
        }
        for commitment in &output.new_commitments {
            crate::ensure!(
                !seen_commitments.contains(commitment),
                LeeError::UnionAggregation(
                    "duplicate commitment across transactions in batch".into()
                )
            );
            seen_commitments.push(commitment.clone());
        }
    }

    // 2. Each public account is updated by at most one transaction in the batch.
    let mut seen_updated_account_ids: Vec<AccountId> = Vec::new();
    for output in outputs {
        crate::ensure!(
            output.public_pre_states.len() == output.public_post_states.len(),
            LeeError::UnionAggregation(
                "public pre-state and post-state count mismatch in output".into()
            )
        );
        for (pre_state, post_state) in output
            .public_pre_states
            .iter()
            .zip(&output.public_post_states)
        {
            if pre_state.account != *post_state {
                crate::ensure!(
                    !seen_updated_account_ids.contains(&pre_state.account_id),
                    LeeError::UnionAggregation(
                        "public account updated by multiple transactions in batch".into()
                    )
                );
                seen_updated_account_ids.push(pre_state.account_id);
            }
        }
    }

    // 3. `block_id`/`timestamp` fall within each output's validity window.
    for output in outputs {
        crate::ensure!(
            output.block_validity_window.is_valid_for(block_id),
            LeeError::UnionAggregation(
                "transaction block validity window does not include the block id".into()
            )
        );
        crate::ensure!(
            output.timestamp_validity_window.is_valid_for(timestamp),
            LeeError::UnionAggregation(
                "transaction timestamp validity window does not include the timestamp".into()
            )
        );
    }

    Ok(())
}

/// Natively recomputes the claim digest the union root receipt must carry for this
/// exact ordered batch of PPE outputs.
///
/// Each leaf is the [`Assumption`] the union program derives from a PPE succinct
/// receipt: the digest of [`ReceiptClaim::ok`] over the pinned PPE image id and the
/// output's canonical journal bytes, together with the recursion control root. Leaves
/// are folded through the same Merkle mountain accumulator shape the prover uses, so
/// the resulting digest matches the root receipt's claim digest if and only if the
/// prover unioned receipts for precisely these journals — bound as an exact multiset
/// and tree pairing, invariant only under swapping the two children of a node (the
/// union program orders each node's children by digest). Batch semantics are
/// order-independent, so sibling transpositions are harmless; nothing may ever rely
/// on intra-pair order being bound.
pub fn expected_root_claim_digest(
    outputs: &[PrivacyPreservingCircuitOutput],
) -> Result<Digest, LeeError> {
    let mut mmr = MerkleMountainAccumulator::<AssumptionPeak>::new();
    for output in outputs {
        let claim = ReceiptClaim::ok(PRIVACY_PRESERVING_CIRCUIT_ID, output.to_bytes());
        mmr.insert(Assumption {
            claim: claim.digest(),
            control_root: ALLOWED_CONTROL_ROOT,
        })?;
    }
    Ok(mmr.root()?.claim)
}

/// Verifies a union-aggregated batch of PPE proofs from public data only.
///
/// Checks, in order:
/// 1. the batch constraints ([`check_batch_constraints`]);
/// 2. that the root receipt's claim digest equals the natively recomputed union-tree
///    root for `outputs` ([`expected_root_claim_digest`]);
/// 3. the root receipt's STARK seal ([`SuccinctReceipt::verify_integrity`]).
///
/// Together, 2 + 3 prove that every `outputs[i]` is the journal of a valid execution of
/// the privacy-preserving circuit: the binding chain is journal bytes → leaf claim
/// (image id + journal digest) → leaf assumption (claim digest + control root) →
/// union-tree root → STARK. For a batch of one, the "root" is simply the transaction's
/// own succinct receipt with its claim pruned ([`SuccinctReceipt::into_unknown`]) and
/// the same equality holds without any union step.
///
/// This function is intentionally free of any dependency on prover or chain state so
/// that block validation remains outsourceable; global uniqueness checks against the
/// node's own nullifier/commitment sets remain the caller's responsibility, exactly as
/// in the per-transaction design.
pub fn verify_union_aggregation(
    outputs: &[PrivacyPreservingCircuitOutput],
    block_id: BlockId,
    timestamp: Timestamp,
    root: &SuccinctReceipt<Unknown>,
) -> Result<(), LeeError> {
    crate::ensure!(
        !outputs.is_empty(),
        LeeError::UnionAggregation("cannot verify an empty batch".into())
    );

    check_batch_constraints(outputs, block_id, timestamp)?;

    let expected = expected_root_claim_digest(outputs)?;
    crate::ensure!(
        root.claim.digest() == expected,
        LeeError::InvalidPrivacyPreservingProof
    );

    root.verify_integrity()
        .map_err(|_verification_error| LeeError::InvalidPrivacyPreservingProof)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    //! Guest-vs-native equivalence: every batch the `sequencer_aggregator` guest
    //! rejects through its checks 1–3 must be rejected by [`check_batch_constraints`],
    //! and a valid batch must be accepted by both. The guest runs its checks before any
    //! `env::verify`, so the tampered cases execute (not prove) the real guest binary
    //! with no assumptions attached.

    use lee_core::{
        account::Nonce,
        message::{EncryptedAccountData, Message},
    };
    use risc0_zkvm::{ExecutorEnv, InnerReceipt, Receipt, default_executor};
    use test_program_methods::{PpeFixture, SEQUENCER_AGGREGATOR_ELF};

    use super::*;

    /// Block id the checked-in fixtures were generated for.
    const FIXTURE_BLOCK_ID: BlockId = 1;
    /// Timestamp the checked-in fixtures were generated for.
    const FIXTURE_TIMESTAMP: Timestamp = 1_700_000_000;

    /// Loads the PPE fixtures and decodes their circuit outputs; empty when the
    /// fixture file is absent (callers skip gracefully, matching the other
    /// fixture-based tests).
    fn load_fixture_outputs() -> (Vec<PpeFixture>, Vec<PrivacyPreservingCircuitOutput>) {
        let path = std::env::var("PPE_FIXTURES").unwrap_or_else(|_| "ppe_fixtures.bin".to_owned());
        let fixtures = PpeFixture::load_bundle(&path);
        let outputs = fixtures
            .iter()
            .map(|fixture| {
                let words: &[u32] = bytemuck::cast_slice(&fixture.output_bytes);
                risc0_zkvm::serde::from_slice(words).expect("fixture output_bytes invalid")
            })
            .collect();
        (fixtures, outputs)
    }

    /// Rebuilds the guest-resident message mirror for a circuit output.
    ///
    /// Nonces and view tags are not part of [`PrivacyPreservingCircuitOutput`] and play
    /// no role in the guest's batch checks, so they are filled with placeholders.
    fn message_from_output(output: &PrivacyPreservingCircuitOutput) -> Message {
        Message {
            public_account_ids: output
                .public_pre_states
                .iter()
                .map(|pre_state| pre_state.account_id)
                .collect(),
            nonces: output
                .public_pre_states
                .iter()
                .map(|_pre_state| Nonce(0))
                .collect(),
            public_post_states: output.public_post_states.clone(),
            encrypted_private_post_states: output
                .ciphertexts
                .iter()
                .map(|ciphertext| EncryptedAccountData {
                    ciphertext: ciphertext.clone(),
                    view_tag: 0,
                })
                .collect(),
            new_commitments: output.new_commitments.clone(),
            new_nullifiers: output.new_nullifiers.clone(),
            block_validity_window: output.block_validity_window,
            timestamp_validity_window: output.timestamp_validity_window,
        }
    }

    /// Executes (without proving) the `sequencer_aggregator` guest over `outputs`,
    /// attaching each fixture receipt as an assumption when provided. Returns the
    /// guest's failure message when it rejects the batch.
    fn run_guest(
        outputs: &[PrivacyPreservingCircuitOutput],
        fixtures: &[PpeFixture],
    ) -> Result<(), String> {
        let messages: Vec<Message> = outputs.iter().map(message_from_output).collect();
        let pre_states: Vec<Vec<lee_core::account::AccountWithMetadata>> = outputs
            .iter()
            .map(|output| output.public_pre_states.clone())
            .collect();

        let mut env_builder = ExecutorEnv::builder();
        for (fixture, output) in fixtures.iter().zip(outputs) {
            let inner: InnerReceipt = borsh::from_slice(&fixture.proof_bytes)
                .expect("fixture proof_bytes is not a valid InnerReceipt");
            env_builder.add_assumption(Receipt::new(inner, output.to_bytes()));
        }
        env_builder
            .write(&PRIVACY_PRESERVING_CIRCUIT_ID)
            .expect("write image id");
        env_builder
            .write(&FIXTURE_BLOCK_ID)
            .expect("write block id");
        env_builder
            .write(&FIXTURE_TIMESTAMP)
            .expect("write timestamp");
        env_builder.write(&messages).expect("write messages");
        env_builder.write(&pre_states).expect("write pre-states");
        let env = env_builder.build().expect("build executor env");

        match default_executor().execute(env, SEQUENCER_AGGREGATOR_ELF) {
            Ok(_session) => Ok(()),
            Err(error) => Err(format!("{error:#}")),
        }
    }

    /// Asserts that the guest and the native checks agree on rejecting `outputs`.
    ///
    /// The guest run attaches no assumptions, so it would eventually fail at its
    /// `env::verify` step (check 4) for *any* batch; requiring `expected_guest_message`
    /// (the specific check 1-3 assertion text) in the failure proves the rejection came
    /// from the batch check under test, not from the missing assumptions.
    fn assert_rejected_by_both(
        outputs: &[PrivacyPreservingCircuitOutput],
        case: &str,
        expected_guest_message: &str,
    ) {
        let guest_error = run_guest(outputs, &[])
            .expect_err(&format!("guest accepted a batch it must reject: {case}"));
        assert!(
            guest_error.contains(expected_guest_message),
            "guest rejected the batch ({case}) but not via the expected check: \
             wanted {expected_guest_message:?} in {guest_error:?}"
        );
        assert!(
            check_batch_constraints(outputs, FIXTURE_BLOCK_ID, FIXTURE_TIMESTAMP).is_err(),
            "native checks accepted a batch they must reject: {case}"
        );
    }

    /// A clean two-transaction fixture batch is accepted by the guest (with its real
    /// receipts as assumptions) and by the native checks alike.
    #[test]
    fn valid_batch_accepted_by_guest_and_native() {
        let (fixtures, outputs) = load_fixture_outputs();
        if outputs.len() < 2 {
            return; // fixtures absent - load_bundle printed a skip notice
        }
        let outputs = &outputs[..2];
        let fixtures = &fixtures[..2];

        run_guest(outputs, fixtures).expect("guest rejected a valid batch");
        assert!(
            check_batch_constraints(outputs, FIXTURE_BLOCK_ID, FIXTURE_TIMESTAMP).is_ok(),
            "native checks rejected a valid batch"
        );
    }

    /// A nullifier reused across two transactions is rejected by both paths.
    #[test]
    fn duplicate_nullifier_rejected_by_guest_and_native() {
        let (_fixtures, mut outputs) = load_fixture_outputs();
        if outputs.len() < 2 {
            return;
        }
        outputs.truncate(2);
        let stolen = outputs[0].new_nullifiers[0];
        outputs[1].new_nullifiers[0] = stolen;

        assert_rejected_by_both(
            &outputs,
            "duplicate nullifier across transactions",
            "Duplicate nullifier across transactions in batch",
        );
    }

    /// A commitment reused across two transactions is rejected by both paths.
    #[test]
    fn duplicate_commitment_rejected_by_guest_and_native() {
        let (_fixtures, mut outputs) = load_fixture_outputs();
        if outputs.len() < 2 {
            return;
        }
        outputs.truncate(2);
        let stolen = outputs[0].new_commitments[0].clone();
        outputs[1].new_commitments[0] = stolen;

        assert_rejected_by_both(
            &outputs,
            "duplicate commitment across transactions",
            "Duplicate commitment across transactions in batch",
        );
    }

    /// Two transactions updating the same public account are rejected by both paths.
    #[test]
    fn double_public_account_update_rejected_by_guest_and_native() {
        let (_fixtures, mut outputs) = load_fixture_outputs();
        if outputs.len() < 2 {
            return;
        }
        outputs.truncate(2);
        // Each fixture transaction updates its (single) public sender account; aliasing
        // the second sender onto the first makes both transactions update one account.
        let stolen = outputs[0].public_pre_states[0].account_id;
        outputs[1].public_pre_states[0].account_id = stolen;

        assert_rejected_by_both(
            &outputs,
            "public account updated by two transactions",
            "Public account updated by multiple transactions in batch",
        );
    }

    /// A block validity window excluding the block id is rejected by both paths.
    #[test]
    fn block_window_violation_rejected_by_guest_and_native() {
        let (_fixtures, mut outputs) = load_fixture_outputs();
        if outputs.len() < 2 {
            return;
        }
        outputs.truncate(2);
        outputs[1].block_validity_window =
            lee_core::program::BlockValidityWindow::from((FIXTURE_BLOCK_ID + 1)..);

        assert_rejected_by_both(
            &outputs,
            "block id outside validity window",
            "Transaction block validity window does not include the block id",
        );
    }

    /// A timestamp validity window excluding the timestamp is rejected by both paths.
    #[test]
    fn timestamp_window_violation_rejected_by_guest_and_native() {
        let (_fixtures, mut outputs) = load_fixture_outputs();
        if outputs.len() < 2 {
            return;
        }
        outputs.truncate(2);
        outputs[1].timestamp_validity_window =
            lee_core::program::TimestampValidityWindow::from(..FIXTURE_TIMESTAMP);

        assert_rejected_by_both(
            &outputs,
            "timestamp outside validity window",
            "Transaction timestamp validity window does not include the timestamp",
        );
    }
}
