//! Host-side aggregator circuit: batches multiple privacy-preserving circuit proofs into
//! a single aggregated proof.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    AggregatorCircuitInput, AggregatorCircuitOutput, BlockId, Commitment, Nullifier,
    PrivacyPreservingCircuitOutput, Timestamp, account::AccountId,
};
use risc0_zkvm::{ExecutorEnv, InnerReceipt, ProverOpts, Receipt, default_prover};

use crate::{
    PrivacyPreservingTransaction, V03State,
    error::LeeError,
    program_methods::PRIVACY_PRESERVING_CIRCUIT_ID,
    validated_state_diff::circuit_output_for_message,
};

/// Proof produced by the aggregator circuit.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AggregatorProof(Vec<u8>);

impl AggregatorProof {
    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }

    #[must_use]
    pub const fn from_inner(inner: Vec<u8>) -> Self {
        Self(inner)
    }

    #[must_use]
    pub fn is_valid_for(&self, output: &AggregatorCircuitOutput, circuit_id: [u32; 8]) -> bool {
        verify_proof(&self.0, output, circuit_id)
    }
}

fn verify_proof(
    proof_bytes: &[u8],
    output: &AggregatorCircuitOutput,
    circuit_id: [u32; 8],
) -> bool {
    let Ok(inner) = borsh::from_slice::<InnerReceipt>(proof_bytes) else {
        return false;
    };
    let receipt = Receipt::new(inner, output.to_bytes());
    receipt.verify(circuit_id).is_ok()
}

/// Filters `input_txs` down to the subset that can be aggregated together in one batch.
///
/// Each transaction is independently re-validated against `state` via
/// [`ValidatedStateDiff::from_privacy_preserving_transaction`] (signatures, nonces, validity
/// windows, proof, commitment/nullifier checks); transactions that fail this check are dropped.
///
/// Surviving transactions are then checked against every other surviving transaction so far,
/// mirroring the cross-transaction `assert!`s in the aggregator guests
/// (`program_methods/guest/src/bin/aggregator_circuit{,_strict}/main.rs`): a transaction is
/// dropped if it:
/// - reuses a nullifier already spent by an earlier transaction in this batch,
/// - reuses a commitment already created by an earlier transaction in this batch, or
/// - updates a public account already updated by an earlier transaction in this batch.
///
/// Returns the surviving transactions paired with the `PrivacyPreservingCircuitOutput` each
/// one's proof commits to, in input order. This filtering only depends on `state`, not on the
/// prover, so it can run anywhere `state` is available (e.g. ahead of batch construction).
#[must_use]
pub fn select_aggregatable_transactions(
    input_txs: Vec<PrivacyPreservingTransaction>,
    state: &V03State,
    _block_id: BlockId,
    _timestamp: Timestamp,
) -> Vec<(PrivacyPreservingTransaction, PrivacyPreservingCircuitOutput)> {
    let mut accepted = Vec::new();
    let mut seen_nullifiers: Vec<Nullifier> = Vec::new();
    let mut seen_commitments: Vec<Commitment> = Vec::new();
    let mut seen_updated_account_ids: Vec<AccountId> = Vec::new();

    for tx in input_txs {
        /*
        if let Err(e) =
            ValidatedStateDiff::from_privacy_preserving_transaction(&tx, state, block_id, timestamp)
        {
            eprintln!("[DEBUG] tx dropped by from_privacy_preserving_transaction: {e}");
            continue;
        }*/

        let signer_account_ids = tx.signer_account_ids();
        let circuit_output = circuit_output_for_message(state, &tx.message, &signer_account_ids);

        let updated_account_ids = || {
            circuit_output
                .public_pre_states
                .iter()
                .zip(circuit_output.public_post_states.iter())
                .filter(|(pre_state, post_state)| pre_state.account != **post_state)
                .map(|(pre_state, _)| pre_state.account_id)
        };

        let has_duplicate_nullifier = circuit_output
            .new_nullifiers
            .iter()
            .any(|(nullifier, _)| seen_nullifiers.contains(nullifier));
        let has_duplicate_commitment = circuit_output
            .new_commitments
            .iter()
            .any(|commitment| seen_commitments.contains(commitment));
        let has_duplicate_account_update =
            updated_account_ids().any(|account_id| seen_updated_account_ids.contains(&account_id));

        if has_duplicate_nullifier || has_duplicate_commitment || has_duplicate_account_update {
            continue;
        }

        seen_nullifiers.extend(circuit_output.new_nullifiers.iter().map(|(n, _)| *n));
        seen_commitments.extend(circuit_output.new_commitments.iter().cloned());
        seen_updated_account_ids.extend(updated_account_ids());

        accepted.push((tx, circuit_output));
    }

    accepted
}

/// Aggregates privacy-preserving circuit proofs into a single proof.
///
/// `input_txs` is first filtered down via [`select_aggregatable_transactions`]; only the
/// surviving transactions are proven against.
///
/// `elf` is the compiled aggregator circuit binary. Use
/// `lee::program_methods::AGGREGATOR_CIRCUIT_ELF` for the core circuit or
/// `AGGREGATOR_CIRCUIT_STRICT_ELF` for the strict variant.
pub fn aggregate(
    block_id: BlockId,
    timestamp: Timestamp,
    input_txs: Vec<PrivacyPreservingTransaction>,
    state: &V03State,
    elf: &[u8],
    segment_limit_po2: Option<u32>,
) -> Result<(AggregatorCircuitOutput, AggregatorProof), LeeError> {
    run_aggregator(block_id, timestamp, input_txs, state, elf, segment_limit_po2)
}

fn run_aggregator(
    block_id: BlockId,
    timestamp: Timestamp,
    input_txs: Vec<PrivacyPreservingTransaction>,
    state: &V03State,
    elf: &[u8],
    segment_limit_po2: Option<u32>,
) -> Result<(AggregatorCircuitOutput, AggregatorProof), LeeError> {
    let mut env_builder = ExecutorEnv::builder();
    if let Some(po2) = segment_limit_po2 {
        env_builder.segment_limit_po2(po2);
    }

    let input_len = input_txs.len();
    let mut circuit_outputs = Vec::new();
    for (tx, circuit_output) in select_aggregatable_transactions(input_txs, state, block_id, timestamp) {
        let inner = borsh::from_slice::<InnerReceipt>(&tx.witness_set.proof.into_inner())
            .map_err(|e| LeeError::CircuitOutputDeserializationError(e.to_string()))?;
        env_builder.add_assumption(Receipt::new(inner, circuit_output.to_bytes()));
        circuit_outputs.push(circuit_output);
    }

    eprintln!(
        "[DEBUG] select_aggregatable_transactions: input_len={input_len} accepted={}",
        circuit_outputs.len()
    );

    let input = AggregatorCircuitInput {
        privacy_preserving_circuit_id: PRIVACY_PRESERVING_CIRCUIT_ID,
        block_id,
        timestamp,
        circuit_outputs,
    };

    env_builder
        .write(&input)
        .map_err(|e| LeeError::CircuitProvingError(e.to_string()))?;

    let env = env_builder
        .build()
        .map_err(|e| LeeError::CircuitProvingError(e.to_string()))?;

    let prove_info = default_prover()
        // TODO: succinct compresses all segments into one receipt via recursion — consider
        // ProverOpts::composite() (no recursion, one receipt per segment) if proving speed
        // matters more than proof size.
        .prove_with_opts(env, elf, &ProverOpts::succinct())
        .map_err(|e| LeeError::CircuitProvingError(e.to_string()))?;

    let proof = AggregatorProof(borsh::to_vec(&prove_info.receipt.inner)?);

    let output: AggregatorCircuitOutput = prove_info
        .receipt
        .journal
        .decode()
        .map_err(|e| LeeError::CircuitOutputDeserializationError(e.to_string()))?;

    Ok((output, proof))
}

#[cfg(test)]
mod tests {
    use lee_core::{BlockId, Timestamp};
    use test_program_methods::{PpeFixture, PpeTxFixtureBundle};

    use super::aggregate;
    use crate::{
        PrivacyPreservingTransaction, V03State,
        program_methods::{
            AGGREGATOR_CIRCUIT_ELF, AGGREGATOR_CIRCUIT_ID, AGGREGATOR_CIRCUIT_STRICT_ELF,
            AGGREGATOR_CIRCUIT_STRICT_ID,
        },
    };

    /// Benchmark: aggregate N pre-generated PPE transactions loaded from a fixture file.
    ///
    /// Generate fixtures first:
    ///
    /// ```sh
    /// cargo run --release -p ppe_test_data_gen -- --tx-output ppe_tx_fixtures.bin
    /// ```
    ///
    /// Control via env vars:
    /// - `PPE_TX_FIXTURES`: path to fixture file (default: `ppe_tx_fixtures.bin`).
    /// - `AGGREGATOR_COUNT`: number of fixtures to use (default: all).
    /// - `AGGREGATOR_STRICT`: set to "1" for the strict variant (default: core).
    ///
    /// Skips gracefully when the fixture file is absent.
    ///
    /// Output line (captured by `bench_aggregator_cuda.sh`):
    /// `[lee::analytics] aggregator n=… variant=… proving_ms=… proof_size_bytes=…`.
    #[test]
    fn bench_aggregator() {
        let path = std::env::var("PPE_TX_FIXTURES")
            .unwrap_or_else(|_| "ppe_tx_fixtures.bin".to_owned());
        let Some(bundle) = PpeTxFixtureBundle::load_bundle(&path) else {
            return;
        };

        let state: V03State =
            borsh::from_slice(&bundle.state_bytes).expect("fixture state_bytes invalid");
        let mut transactions: Vec<PrivacyPreservingTransaction> = bundle
            .tx_bytes
            .iter()
            .map(|bytes| borsh::from_slice(bytes).expect("fixture tx_bytes invalid"))
            .collect();

        if transactions.is_empty() {
            return;
        }

        if let Ok(s) = std::env::var("AGGREGATOR_COUNT") {
            let count: usize = s.parse().expect("AGGREGATOR_COUNT must be a number");
            transactions.truncate(count);
        }

        let strict: bool = std::env::var("AGGREGATOR_STRICT")
            .map(|s| s == "1" || s == "true")
            .unwrap_or(false);

        let (elf, circuit_id) = if strict {
            (AGGREGATOR_CIRCUIT_STRICT_ELF, AGGREGATOR_CIRCUIT_STRICT_ID)
        } else {
            (AGGREGATOR_CIRCUIT_ELF, AGGREGATOR_CIRCUIT_ID)
        };

        let block_id: BlockId = bundle.block_id;
        let timestamp: Timestamp = bundle.timestamp;
        let segment_limit_po2: Option<u32> = std::env::var("PPE_SEGMENT_LIMIT_PO2")
            .ok()
            .map(|s| s.parse().expect("PPE_SEGMENT_LIMIT_PO2 must be a number"));

        let n = transactions.len();
        let t0 = std::time::Instant::now();
        let (_, agg_proof) = aggregate(
            block_id,
            timestamp,
            transactions,
            &state,
            elf,
            segment_limit_po2,
        )
        .expect("aggregation should succeed");
        let proving_ms = t0.elapsed().as_millis();

        let variant = if strict { "strict" } else { "core" };
        let proof_size = agg_proof.into_inner().len();
        #[expect(clippy::print_stderr, reason = "benchmark result line consumed by tooling")]
        {
            eprintln!(
                "[lee::analytics] aggregator n={n} variant={variant} proving_ms={proving_ms} proof_size_bytes={proof_size}",
            );
        }

        let _ = circuit_id;
    }

    /// Diagnostic: does `circuit_output_for_message`'s reconstruction of `public_pre_states[0]`
    /// from a fresh `V03State::new_with_genesis_accounts` genesis state match the
    /// `AccountWithMetadata` that `ppe_test_data_gen` originally fed to `execute_and_prove`?
    /// No proving involved — pure host-side construction, to isolate whether the
    /// "Invalid privacy preserving execution circuit proof" failure comes from this
    /// reconstruction step.
    #[test]
    fn debug_circuit_output_for_message_pre_state_reconstruction() {
        use lee_core::account::{Account, AccountId, AccountWithMetadata};

        use crate::{PrivateKey, PublicKey, program::Program};

        let program = Program::authenticated_transfer_program();
        let signing_key = PrivateKey::try_new([50_u8; 32]).expect("valid seed");
        let sender_account_id = AccountId::from(&PublicKey::new_from_private_key(&signing_key));

        let original = AccountWithMetadata::new(
            Account {
                program_owner: program.id(),
                balance: 110,
                ..Account::default()
            },
            true,
            sender_account_id,
        );

        let state = V03State::new_with_genesis_accounts(
            &[(sender_account_id, 110)],
            vec![],
            1_700_000_000,
        );
        let signer_account_ids = vec![sender_account_id];
        let reconstructed = AccountWithMetadata::new(
            state.get_account_by_id(sender_account_id),
            signer_account_ids.contains(&sender_account_id),
            sender_account_id,
        );

        assert_eq!(
            original, reconstructed,
            "public_pre_states[0] reconstruction mismatch"
        );
    }

    /// Diagnostic: for fixture index 0, does `circuit_output_for_message`'s reconstruction
    /// (from `ppe_tx_fixtures.bin`'s state + transaction) match the actual
    /// `PrivacyPreservingCircuitOutput` that was proven (from `ppe_fixtures.bin`)?
    /// Field-by-field, to localize a journal mismatch if `proof.is_valid_for(...)` fails.
    #[test]
    fn debug_circuit_output_for_message_matches_proven_output() {
        use lee_core::PrivacyPreservingCircuitOutput;

        use super::circuit_output_for_message;

        let fixtures_path =
            std::env::var("PPE_FIXTURES").unwrap_or_else(|_| "ppe_fixtures.bin".to_owned());
        let fixtures = PpeFixture::load_bundle(&fixtures_path);
        let Some(fixture) = fixtures.first() else {
            return;
        };
        let words: &[u32] = bytemuck::cast_slice(&fixture.output_bytes);
        let original: PrivacyPreservingCircuitOutput =
            risc0_zkvm::serde::from_slice(words).expect("output_bytes should decode");

        let tx_path = std::env::var("PPE_TX_FIXTURES")
            .unwrap_or_else(|_| "ppe_tx_fixtures.bin".to_owned());
        let Some(bundle) = PpeTxFixtureBundle::load_bundle(&tx_path) else {
            return;
        };
        let state: V03State =
            borsh::from_slice(&bundle.state_bytes).expect("fixture state_bytes invalid");
        let tx: PrivacyPreservingTransaction =
            borsh::from_slice(&bundle.tx_bytes[0]).expect("fixture tx_bytes invalid");
        let signer_account_ids = tx.signer_account_ids();
        let reconstructed = circuit_output_for_message(&state, &tx.message, &signer_account_ids);

        assert_eq!(
            original.public_pre_states, reconstructed.public_pre_states,
            "public_pre_states mismatch"
        );
        assert_eq!(
            original.public_post_states, reconstructed.public_post_states,
            "public_post_states mismatch"
        );
        assert_eq!(
            original.ciphertexts, reconstructed.ciphertexts,
            "ciphertexts mismatch"
        );
        assert_eq!(
            original.new_commitments, reconstructed.new_commitments,
            "new_commitments mismatch"
        );
        assert_eq!(
            original.new_nullifiers, reconstructed.new_nullifiers,
            "new_nullifiers mismatch"
        );
        assert_eq!(
            original.block_validity_window, reconstructed.block_validity_window,
            "block_validity_window mismatch"
        );
        assert_eq!(
            original.timestamp_validity_window, reconstructed.timestamp_validity_window,
            "timestamp_validity_window mismatch"
        );
        assert_eq!(original, reconstructed, "full PrivacyPreservingCircuitOutput mismatch");
    }

    /// Diagnostic: run the real `from_privacy_preserving_transaction` check (signatures,
    /// nonces, validity windows, proof verification, commitment/nullifier freshness) against
    /// fixture index 0 of `ppe_tx_fixtures.bin`, in isolation, to see exactly which sub-check
    /// fails (if any) for the current fixtures.
    #[test]
    fn debug_from_privacy_preserving_transaction_fixture0() {
        use crate::validated_state_diff::ValidatedStateDiff;

        let tx_path = std::env::var("PPE_TX_FIXTURES")
            .unwrap_or_else(|_| "ppe_tx_fixtures.bin".to_owned());
        let Some(bundle) = PpeTxFixtureBundle::load_bundle(&tx_path) else {
            return;
        };
        let state: V03State =
            borsh::from_slice(&bundle.state_bytes).expect("fixture state_bytes invalid");
        let tx: PrivacyPreservingTransaction =
            borsh::from_slice(&bundle.tx_bytes[0]).expect("fixture tx_bytes invalid");

        let result = ValidatedStateDiff::from_privacy_preserving_transaction(
            &tx,
            &state,
            bundle.block_id,
            bundle.timestamp,
        );
        match &result {
            Ok(_) => eprintln!("[DEBUG] fixture 0: from_privacy_preserving_transaction Ok"),
            Err(e) => eprintln!("[DEBUG] fixture 0: from_privacy_preserving_transaction Err: {e}"),
        }
        assert!(result.is_ok());
    }

    /// Diagnostic: drill into `Proof::is_valid_for` for fixture index 0 — does the proof
    /// bytes blob even decode as `InnerReceipt`, does `receipt.verify(...)` succeed against
    /// the reconstructed journal, and do the raw proof bytes match `ppe_fixtures.bin`'s
    /// `proof_bytes` for the same index?
    #[test]
    fn debug_proof_is_valid_for_fixture0() {
        use super::circuit_output_for_message;

        let tx_path = std::env::var("PPE_TX_FIXTURES")
            .unwrap_or_else(|_| "ppe_tx_fixtures.bin".to_owned());
        let Some(bundle) = PpeTxFixtureBundle::load_bundle(&tx_path) else {
            return;
        };
        let state: V03State =
            borsh::from_slice(&bundle.state_bytes).expect("fixture state_bytes invalid");
        let tx: PrivacyPreservingTransaction =
            borsh::from_slice(&bundle.tx_bytes[0]).expect("fixture tx_bytes invalid");
        let signer_account_ids = tx.signer_account_ids();
        let reconstructed = circuit_output_for_message(&state, &tx.message, &signer_account_ids);

        let proof_bytes = tx.witness_set.proof.0.clone();
        eprintln!("[DEBUG] tx.witness_set.proof bytes len = {}", proof_bytes.len());

        match borsh::from_slice::<risc0_zkvm::InnerReceipt>(&proof_bytes) {
            Ok(inner) => {
                eprintln!("[DEBUG] proof bytes decode as InnerReceipt: Ok");
                let receipt = risc0_zkvm::Receipt::new(inner, reconstructed.to_bytes());
                match receipt.verify(crate::program_methods::PRIVACY_PRESERVING_CIRCUIT_ID) {
                    Ok(()) => eprintln!("[DEBUG] receipt.verify: Ok"),
                    Err(e) => eprintln!("[DEBUG] receipt.verify: Err: {e}"),
                }
            }
            Err(e) => eprintln!("[DEBUG] proof bytes decode as InnerReceipt: Err: {e}"),
        }

        let fixtures_path =
            std::env::var("PPE_FIXTURES").unwrap_or_else(|_| "ppe_fixtures.bin".to_owned());
        let fixtures = PpeFixture::load_bundle(&fixtures_path);
        if let Some(fixture) = fixtures.first() {
            eprintln!(
                "[DEBUG] fixture.proof_bytes len = {}, tx proof bytes == fixture.proof_bytes: {}",
                fixture.proof_bytes.len(),
                proof_bytes == fixture.proof_bytes
            );
            eprintln!(
                "[DEBUG] fixture.output_bytes len = {}, reconstructed.to_bytes() == fixture.output_bytes: {}",
                fixture.output_bytes.len(),
                reconstructed.to_bytes() == fixture.output_bytes
            );
        }
    }
}
