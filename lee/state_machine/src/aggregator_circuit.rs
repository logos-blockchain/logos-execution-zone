//! Host-side aggregator circuit: batches multiple privacy-preserving circuit proofs into
//! a single aggregated proof.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    AggregatorCircuitInput, AggregatorCircuitOutput, BlockId, PrivacyPreservingCircuitOutput,
    Timestamp,
};
use risc0_zkvm::{ExecutorEnv, InnerReceipt, ProverOpts, Receipt, default_prover};

use crate::{
    error::LeeError, privacy_preserving_transaction::circuit::Proof,
    program_methods::PRIVACY_PRESERVING_CIRCUIT_ID,
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

/// Aggregates N privacy-preserving circuit proofs into a single proof.
///
/// `elf` is the compiled aggregator circuit binary. Use
/// `lee::program_methods::AGGREGATOR_CIRCUIT_ELF` for the core circuit or
/// `AGGREGATOR_CIRCUIT_STRICT_ELF` for the strict variant.
pub fn aggregate(
    block_id: BlockId,
    timestamp: Timestamp,
    proofs: Vec<(PrivacyPreservingCircuitOutput, Proof)>,
    elf: &[u8],
    segment_limit_po2: Option<u32>,
) -> Result<(AggregatorCircuitOutput, AggregatorProof), LeeError> {
    run_aggregator(block_id, timestamp, proofs, elf, segment_limit_po2)
}

fn run_aggregator(
    block_id: BlockId,
    timestamp: Timestamp,
    proofs: Vec<(PrivacyPreservingCircuitOutput, Proof)>,
    elf: &[u8],
    segment_limit_po2: Option<u32>,
) -> Result<(AggregatorCircuitOutput, AggregatorProof), LeeError> {
    // TODO: add host-side pre-checks before invoking the prover (e.g. no duplicate
    // nullifiers/commitments, validity windows, public account uniqueness) so obviously
    // invalid batches are rejected cheaply without spending GPU time.
    let mut env_builder = ExecutorEnv::builder();
    if let Some(po2) = segment_limit_po2 {
        env_builder.segment_limit_po2(po2);
    }
    let mut circuit_outputs = Vec::with_capacity(proofs.len());

    for (circuit_output, proof) in proofs {
        let inner = borsh::from_slice::<InnerReceipt>(&proof.into_inner())
            .map_err(|e| LeeError::CircuitOutputDeserializationError(e.to_string()))?;
        let receipt = Receipt::new(inner, circuit_output.to_bytes());
        env_builder.add_assumption(receipt);
        circuit_outputs.push(circuit_output);
    }

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
    use lee_core::{BlockId, PrivacyPreservingCircuitOutput, Timestamp};
    use test_program_methods::PpeFixture;

    use super::aggregate;
    use crate::{
        privacy_preserving_transaction::circuit::Proof,
        program_methods::{
            AGGREGATOR_CIRCUIT_ELF, AGGREGATOR_CIRCUIT_ID, AGGREGATOR_CIRCUIT_STRICT_ELF,
            AGGREGATOR_CIRCUIT_STRICT_ID,
        },
    };

    /// Benchmark: aggregate N pre-generated PPE proofs loaded from a fixture file.
    ///
    /// Generate fixtures first:
    ///   cargo run --release -p ppe_test_data_gen -- --output ppe_fixtures.bin
    ///
    /// Control via env vars:
    ///   PPE_FIXTURES      — path to fixture file (default: ppe_fixtures.bin)
    ///   AGGREGATOR_COUNT  — number of fixtures to use (default: all)
    ///   AGGREGATOR_STRICT — set to "1" for the strict variant (default: core)
    ///
    /// Skips gracefully when the fixture file is absent.
    ///
    /// Output line (captured by bench_aggregator_cuda.sh):
    ///   [lee::analytics] aggregator n=… variant=… proving_ms=… proof_size_bytes=…
    #[test]
    fn bench_aggregator() {
        let path =
            std::env::var("PPE_FIXTURES").unwrap_or_else(|_| "ppe_fixtures.bin".to_owned());
        let mut fixtures = PpeFixture::load_bundle(&path);

        if fixtures.is_empty() {
            return;
        }

        if let Ok(s) = std::env::var("AGGREGATOR_COUNT") {
            let count: usize = s.parse().expect("AGGREGATOR_COUNT must be a number");
            fixtures.truncate(count);
        }

        let strict: bool = std::env::var("AGGREGATOR_STRICT")
            .map(|s| s == "1" || s == "true")
            .unwrap_or(false);

        let (elf, circuit_id) = if strict {
            (AGGREGATOR_CIRCUIT_STRICT_ELF, AGGREGATOR_CIRCUIT_STRICT_ID)
        } else {
            (AGGREGATOR_CIRCUIT_ELF, AGGREGATOR_CIRCUIT_ID)
        };

        let proofs: Vec<(PrivacyPreservingCircuitOutput, Proof)> = fixtures
            .iter()
            .map(|f| {
                let words: &[u32] = bytemuck::cast_slice(&f.output_bytes);
                let output: PrivacyPreservingCircuitOutput =
                    risc0_zkvm::serde::from_slice(words).expect("fixture output_bytes invalid");
                let proof = Proof::from_inner(f.proof_bytes.clone());
                (output, proof)
            })
            .collect();

        let block_id: BlockId = 1;
        let timestamp = Timestamp::from(1_700_000_000_u64);
        let segment_limit_po2: Option<u32> = std::env::var("PPE_SEGMENT_LIMIT_PO2")
            .ok()
            .map(|s| s.parse().expect("PPE_SEGMENT_LIMIT_PO2 must be a number"));

        let t0 = std::time::Instant::now();
        let (_, agg_proof) =
            aggregate(block_id, timestamp, proofs, elf, segment_limit_po2).expect("aggregation should succeed");
        let proving_ms = t0.elapsed().as_millis();

        let variant = if strict { "strict" } else { "core" };
        let proof_size = agg_proof.into_inner().len();
        eprintln!(
            "[lee::analytics] aggregator n={} variant={variant} proving_ms={proving_ms} proof_size_bytes={proof_size}",
            fixtures.len(),
        );

        let _ = circuit_id;
    }
}
