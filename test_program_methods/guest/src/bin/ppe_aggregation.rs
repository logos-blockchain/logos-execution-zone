use lee_core::PrivacyPreservingCircuitOutput;
use risc0_zkvm::{guest::env, serde::to_vec};

/// Aggregation circuit for N privacy-preserving execution proofs.
///
/// The host writes:
///   1. The PPE circuit image ID (`[u32; 8]`)
///   2. `Vec<PrivacyPreservingCircuitOutput>` — the N outputs to verify and re-commit
///
/// It also loads each PPE receipt as an assumption before running this guest.
/// `env::verify` checks each assumption cryptographically; if any proof is
/// invalid the guest panics and no aggregation receipt is produced.
///
/// Journal: `Vec<PrivacyPreservingCircuitOutput>` — the verifier recovers all
/// circuit outputs from the single aggregated proof.
///
/// Outputs are read once as a word-native `Vec<...>` and re-serialized per-output via
/// `to_vec()` for `env::verify`, mirroring `aggregator_circuit`. This replaced reading
/// each journal as a raw `env::read::<Vec<u8>>()`: risc0's default serde deserializes
/// `Vec<u8>` one byte at a time (each unpacked from a word), which costs more guest
/// cycles than the word-native path. `to_vec(output)` and `output.to_bytes()` produce
/// identical bytes, so the assumption journal digest is unchanged.
fn main() {
    // The host passes the PPE circuit image ID so the guest stays independent
    // of the host-only `lee` crate.
    let ppe_image_id: [u32; 8] = env::read();
    let outputs: Vec<PrivacyPreservingCircuitOutput> = env::read();

    for output in &outputs {
        let output_words =
            to_vec(output).expect("PrivacyPreservingCircuitOutput serialization should not fail");
        env::verify(ppe_image_id, &output_words)
            .expect("PPE_aggregation: a PPE proof failed verification");
    }

    env::commit(&outputs);
}
