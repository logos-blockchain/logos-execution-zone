use lee_core::PrivacyPreservingCircuitOutput;
use risc0_zkvm::guest::env;

/// Aggregation circuit for N privacy-preserving execution proofs.
///
/// The host writes:
///   1. The PPE circuit image ID (`[u32; 8]`)
///   2. The count N (`u32`)
///   3. N journal byte-buffers (each produced by `PrivacyPreservingCircuitOutput::to_bytes()`)
///
/// It also loads each PPE receipt as an assumption before running this guest.
/// `env::verify` checks each assumption cryptographically; if any proof is
/// invalid the guest panics and no aggregation receipt is produced.
///
/// Journal: `Vec<PrivacyPreservingCircuitOutput>` — the verifier recovers all
/// circuit outputs from the single aggregated proof.
fn main() {
    // The host passes the PPE circuit image ID so the guest stays independent
    // of the host-only `lee` crate.
    let ppe_image_id: [u32; 8] = env::read();
    let count: u32 = env::read();

    let mut outputs = Vec::with_capacity(count as usize);

    for _ in 0..count {
        let journal: Vec<u8> = env::read();

        env::verify(ppe_image_id, &journal)
            .expect("PPE_aggregation: a PPE proof failed verification");

        let word_slice: &[u32] = bytemuck::cast_slice(&journal);
        let output: PrivacyPreservingCircuitOutput =
            risc0_zkvm::serde::from_slice(word_slice)
                .expect("PPE_aggregation: failed to deserialise circuit output");
        outputs.push(output);
    }

    env::commit(&outputs);
}
