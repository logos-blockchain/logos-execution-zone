use borsh::{BorshDeserialize, BorshSerialize};

/// A single pre-generated PPE proof fixture.
///
/// Produced by `ppe_test_data_gen` and consumed by the aggregation test so that
/// individual transaction proof generation is fully decoupled from the aggregation step.
///
/// Load a bundle with [`PpeFixture::load_bundle`].
#[derive(BorshSerialize, BorshDeserialize)]
pub struct PpeFixture {
    /// Human-readable label identifying the scenario.
    pub label: String,
    /// `PrivacyPreservingCircuitOutput` encoded via `to_bytes()` (risc0 serde / u32 word slice).
    /// This is the journal that was committed by the PPE circuit.
    pub output_bytes: Vec<u8>,
    /// Borsh-encoded `InnerReceipt` (from `Proof::into_inner()`).
    pub proof_bytes: Vec<u8>,
}

impl PpeFixture {
    /// Loads a Borsh-encoded `Vec<PpeFixture>` from `path`.
    ///
    /// Returns an empty `Vec` (and prints a skip notice) when the file does not exist,
    /// so that test suites skip gracefully when fixtures have not been generated yet.
    /// Any other I/O error or deserialisation failure panics with a diagnostic message.
    pub fn load_bundle(path: &str) -> Vec<Self> {
        if !std::path::Path::new(path).exists() {
            eprintln!(
                "[test_program_methods] PPE fixture file '{path}' not found — skipping. \
                 Run `RISC0_DEV_MODE=1 cargo run --release -p ppe_test_data_gen` to generate it."
            );
            return Vec::new();
        }
        let bytes = std::fs::read(path)
            .unwrap_or_else(|e| panic!("failed to read PPE fixture file '{path}': {e}"));
        borsh::from_slice(&bytes).expect("PPE fixture bundle failed Borsh deserialisation")
    }
}
