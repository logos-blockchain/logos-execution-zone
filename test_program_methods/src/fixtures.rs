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
    #[must_use]
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

/// A bundle of pre-generated `PrivacyPreservingTransaction`s plus the genesis `V03State`
/// they were proven against.
///
/// Produced by `ppe_test_data_gen` and consumed by the aggregator circuit benchmark, so
/// that transaction proving is fully decoupled from aggregation. `state_bytes` and
/// `tx_bytes` are Borsh-encoded `lee::V03State` and `lee::PrivacyPreservingTransaction`
/// values respectively, kept as raw bytes so this crate doesn't need to depend on `lee`.
///
/// Load a bundle with [`PpeTxFixtureBundle::load_bundle`].
#[derive(BorshSerialize, BorshDeserialize)]
pub struct PpeTxFixtureBundle {
    /// Block id the transactions' validity windows and nonces were proven against.
    pub block_id: u64,
    /// Timestamp the transactions' validity windows were proven against.
    pub timestamp: u64,
    /// Human-readable labels identifying each transaction's scenario, in `tx_bytes` order.
    pub labels: Vec<String>,
    /// Borsh-encoded `V03State` containing the genesis sender accounts.
    pub state_bytes: Vec<u8>,
    /// Borsh-encoded `PrivacyPreservingTransaction`s, one per `labels` entry.
    pub tx_bytes: Vec<Vec<u8>>,
}

impl PpeTxFixtureBundle {
    /// Loads a Borsh-encoded `PpeTxFixtureBundle` from `path`.
    ///
    /// Returns `None` (and prints a skip notice) when the file does not exist, so that
    /// test suites skip gracefully when fixtures have not been generated yet. Any other
    /// I/O error or deserialisation failure panics with a diagnostic message.
    #[must_use]
    pub fn load_bundle(path: &str) -> Option<Self> {
        if !std::path::Path::new(path).exists() {
            eprintln!(
                "[test_program_methods] PPE tx fixture file '{path}' not found — skipping. \
                 Run `RISC0_DEV_MODE=1 cargo run --release -p ppe_test_data_gen` to generate it."
            );
            return None;
        }
        let bytes = std::fs::read(path)
            .unwrap_or_else(|e| panic!("failed to read PPE tx fixture file '{path}': {e}"));
        Some(borsh::from_slice(&bytes).expect("PPE tx fixture bundle failed Borsh deserialisation"))
    }
}
