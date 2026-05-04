#![expect(
    clippy::multiple_inherent_impl,
    reason = "We prefer to group methods by functionality rather than by type for encoding"
)]

pub use circuit_io::{
    InputAccountIdentity, PrivacyPreservingCircuitInput, PrivacyPreservingCircuitOutput,
};
pub use commitment::{
    Commitment, CommitmentSetDigest, DUMMY_COMMITMENT, DUMMY_COMMITMENT_HASH, MembershipProof,
    compute_digest_for_path,
};
pub use encryption::{EncryptionScheme, SharedSecretKey};
pub use nullifier::{Identifier, Nullifier, NullifierPublicKey, NullifierSecretKey};

pub mod account;
mod circuit_io;
mod commitment;
mod encoding;
pub mod encryption;
mod nullifier;
pub mod program;

#[cfg(feature = "host")]
pub mod error;

pub type BlockId = u64;
/// Unix timestamp in milliseconds.
pub type Timestamp = u64;
