#![expect(
    clippy::multiple_inherent_impl,
    reason = "We prefer to group methods by functionality rather than by type for encoding"
)]

pub use authorization::AuthorizationSecretKey;
pub use circuit_io::{
    NullifierWitness, PrivacyPreservingCircuitInput, PrivacyPreservingCircuitOutput, PrivateKind,
    PrivateWitness,
};
pub use commitment::{
    Commitment, CommitmentSetDigest, DUMMY_COMMITMENT, DUMMY_COMMITMENT_HASH, MembershipProof,
    compute_digest_for_path,
};
pub use encryption::{
    EncryptedAccountData, EncryptionScheme, EphemeralPublicKey, EphemeralSecretKey,
    ML_KEM_768_CIPHERTEXT_LEN, SharedSecretKey, ViewTag,
};
pub use nullifier::{
    Identifier, Nullifier, NullifierPublicKey, NullifierSecretKey, derive_nullifier_secret_key,
};
pub use program::PrivateAccountKind;
pub use validation::{
    Attestation, Authorization, Backend, ThreadedDiff, ValidationError, validate_state_diff,
};

pub mod account;
mod authorization;
mod circuit_io;
mod commitment;
mod encoding;
pub mod encryption;
mod nullifier;
pub mod program;
mod validation;

pub mod error;

pub const GENESIS_BLOCK_ID: BlockId = 1;

pub type BlockId = u64;
/// Unix timestamp in milliseconds.
pub type Timestamp = u64;
