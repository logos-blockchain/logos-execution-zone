#![expect(
    clippy::multiple_inherent_impl,
    reason = "We prefer to group methods by functionality rather than by type for encoding"
)]

pub use circuit_io::{
    BareProgramOutput, DummyInput, InputAccount, InputAccountIdentity, NullifierWitness,
    PrivacyPreservingCircuitInput, PrivacyPreservingCircuitOutput, PrivateAction, PrivateWitness,
    PublicAction, WitnessKind,
};
pub use commitment::{
    Commitment, CommitmentSetDigest, DUMMY_COMMITMENT, DUMMY_COMMITMENT_HASH, MembershipProof,
    compute_digest_for_path,
};
pub use encryption::{
    EncryptedAccountData, EncryptionScheme, EphemeralPublicKey, EphemeralSecretKey,
    ML_KEM_768_CIPHERTEXT_LEN, SharedSecretKey, ViewTag,
};
pub use frame::{from_frame, to_borsh_frame, to_frame};
pub use nullifier::{
    AuthorizationSecretKey, Identifier, Nullifier, NullifierPublicKey, NullifierSecretKey,
};
pub use program::PrivateAccountKind;

pub mod account;
mod circuit_io;
mod commitment;
mod encoding;
pub mod encryption;
mod frame;
mod nullifier;
pub mod program;

#[cfg(feature = "host")]
pub mod error;

pub const GENESIS_BLOCK_ID: BlockId = 1;

pub type BlockId = u64;
/// Unix timestamp in milliseconds.
pub type Timestamp = u64;
