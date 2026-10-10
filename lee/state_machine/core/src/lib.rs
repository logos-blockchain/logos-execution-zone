#![expect(
    clippy::multiple_inherent_impl,
    reason = "We prefer to group methods by functionality rather than by type for encoding"
)]

pub use circuit_io::{
    DummyInput, DummyOutput, InvalidMessageEvidence, MessageWitness, NullifierWitness,
    PrivacyPreservingCircuitInput, PrivacyPreservingCircuitOutput, PrivateAction, PrivateWitness,
    ProgramImageClaim, ProgramImageWitness, ProvenExecution, ProvingInput, RegularKey, RootCall,
    SenderPresentation, ShadowProgramWitness, WitnessKind,
};
pub use commitment::{
    Commitment, CommitmentSetDigest, DUMMY_COMMITMENT, DUMMY_COMMITMENT_HASH,
    InvalidMembershipProof, MembershipProof, compute_digest_for_path,
};
pub use encryption::{
    EncryptedNote, EncryptionScheme, EphemeralPublicKey, EphemeralSecretKey,
    ML_KEM_768_CIPHERTEXT_LEN, SharedSecretKey,
};
pub use frame::{from_frame, to_borsh_frame, to_frame};
pub use nullifier::{AuthorizationSecretKey, Nullifier, NullifierPublicKey, NullifierSecretKey};
pub use program::PrivateAccountKind;
pub use recovery::{Recipient, RecipientEncryption, RecoveryBinding};
pub use sealing::{InvalidCastSeal, SealedCast, seal_casts};

pub mod account;
mod circuit_io;
mod commitment;
mod encoding;
pub mod encryption;
pub mod error;
pub mod execution_state;
mod frame;
pub mod native_token;
mod nullifier;
pub mod program;
mod recovery;
mod sealing;

pub const GENESIS_BLOCK_ID: BlockId = 1;

pub type BlockId = u64;
/// Unix timestamp in milliseconds.
pub type Timestamp = u64;
