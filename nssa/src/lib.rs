#![expect(
    clippy::multiple_inherent_impl,
    reason = "We prefer to group methods by functionality rather than by type for encoding"
)]

pub use nssa_core::{
    SharedSecretKey,
    account::{Account, AccountId, Data},
    encryption::EphemeralPublicKey,
    program::ProgramId,
};
pub use privacy_preserving_transaction::{
    PrivacyPreservingTransaction, circuit::execute_and_prove,
};
pub use program_deployment_transaction::ProgramDeploymentTransaction;
pub use program_methods::PRIVACY_PRESERVING_CIRCUIT_ID;
pub use public_transaction::PublicTransaction;
pub use signature::{PrivateKey, PublicKey, Signature};
pub use state::V03State;

pub mod encoding;
pub mod error;
mod merkle_tree;
pub mod privacy_preserving_transaction;
pub mod program;
pub mod program_deployment_transaction;
pub mod public_transaction;
mod signature;
mod state;

pub mod program_methods {
    include!(concat!(env!("OUT_DIR"), "/program_methods/mod.rs"));
}
