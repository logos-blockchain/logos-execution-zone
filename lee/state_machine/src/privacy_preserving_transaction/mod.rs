pub use message::Message;
pub use transaction::PrivacyPreservingTransaction;
pub use witness_set::WitnessSet;

pub mod message;
pub mod transaction;
pub mod witness_set;

#[cfg(not(target_os = "zkvm"))]
pub mod circuit;
#[cfg(target_os = "zkvm")]
#[path = "circuit/guest.rs"]
pub mod circuit;
