//! Slashing of sequencers that inscribe a payload that is not a valid block.
//!
//! The approvals a `Slash` carries are its only authorization.

pub use actor::{SlasherActor, build_slash_tx};
pub use r#trait::SlasherActorTrait;

pub mod actor;
pub mod error;
pub mod protocol;
pub mod storage;
pub mod r#trait;

pub type Result<T> = std::result::Result<T, error::Error>;
