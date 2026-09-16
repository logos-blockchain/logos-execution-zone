//! Bedrock Actor communicates with Bedrock.

#[cfg(feature = "actor")]
pub use actor::{BedrockActor, config};
pub use r#trait::BedrockActorTrait;

#[cfg(feature = "actor")]
pub mod actor;
pub mod error;
#[cfg(feature = "mock")]
pub mod mock;
pub mod protocol;
pub mod r#trait;

pub type Result<T> = std::result::Result<T, error::Error>;
