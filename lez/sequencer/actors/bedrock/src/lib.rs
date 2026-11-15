//! Bedrock Actor communicates with Bedrock.

#[cfg(feature = "actor")]
pub use actor::BedrockActor;
#[cfg(feature = "actor")]
pub use logos_blockchain_common_http_client::BasicAuthCredentials;
pub use r#trait::BedrockActorTrait;
#[cfg(feature = "actor")]
pub use url::Url;

#[cfg(feature = "actor")]
pub mod actor;
pub mod error;
#[cfg(feature = "mock")]
pub mod mock;
pub mod protocol;
pub mod r#trait;

pub type Result<T> = std::result::Result<T, error::Error>;
