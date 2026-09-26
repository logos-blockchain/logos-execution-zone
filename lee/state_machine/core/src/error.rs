#[cfg(feature = "host")]
use std::io;

#[cfg(feature = "host")]
use thiserror::Error;

#[cfg(feature = "host")]
#[derive(Error, Debug)]
pub enum LeeCoreError {
    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}
