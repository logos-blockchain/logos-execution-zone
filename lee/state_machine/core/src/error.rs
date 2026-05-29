use std::io;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum LeeCoreError {
    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}
