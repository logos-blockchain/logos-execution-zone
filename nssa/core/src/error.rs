use std::io;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum NssaCoreError {
    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Invalid Public Key")]
    InvalidPublicKey(#[source] k256::schnorr::Error),

    #[error("Invalid hex for public key")]
    InvalidHexPublicKey(hex::FromHexError),

    #[error("Invalid private key")]
    InvalidPrivateKey,
}
