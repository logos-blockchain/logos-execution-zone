use std::io;

use thiserror::Error;

#[macro_export]
macro_rules! ensure {
    ($cond:expr, $err:expr) => {
        if !$cond {
            return Err($err);
        }
    };
}

#[derive(Error, Debug)]
pub enum NssaError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Program violated execution rules")]
    InvalidProgramBehavior,

    #[error("Serialization error: {0}")]
    InstructionSerializationError(String),

    #[error("Invalid private key")]
    InvalidPrivateKey,

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Invalid Public Key")]
    InvalidPublicKey,

    #[error("Risc0 error: {0}")]
    ProgramWriteInputFailed(String),

    #[error("Risc0 error: {0}")]
    ProgramExecutionFailed(String),

    #[error("Risc0 error: {0}")]
    ProgramProveFailed(String),

    #[error("Invalid transaction: {0}")]
    TransactionDeserializationError(String),

    #[error("Core error")]
    Core(#[from] nssa_core::error::NssaCoreError),

    #[error("Program output deserialization error: {0}")]
    ProgramOutputDeserializationError(String),

    #[error("Circuit output deserialization error: {0}")]
    CircuitOutputDeserializationError(String),

    #[error("Invalid privacy preserving execution circuit proof")]
    InvalidPrivacyPreservingProof,

    #[error("Circuit proving error")]
    CircuitProvingError(String),

    #[error("Invalid program bytecode")]
    InvalidProgramBytecode,

    #[error("Program already exists")]
    ProgramAlreadyExists,

    #[error("Chain of calls is too long")]
    MaxChainedCallsDepthExceeded,
}

#[derive(Debug)]
enum testError {
    testErr,
}


fn test_function_ensure(cond: bool) -> Result<(), testError> {
    ensure!(cond, testError::testErr);

    Ok(())
}


#[test]
fn test_ensure() {
    assert!(test_function_ensure(true).is_ok());
    assert!(test_function_ensure(false).is_err());

}