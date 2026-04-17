use std::io;

use nssa_core::{
    account::{Account, AccountId},
    program::ProgramId,
};
use thiserror::Error;

#[macro_export]
macro_rules! ensure {
    ($cond:expr, $err:expr) => {
        if !$cond {
            return Err($err.into());
        }
    };
}

#[derive(Error, Debug)]
pub enum NssaError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Program violated execution rules")]
    InvalidProgramBehavior(#[from] InvalidProgramBehaviorError),

    #[error("Serialization error: {0}")]
    InstructionSerializationError(String),

    #[error("Invalid private key")]
    InvalidPrivateKey,

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Invalid Public Key")]
    InvalidPublicKey(#[source] k256::schnorr::Error),

    #[error("Invalid hex for public key")]
    InvalidHexPublicKey(#[source] hex::FromHexError),

    #[error("Failed to write program input: {0}")]
    ProgramWriteInputFailed(String),

    #[error("Failed to execute program: {0}")]
    ProgramExecutionFailed(String),

    #[error("Failed to prove program: {0}")]
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
    InvalidProgramBytecode(#[source] anyhow::Error),

    #[error("Program already exists")]
    ProgramAlreadyExists,

    #[error("Chain of calls is too long")]
    MaxChainedCallsDepthExceeded,

    #[error("Max account nonce reached")]
    MaxAccountNonceReached,

    #[error("Execution outside of the validity window")]
    OutOfValidityWindow,
}

#[derive(Error, Debug)]
pub enum InvalidProgramBehaviorError {
    #[error(
        "Inconsistent pre-state for account {account_id} : expected {expected:?}, actual {actual:?}"
    )]
    InconsistentAccountPreState {
        account_id: AccountId,
        // Boxed to reduce the size of the error type
        expected: Box<Account>,
        actual: Box<Account>,
    },

    #[error(
        "Inconsistent authorization for account {account_id} : expected {expected_authorization}, actual {actual_authorization}"
    )]
    InconsistentAccountAuthorization {
        account_id: AccountId,
        expected_authorization: bool,
        actual_authorization: bool,
    },

    #[error("Program ID mismatch: expected {expected:?}, actual {actual:?}")]
    MismatchedProgramId {
        expected: ProgramId,
        actual: ProgramId,
    },

    #[error("Caller program ID mismatch: expected {expected:?}, actual {actual:?}")]
    MismatchedCallerProgramId {
        expected: Option<ProgramId>,
        actual: Option<ProgramId>,
    },

    #[error(transparent)]
    ExecutionValidationFailed(#[from] nssa_core::program::ExecutionValidationError),

    #[error("Trying to claim account {account_id} which is not default")]
    ClaimedNonDefaultAccount { account_id: AccountId },

    #[error("Trying to claim account {account_id} which is not authorized")]
    ClaimedUnauthorizedAccount { account_id: AccountId },

    #[error("PDA claim mismatch: expected {expected:?}, actual {actual:?}")]
    MismatchedPdaClaim {
        expected: AccountId,
        actual: AccountId,
    },

    #[error("Default account {account_id} was modified without being claimed")]
    DefaultAccountModifiedWithoutClaim { account_id: AccountId },

    #[error("Called program {program_id:?} which is not listed in dependencies")]
    UndeclaredProgramDependency { program_id: ProgramId },
}

#[cfg(test)]
mod tests {

    #[derive(Debug)]
    enum TestError {
        TestErr,
    }

    fn test_function_ensure(cond: bool) -> Result<(), TestError> {
        ensure!(cond, TestError::TestErr);

        Ok(())
    }

    #[test]
    fn ensure_works() {
        assert!(test_function_ensure(true).is_ok());
        assert!(test_function_ensure(false).is_err());
    }
}
