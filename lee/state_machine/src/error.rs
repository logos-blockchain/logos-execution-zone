use std::io;

use lee_core::{
    account::{Account, AccountId, BalanceDiffError},
    execution_state::ExecutionWalkError,
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
pub enum LeeError {
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
    Core(#[from] lee_core::error::LeeCoreError),

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

    #[error("Execution outside of the validity window")]
    OutOfValidityWindow,

    #[error(transparent)]
    ExecutionWalk(Box<ExecutionWalkError<Self>>),
}

impl From<ExecutionWalkError<Self>> for LeeError {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "every other walk rejection is carried through unchanged, and one added later should be too"
    )]
    fn from(error: ExecutionWalkError<Self>) -> Self {
        match error {
            // The walk hands back whatever the host's own per-call step failed with.
            ExecutionWalkError::Provider(error) => error,
            // Pinned by callers, so it keeps its own variant.
            ExecutionWalkError::MaxChainedCallsDepthExceeded => Self::MaxChainedCallsDepthExceeded,
            error => Self::ExecutionWalk(Box::new(error)),
        }
    }
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

    #[error("Unauthorized account marked as authorized")]
    InvalidAccountAuthorization { account_id: AccountId },

    #[error("Authorized account marked as not authorized")]
    AuthorizedAccountMarkedAsNotAuthorized { account_id: AccountId },

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
    ExecutionValidationFailed(#[from] lee_core::program::ExecutionValidationError),

    #[error(transparent)]
    Claim(#[from] lee_core::program::ClaimError),

    #[error("Default account {account_id} was modified without being claimed")]
    DefaultAccountModifiedWithoutClaim { account_id: AccountId },

    #[error("Called program {program_id:?} which is not listed in dependencies")]
    UndeclaredProgramDependency { program_id: ProgramId },

    #[error(
        "Account {account_id} was declared in the transaction but is missing from the program output"
    )]
    DeclaredAccountMissingFromOutput { account_id: AccountId },

    #[error(transparent)]
    BalanceDiffFailed(#[from] BalanceDiffError),

    #[error(
        "Program {program_id:?} ran on accounts its caller did not name: a chained call's \
         `accounts` must match the callee's journalled pre_states exactly, in order"
    )]
    ChainedCallAccountsMismatch { program_id: ProgramId },

    #[error(
        "Program {program_id:?} journalled pre_states the execution walk does not derive for it"
    )]
    JournalledPreStatesMismatch { program_id: ProgramId },
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
