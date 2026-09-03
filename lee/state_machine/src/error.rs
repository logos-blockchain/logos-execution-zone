use std::io;

use lee_core::{
    account::{Account, AccountId, Cycles},
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

    #[error("Execution exceeded its cycle budget of {budget} cycles")]
    OutOfGas { budget: Cycles },

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

    #[error("Max account nonce reached")]
    MaxAccountNonceReached,

    #[error("Execution outside of the validity window")]
    OutOfValidityWindow,

    #[error("Unknown program")]
    UnknownProgram {
        /// A top-level unknown program is detectable before execution,
        /// but if it is part of a chain of calls, we can only learn it
        /// after executing; therefore, the failure is charged.
        chained: bool,
    },
}

impl LeeError {
    /// Whether a failing action is charged-and-reverted (the block stays valid)
    /// rather than rejecting the block.
    ///
    /// - A malformed transaction is caught before the program runs, costs no cycles, and rejects
    ///   the block.
    /// - Auth and nonce failures never reach here; they bail before execution.
    /// - Every other failure that surfaces during or after execution, so it is charged and
    ///   reverted: the payer pays and the nonce advances.
    #[must_use]
    pub const fn is_chargeable(&self) -> bool {
        !matches!(
            self,
            Self::InvalidInput(_) | Self::UnknownProgram { chained: false }
        )
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

    #[error(
        "Account {account_id} was declared in the transaction but is missing from the program output"
    )]
    DeclaredAccountMissingFromOutput { account_id: AccountId },

    #[error(
        "Chained call named account {account_id}, but it isn't resolvable from the top-level \
         pre_states or any earlier call's materialized diff in this transaction"
    )]
    UnknownChainedCallAccount { account_id: AccountId },

    #[error(
        "Program {program_id:?} ran on accounts its caller either did not name or did not name \
         in appropriate order."
    )]
    ChainedCallAccountsMismatch { program_id: ProgramId },

    #[error(
        "Program {program_id:?}'s own output reports account {account_id}, which the chained \
         call that invoked it never named"
    )]
    UndeclaredAccountInProgramOutput {
        program_id: ProgramId,
        account_id: AccountId,
    },
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

    #[test]
    fn is_chargeable_charges_execution_failures_rejects_structural_defects() {
        use super::LeeError;

        // Anything that surfaces during or after execution has already burned
        // proposer cycles, so it is charged and reverted rather than rejecting
        // the block. A guest-panic revert (insufficient balance, failed swap,
        // `assert!`) surfaces as `ProgramExecutionFailed` — the common case.
        assert!(LeeError::ProgramExecutionFailed("guest panicked".into()).is_chargeable());
        assert!(LeeError::OutOfGas { budget: 0 }.is_chargeable());
        assert!(LeeError::MaxChainedCallsDepthExceeded.is_chargeable());
        // Post-execution: the validity window is read off the program output.
        assert!(LeeError::OutOfValidityWindow.is_chargeable());

        // An unknown program named by a chained call is only discovered after
        // the caller already executed, so it is charged; named top-level it is
        // detectable before execution and rejects instead.
        assert!(LeeError::UnknownProgram { chained: true }.is_chargeable());
        assert!(!LeeError::UnknownProgram { chained: false }.is_chargeable());

        // A malformed transaction is caught before execution, so it costs no
        // cycles and rejects the block instead of charging.
        assert!(!LeeError::InvalidInput("malformed".into()).is_chargeable());
    }
}
