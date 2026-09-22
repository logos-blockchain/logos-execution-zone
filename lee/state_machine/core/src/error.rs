#[cfg(feature = "host")]
use std::io;

use thiserror::Error;

use crate::{
    account::{AccountId, BalanceDiffError},
    program::{AccountInput, ExecutionValidationError},
};

#[cfg(feature = "host")]
#[derive(Error, Debug)]
pub enum LeeCoreError {
    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}

/// Ways a program can violate the execution rules the environment enforces on it.
///
/// Raised by the shared traversal in [`crate::validation`], so both environments reject on it:
/// the public state machine surfaces it as `LeeError::InvalidProgramBehavior`, the privacy
/// preserving circuit panics on it in-guest.
#[derive(Error, Debug)]
pub enum InvalidProgramBehaviorError {
    #[error(
        "Inconsistent pre-state for account {account_id} : expected {expected:?}, actual {actual:?}"
    )]
    InconsistentAccountPreState {
        account_id: AccountId,
        // Boxed to reduce the size of the error type
        expected: Box<AccountInput>,
        actual: Box<AccountInput>,
    },

    #[error("Unauthorized account marked as authorized")]
    InvalidAccountAuthorization { account_id: AccountId },

    #[error("Authorized account marked as not authorized")]
    AuthorizedAccountMarkedAsNotAuthorized { account_id: AccountId },

    #[error("Program account ID mismatch: expected {expected}, actual {actual}")]
    MismatchedProgramId {
        expected: AccountId,
        actual: AccountId,
    },

    #[error("Caller program account ID mismatch: expected {expected:?}, actual {actual:?}")]
    MismatchedCallerProgramId {
        expected: Option<AccountId>,
        actual: Option<AccountId>,
    },

    #[error("Chained call to {program_account_id} did not execute")]
    ChainedCallDidNotExecute { program_account_id: AccountId },

    #[error(transparent)]
    ExecutionValidationFailed(#[from] ExecutionValidationError),

    #[error("Called program {program_account_id} which is not listed in dependencies")]
    UndeclaredProgramDependency { program_account_id: AccountId },

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
        "Program {program_account_id} ran on accounts its caller either did not name or did not \
         name in appropriate order."
    )]
    ChainedCallAccountsMismatch { program_account_id: AccountId },

    #[error(
        "Program {program_account_id}'s own output reports account {account_id}, which the \
         chained call that invoked it never named"
    )]
    UndeclaredAccountInProgramOutput {
        program_account_id: AccountId,
        account_id: AccountId,
    },

    #[error(transparent)]
    BalanceDiffFailed(#[from] BalanceDiffError),
}
