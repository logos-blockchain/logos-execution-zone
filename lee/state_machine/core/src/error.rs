use std::io;

use thiserror::Error;

use crate::{
    account::{Account, AccountId},
    program::{ExecutionValidationError, ProgramId},
};

#[derive(Error, Debug)]
pub enum LeeCoreError {
    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),
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
    ExecutionValidationFailed(#[from] ExecutionValidationError),

    #[error("Trying to claim account {account_id} which is not default")]
    ClaimedNonDefaultAccount { account_id: AccountId },

    #[error("PDA claim for account {account_id} does not match its (program, seed) derivation")]
    MismatchedPdaClaim { account_id: AccountId },

    #[error("Claim for account {account_id} does not exhibit the preimage of its address")]
    UnprovenAccountClaim { account_id: AccountId },

    #[error("Default account {account_id} was modified without being claimed")]
    DefaultAccountModifiedWithoutClaim { account_id: AccountId },

    #[error("Called program {program_id:?} which is not listed in dependencies")]
    UndeclaredProgramDependency { program_id: ProgramId },
}
