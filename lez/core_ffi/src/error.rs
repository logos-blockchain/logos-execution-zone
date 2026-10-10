//! Error handling for the FFI layer.
//!
//! Uses numeric error codes with error messages printed to stderr.

use std::str::Utf8Error;

use crate::primitives::errors::PrimitiveOperationStatus;

/// Error codes returned by FFI functions.
#[repr(C)]
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum FfiOperationError {
    /// Operation completed successfully.
    #[default]
    Success = 0,
    /// A null pointer was passed where a valid pointer was expected.
    NullPointer = 1,
    /// Invalid UTF-8 string.
    InvalidUtf8 = 2,
    /// Invalid or malformed argument.
    InvalidArgument = 3,
    /// Error during sequencer initialization.
    SequencerInitializationError = 4,
    /// Wallet handle is not initialized.
    WalletNotInitialized = 5,
    /// Configuration error.
    ConfigError = 6,
    /// Storage/persistence error.
    StorageError = 7,
    /// Network/RPC error.
    NetworkError = 8,
    /// Query failed.
    QueryError = 9,
    /// Account not found.
    AccountNotFound = 10,
    /// Key not found for account.
    KeyNotFound = 11,
    /// Insufficient funds for operation.
    InsufficientFunds = 12,
    /// Invalid account ID format.
    InvalidAccountId = 13,
    /// Tokio runtime error.
    RuntimeError = 14,
    /// Password required but not provided.
    PasswordRequired = 15,
    /// Block synchronization error.
    SyncError = 16,
    /// Serialization/deserialization error.
    SerializationError = 17,
    /// Invalid conversion from FFI types to LEE types.
    InvalidTypeConversion = 18,
    /// Invalid Key value.
    InvalidKeyValue = 19,
    /// Invalid program bytecode.
    InvalidBytecode = 20,
    /// Fee payer cannot fund the fee reserve.
    PayerCannotFund = 21,
    /// Operation not supported yet.
    NotSupported = 22,
    /// Maximum response size exceeded.
    ResponseTooBig = 23,
    /// Internal error (catch-all).
    InternalError = 99,
}

impl From<Utf8Error> for FfiOperationError {
    fn from(_value: Utf8Error) -> Self {
        Self::InvalidUtf8
    }
}

impl FfiOperationError {
    /// Check if it's [`FfiOperationError::Success`] or panic.
    pub fn unwrap(self) {
        let Self::Success = self else {
            panic!("Called `unwrap()` on error value `{self:#?}`");
        };
    }

    #[must_use]
    pub fn is_ok(&self) -> bool {
        *self == Self::Success
    }

    #[must_use]
    pub fn is_error(&self) -> bool {
        !self.is_ok()
    }
}

impl From<PrimitiveOperationStatus> for FfiOperationError {
    fn from(value: PrimitiveOperationStatus) -> Self {
        match value {
            PrimitiveOperationStatus::Ok => Self::Success,
            PrimitiveOperationStatus::CastError => Self::InvalidTypeConversion,
        }
    }
}

/// Log an error message to stderr.
#[expect(
    clippy::print_stderr,
    reason = "In FFI context it's better to print errors than to return strings"
)]
pub fn print_error(msg: impl Into<String>) {
    eprintln!("[ffi] {}", msg.into());
}
