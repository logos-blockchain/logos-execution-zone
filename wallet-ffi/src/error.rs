//! Error handling for the FFI layer.
//!
//! Uses numeric error codes with error messages printed to stderr.

/// Error codes returned by FFI functions.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletFfiError {
    /// Operation completed successfully.
    Success = 0,
    /// A null pointer was passed where a valid pointer was expected.
    NullPointer = 1,
    /// Invalid UTF-8 string.
    InvalidUtf8 = 2,
    /// Wallet handle is not initialized.
    WalletNotInitialized = 3,
    /// Configuration error.
    ConfigError = 4,
    /// Storage/persistence error.
    StorageError = 5,
    /// Network/RPC error.
    NetworkError = 6,
    /// Account not found.
    AccountNotFound = 7,
    /// Key not found for account.
    KeyNotFound = 8,
    /// Insufficient funds for operation.
    InsufficientFunds = 9,
    /// Invalid account ID format.
    InvalidAccountId = 10,
    /// Tokio runtime error.
    RuntimeError = 11,
    /// Password required but not provided.
    PasswordRequired = 12,
    /// Block synchronization error.
    SyncError = 13,
    /// Serialization/deserialization error.
    SerializationError = 14,
    /// Invalid conversion from FFI types to NSSA types.
    InvalidTypeConversion = 15,
    /// Invalid Key value.
    InvalidKeyValue = 16,
    /// Internal error (catch-all).
    InternalError = 99,
}

impl WalletFfiError {
    /// Check if it's [`WalletFfiError::Success`] or panic.
    pub fn unwrap(self) {
        let Self::Success = self else {
            panic!("Called `unwrap()` on error value `{self:#?}`");
        };
    }
}

/// Log an error message to stderr.
#[expect(
    clippy::print_stderr,
    reason = "In FFI context it's better to print errors than to return strings"
)]
pub fn print_error(msg: impl Into<String>) {
    eprintln!("[wallet-ffi] {}", msg.into());
}
