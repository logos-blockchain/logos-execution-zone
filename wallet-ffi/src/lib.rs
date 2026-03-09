//! NSSA Wallet FFI Library.
//!
//! This crate provides C-compatible bindings for the NSSA wallet functionality.
//!
//! # Usage
//!
//! 1. Initialize the runtime with `wallet_ffi_init_runtime()`
//! 2. Create or open a wallet with `wallet_ffi_create_new()` or `wallet_ffi_open()`
//! 3. Use the wallet functions to manage accounts and transfers
//! 4. Destroy the wallet with `wallet_ffi_destroy()` when done
//!
//! # Thread Safety
//!
//! All functions are thread-safe. The wallet handle uses internal locking
//! to ensure safe concurrent access.
//!
//! # Memory Management
//!
//! - Functions returning pointers allocate memory that must be freed
//! - Use the corresponding `wallet_ffi_free_*` function to free memory
//! - Never free memory returned by FFI using standard C `free()`

#![expect(
    clippy::undocumented_unsafe_blocks,
    clippy::multiple_unsafe_ops_per_block,
    reason = "TODO: fix later"
)]

use std::sync::OnceLock;

use common::error::ExecutionFailureKind;
// Re-export public types for cbindgen
pub use error::WalletFfiError as FfiError;
use tokio::runtime::Handle;
pub use types::*;

use crate::error::print_error;

pub mod account;
pub mod error;
pub mod keys;
pub mod pinata;
pub mod sync;
pub mod transfer;
pub mod types;
pub mod wallet;

static TOKIO_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

/// Get a reference to the global runtime.
pub(crate) fn get_runtime() -> &'static Handle {
    let runtime = TOKIO_RUNTIME.get_or_init(|| {
        match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(e) => {
                print_error(format!("{e}"));
                panic!("Error initializing tokio runtime");
            }
        }
    });
    runtime.handle()
}

/// Run an async future on the global runtime, blocking until completion.
pub(crate) fn block_on<F: std::future::Future>(future: F) -> F::Output {
    let runtime = get_runtime();
    runtime.block_on(future)
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "Error is consumed to create FFI error response"
)]
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "We want to catch all errors for future proofing"
)]
pub(crate) fn map_execution_error(e: ExecutionFailureKind) -> FfiError {
    match e {
        ExecutionFailureKind::InsufficientFundsError => FfiError::InsufficientFunds,
        ExecutionFailureKind::KeyNotFoundError => FfiError::KeyNotFound,
        ExecutionFailureKind::SequencerError(_) | ExecutionFailureKind::SequencerClientError(_) => {
            FfiError::NetworkError
        }
        _ => FfiError::InternalError,
    }
}
