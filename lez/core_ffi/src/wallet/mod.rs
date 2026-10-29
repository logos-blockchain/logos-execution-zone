//! LEE Wallet FFI Library.
//!
//! This crate provides C-compatible bindings for the LEE wallet functionality.
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
    clippy::as_conversions,
    reason = "TODO: fix later"
)]

use std::{
    ffi::{CStr, c_char},
    sync::OnceLock,
};

use ::wallet::ExecutionFailureKind;
use tokio::runtime::Handle;
pub use types::*;

use crate::{
    error::{FfiOperationError, print_error},
    primitives::types::FfiBytes32,
};

pub mod account;
pub mod bridge;
pub mod generic_transaction;
pub mod keys;
pub mod label;
pub mod lifecycle;
pub mod pda;
pub mod pending;
pub mod program_deployment;
pub mod sync;
pub mod transfer;
pub mod types;

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
    clippy::wildcard_enum_match_arm,
    reason = "We want to catch all errors for future proofing"
)]
pub(crate) fn map_execution_error(e: ExecutionFailureKind) -> FfiOperationError {
    match e {
        // TODO: Perform normal error (de-)encoding on both sides
        ExecutionFailureKind::SequencerClientError(message)
            if message.contains("Incorrect fee") =>
        {
            FfiOperationError::PayerCannotFund
        }
        ExecutionFailureKind::InsufficientFundsError => FfiOperationError::InsufficientFunds,
        ExecutionFailureKind::KeyNotFoundError => FfiOperationError::KeyNotFound,
        ExecutionFailureKind::StorageError(_) => FfiOperationError::StorageError,
        ExecutionFailureKind::SequencerError(_) | ExecutionFailureKind::SequencerClientError(_) => {
            FfiOperationError::NetworkError
        }
        _ => FfiOperationError::InternalError,
    }
}

/// Reads a nullable `FfiBytes32` pointer as an optional `AccountId`.
pub(crate) unsafe fn read_optional_account_id(ptr: *const FfiBytes32) -> Option<lee::AccountId> {
    (!ptr.is_null()).then(|| lee::AccountId::from(unsafe { *ptr }))
}

// The `size` entries at `data`, which may be null when there are none.
pub(crate) unsafe fn list<'entries, T>(
    data: *const T,
    size: usize,
) -> Result<&'entries [T], FfiOperationError> {
    if size == 0 {
        return Ok(&[]);
    }
    if data.is_null() {
        print_error("Null pointer for a non-empty list");
        return Err(FfiOperationError::NullPointer);
    }
    Ok(unsafe { std::slice::from_raw_parts(data, size) })
}

/// Helper to convert a C string to a Rust String.
fn c_str_to_string(ptr: *const c_char, name: &str) -> Result<String, FfiOperationError> {
    if ptr.is_null() {
        print_error(format!("Null pointer for {name}"));
        return Err(FfiOperationError::NullPointer);
    }

    let c_str = unsafe { CStr::from_ptr(ptr) };
    match c_str.to_str() {
        Ok(s) => Ok(s.to_owned()),
        Err(e) => {
            print_error(format!("Invalid UTF-8 in {name}: {e}"));
            Err(FfiOperationError::InvalidUtf8)
        }
    }
}
