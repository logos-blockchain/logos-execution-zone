use std::{ffi::c_char, path::PathBuf};

use futures::StreamExt as _;
use indexer_core::{IndexerCore, config::IndexerConfig};

use crate::{IndexerServiceFFI, Runtime, api::PointerResult, errors::OperationStatus};

pub type InitializedIndexerServiceFFIResult = PointerResult<IndexerServiceFFI, OperationStatus>;

/// Creates and starts an indexer based on the provided
/// configuration file path.
///
/// # Arguments
///
/// - `runtime`: A runtime for the indexer to run on, or null to have the indexer create and own
///   one.
/// - `config_path`: A pointer to a string representing the path to the configuration file.
/// - `storage_dir`: A pointer to a string naming the directory under which the indexer stores its
///   state (`RocksDB`), or null/empty to use the current directory. The host (e.g. a Logos module's
///   instance persistence path) owns this location.
///
/// # Returns
///
/// An `InitializedIndexerServiceFFIResult` containing either a pointer to the
/// initialized `IndexerServiceFFI` or an error code.
///
/// # Safety
/// The caller must ensure that:
/// - `runtime` is either null or a valid pointer to a [`Runtime`] that outlives the indexer.
/// - `config_path` is a valid pointer to a null-terminated C string.
/// - `storage_dir` is either null or a valid pointer to a null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn start_indexer(
    runtime: *const Runtime,
    config_path: *const c_char,
    storage_dir: *const c_char,
) -> InitializedIndexerServiceFFIResult {
    // SAFETY: The caller must ensure the validness of the pointer arguments.
    unsafe { setup_indexer(runtime, config_path, storage_dir) }.map_or_else(
        InitializedIndexerServiceFFIResult::from_error,
        InitializedIndexerServiceFFIResult::from_value,
    )
}

/// Initializes and starts an indexer based on the provided
/// configuration file path.
///
/// # Arguments
///
/// - `runtime`: A runtime for the indexer to run on, or null to create and own one.
/// - `config_path`: A pointer to a string representing the path to the configuration file.
/// - `storage_dir`: A pointer to a string naming the storage directory, or null/empty for `.`.
///
/// # Returns
///
/// A `Result` containing either the initialized `IndexerServiceFFI` or an
/// error code.
///
/// # Safety
/// The caller must ensure that:
/// - `runtime` is either null or a valid pointer to a [`Runtime`] that outlives the indexer.
/// - `config_path` is a valid pointer to a null-terminated C string.
/// - `storage_dir` is either null or a valid pointer to a null-terminated C string.
unsafe fn setup_indexer(
    runtime: *const Runtime,
    config_path: *const c_char,
    storage_dir: *const c_char,
) -> Result<IndexerServiceFFI, OperationStatus> {
    let user_config_path = PathBuf::from(
        unsafe { std::ffi::CStr::from_ptr(config_path) }
            .to_str()
            .map_err(|e| {
                log::error!("Could not convert the config path to string: {e}");
                OperationStatus::InitializationError
            })?,
    );
    let config = IndexerConfig::from_path(&user_config_path).map_err(|e| {
        log::error!("Failed to read config: {e}");
        OperationStatus::InitializationError
    })?;

    // The host owns where state lives. An empty/null `storage_dir` falls back to
    // the current directory (matches the standalone service's `--data-dir`
    // default), but a Logos module passes its instance persistence path.
    let storage_dir = if storage_dir.is_null() {
        PathBuf::from(".")
    } else {
        let storage_dir = unsafe { std::ffi::CStr::from_ptr(storage_dir) }
            .to_str()
            .map_err(|e| {
                log::error!("Could not convert the storage dir to string: {e}");
                OperationStatus::InitializationError
            })?;
        if storage_dir.is_empty() {
            PathBuf::from(".")
        } else {
            PathBuf::from(storage_dir)
        }
    };

    // Use the caller's runtime if one was supplied, otherwise create (and own)
    // our own. The `Runtime` wrapper drops the underlying tokio runtime only
    // when we own it; a borrowed one is left to its external owner.
    let runtime = if runtime.is_null() {
        Runtime::new().map_err(|e| {
            log::error!("Could not create tokio runtime: {e}");
            OperationStatus::InitializationError
        })?
    } else {
        // SAFETY: the caller guarantees `runtime` is valid and outlives the indexer.
        let caller = unsafe { &*runtime };
        unsafe { Runtime::from_borrowed(caller.as_ref()) }
    };

    let allow_reset = config.allow_chain_reset;
    let core = runtime
        .block_on(IndexerCore::new_with_genesis_check(
            config,
            &storage_dir,
            allow_reset,
        ))
        .map_err(|e| {
            log::error!("Could not initialize indexer core: {e}");
            OperationStatus::InitializationError
        })?;

    // The block stream writes each parsed block into the store as a side effect
    // of being polled, so we spawn a task that simply drains it. There are no
    // subscribers — queries read the store directly via `core()`.
    let ingest_core = core.clone();
    let ingest_handle = runtime.spawn(async move {
        let mut block_stream = std::pin::pin!(ingest_core.subscribe_parse_block_stream());
        while let Some(result) = block_stream.next().await {
            if let Err(e) = result {
                log::error!("Indexer ingestion error: {e:#}");
            }
        }
        log::warn!("Indexer block stream ended");
    });

    Ok(IndexerServiceFFI::new(core, ingest_handle, runtime))
}

/// Stops and frees the resources associated with the given indexer service.
///
/// # Arguments
///
/// - `indexer`: A pointer to the `IndexerServiceFFI` instance to be stopped.
///
/// # Returns
///
/// An `OperationStatus` indicating success or failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `indexer` is a valid pointer to a `IndexerServiceFFI` instance
/// - The `IndexerServiceFFI` instance was created by this library
/// - The pointer will not be used after this function returns
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stop_indexer(indexer: *mut IndexerServiceFFI) -> OperationStatus {
    if indexer.is_null() {
        log::error!("Attempted to stop a null indexer pointer. This is a bug. Aborting.");
        return OperationStatus::NullPointer;
    }

    let indexer = unsafe { Box::from_raw(indexer) };
    drop(indexer);

    OperationStatus::Ok
}
