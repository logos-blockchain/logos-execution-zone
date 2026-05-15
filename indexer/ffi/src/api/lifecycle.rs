use std::{ffi::c_char, path::PathBuf};

use crate::{
    IndexerServiceFFI, Runtime,
    api::{
        PointerResult,
        client::{UrlProtocol, addr_to_url},
    },
    client::{IndexerClient, IndexerClientTrait as _},
    errors::OperationStatus,
};

pub type InitializedIndexerServiceFFIResult = PointerResult<IndexerServiceFFI, OperationStatus>;

/// Creates and starts an indexer based on the provided
/// configuration file path.
///
/// # Arguments
///
/// - `config_path`: A pointer to a string representing the path to the configuration file.
/// - `port`: Number representing a port, on which indexers RPC will start.
///
/// # Returns
///
/// An `InitializedIndexerServiceFFIResult` containing either a pointer to the
/// initialized `IndexerServiceFFI` or an error code.
///
/// # Safety
/// The caller must ensure that:
/// - `runtime` is a valid pointer to a `tokio::runtime::Runtime` instance.
/// - `config_path` is a valid pointer to a null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn start_indexer(
    runtime: *const Runtime,
    config_path: *const c_char,
    port: u16,
) -> InitializedIndexerServiceFFIResult {
    // SAFETY: The caller must ensure the validness of the `runtime` and `config_path` pointers.
    unsafe { setup_indexer(runtime, config_path, port) }.map_or_else(
        InitializedIndexerServiceFFIResult::from_error,
        InitializedIndexerServiceFFIResult::from_value,
    )
}

/// Creates a new [`tokio::runtime::Runtime`].
#[unsafe(no_mangle)]
pub extern "C" fn new_runtime() -> PointerResult<Runtime, OperationStatus> {
    Runtime::new().map_or_else(
        |_e| PointerResult::from_error(OperationStatus::InitializationError),
        PointerResult::from_value,
    )
}

/// Initializes and starts an indexer based on the provided
/// configuration file path.
///
/// # Arguments
///
/// - `config_path`: A pointer to a string representing the path to the configuration file.
/// - `port`: Number representing a port, on which indexers RPC will start.
///
/// # Returns
///
/// A `Result` containing either the initialized `IndexerServiceFFI` or an
/// error code.
///
/// # Safety
/// The caller must ensure that:
/// - `runtime` is a valid pointer to a `tokio::runtime::Runtime` instance.
/// - `config_path` is a valid pointer to a null-terminated C string.
unsafe fn setup_indexer(
    runtime: *const Runtime,
    config_path: *const c_char,
    port: u16,
) -> Result<IndexerServiceFFI, OperationStatus> {
    let user_config_path = PathBuf::from(
        unsafe { std::ffi::CStr::from_ptr(config_path) }
            .to_str()
            .map_err(|e| {
                log::error!("Could not convert the config path to string: {e}");
                OperationStatus::InitializationError
            })?,
    );
    let config = indexer_service::IndexerConfig::from_path(&user_config_path).map_err(|e| {
        log::error!("Failed to read config: {e}");
        OperationStatus::InitializationError
    })?;

    // SAFETY: The caller must ensure that `runtime` is a valid pointer to a
    // `tokio::runtime::Runtime` instance.
    let runtime = unsafe { &*runtime };

    let indexer_handle = runtime
        .block_on(indexer_service::run_server(config, port))
        .map_err(|e| {
            log::error!("Could not start indexer service: {e}");
            OperationStatus::InitializationError
        })?;

    let indexer_url = addr_to_url(UrlProtocol::Ws, indexer_handle.addr())?;
    let indexer_client = runtime
        .block_on(IndexerClient::new(&indexer_url))
        .map_err(|e| {
            log::error!("Could not start indexer client: {e}");
            OperationStatus::InitializationError
        })?;

    Ok(IndexerServiceFFI::new(indexer_handle, indexer_client))
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
