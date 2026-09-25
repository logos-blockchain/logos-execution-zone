use std::{
    ffi::c_char,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use sequencer_service::SequencerConfig;

use crate::{Runtime, SequencerServiceFFI, api::PointerResult, errors::OperationStatus};

pub type InitializedSequencerServiceFFIResult = PointerResult<SequencerServiceFFI, OperationStatus>;

/// Creates and starts an sequencer based on the provided
/// configuration file path.
///
/// # Arguments
///
/// - `runtime`: A runtime for the sequencer to run on, or null to have the sequencer create and own
///   one.
/// - `config_path`: A pointer to a string representing the path to the configuration file.
///
/// # Returns
///
/// An `InitializedSequencerServiceFFIResult` containing either a pointer to the
/// initialized `SequencerServiceFFI` or an error code.
///
/// # Safety
/// The caller must ensure that:
/// - `runtime` is either null or a valid pointer to a [`Runtime`] that outlives the sequencer.
/// - `config_path` is a valid pointer to a null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sequencer_ffi_start_sequencer(
    runtime: *const Runtime,
    config_path: *const c_char,
) -> InitializedSequencerServiceFFIResult {
    // SAFETY: The caller must ensure the validness of the pointer arguments.
    unsafe { setup_sequencer(runtime, config_path) }.map_or_else(
        InitializedSequencerServiceFFIResult::from_error,
        InitializedSequencerServiceFFIResult::from_value,
    )
}

/// Initializes and starts an sequencer based on the provided
/// configuration file path.
///
/// # Arguments
///
/// - `runtime`: A runtime for the sequencer to run on, or null to create and own one.
/// - `config_path`: A pointer to a string representing the path to the configuration file.
///
/// # Returns
///
/// A `Result` containing either the initialized `SequencerServiceFFI` or an
/// error code.
///
/// # Safety
/// The caller must ensure that:
/// - `runtime` is either null or a valid pointer to a [`Runtime`] that outlives the sequencer.
/// - `config_path` is a valid pointer to a null-terminated C string.
unsafe fn setup_sequencer(
    runtime: *const Runtime,
    config_path: *const c_char,
) -> Result<SequencerServiceFFI, OperationStatus> {
    if config_path.is_null() {
        log::error!("Attempted to give a null config_path pointer. This is a bug. Aborting.");
        return Err(OperationStatus::NullPointer);
    }

    let user_config_path = PathBuf::from(
        unsafe { std::ffi::CStr::from_ptr(config_path) }
            .to_str()
            .map_err(|e| {
                log::error!("Could not convert the config path to string: {e}");
                OperationStatus::InitializationError
            })?,
    );
    let config = SequencerConfig::from_path(&user_config_path).map_err(|e| {
        log::error!("Failed to read config: {e}");
        OperationStatus::InitializationError
    })?;

    // Use the caller's runtime if one was supplied, otherwise create (and own)
    // our own. The `Runtime` wrapper drops the underlying tokio runtime only
    // when we own it; a borrowed one is left to its external owner.
    let runtime = if runtime.is_null() {
        Runtime::new().map_err(|e| {
            log::error!("Could not create tokio runtime: {e}");
            OperationStatus::InitializationError
        })?
    } else {
        // SAFETY: the caller guarantees `runtime` is valid and outlives the sequencer.
        let caller = unsafe { &*runtime };
        unsafe { Runtime::from_borrowed(caller.as_ref()) }
    };

    // This crate leaves the service's `rpc` feature off, so nothing binds this
    // and queries reach the executor through the FFI instead. A workspace build
    // can unify the feature back on, so keep it a loopback port the kernel
    // picks, which can collide with nothing.
    let rpc_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));

    let handle = runtime
        .block_on(sequencer_service::run(config, rpc_addr))
        .map_err(|e| {
            log::error!("Could not start the sequencer: {e:#}");
            OperationStatus::InitializationError
        })?;

    Ok(SequencerServiceFFI::new(handle, runtime))
}

/// Stops and frees the resources associated with the given sequencer service.
///
/// # Arguments
///
/// - `sequencer`: A pointer to the `SequencerServiceFFI` instance to be stopped.
///
/// # Returns
///
/// An `OperationStatus` indicating success or failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `sequencer` is a valid pointer to a `SequencerServiceFFI` instance
/// - The `SequencerServiceFFI` instance was created by this library
/// - The pointer will not be used after this function returns
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sequencer_ffi_stop_sequencer(
    sequencer: *mut SequencerServiceFFI,
) -> OperationStatus {
    if sequencer.is_null() {
        log::error!("Attempted to stop a null sequencer pointer. This is a bug. Aborting.");
        return OperationStatus::NullPointer;
    }

    let sequencer = unsafe { Box::from_raw(sequencer) };

    drop(sequencer);

    OperationStatus::Ok
}
