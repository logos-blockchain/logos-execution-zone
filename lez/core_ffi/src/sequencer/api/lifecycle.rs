use std::{ffi::c_char, sync::Arc};

use clap::Parser as _;
use sequencer_service::{StartArgs, ops::OpsServer};

use crate::{
    error::FfiOperationError,
    primitives::{result::PointerResult, runtime::Runtime},
    sequencer::SequencerServiceFFI,
};

pub type InitializedSequencerServiceFFIResult =
    PointerResult<SequencerServiceFFI, FfiOperationError>;

/// `sequencer_service start`'s options.
#[derive(clap::Parser)]
#[clap(no_binary_name = true)]
struct StartCommand {
    #[clap(flatten)]
    args: StartArgs,
}

/// Creates and starts a sequencer the way `sequencer_service start` does, taking the same
/// options.
///
/// `args` are `start`'s arguments without the program name, e.g. `["/var/lib/sequencer",
/// "--config", "/etc/sequencer/config.json"]`. Each option left out falls back to its
/// `SEQUENCER_<OPTION>` env var, then to the config, exactly as for `start`. That includes
/// serving the RPC on `--rpc-listen-address` and `/ping`, `/health` and `/metrics` on the
/// config's `metrics_listen_address`.
///
/// Blocks until the sequencer has started, which with `--wait-for-channel` lasts until the
/// channel exists.
///
/// # Arguments
///
/// - `runtime`: A runtime for the sequencer to run on, or null to have the sequencer create and own
///   one.
/// - `args`: Pointer to `args_len` null-terminated strings, or null when `args_len` is zero.
/// - `args_len`: The number of strings in `args`.
///
/// # Returns
///
/// An `InitializedSequencerServiceFFIResult` containing either a pointer to the
/// initialized `SequencerServiceFFI` or an error code.
///
/// # Safety
/// The caller must ensure that:
/// - `runtime` is either null or a valid pointer to a [`Runtime`] that outlives the sequencer.
/// - `args` points to `args_len` valid pointers to null-terminated C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sequencer_ffi_start_sequencer(
    runtime: *const Runtime,
    args: *const *const c_char,
    args_len: usize,
) -> InitializedSequencerServiceFFIResult {
    // SAFETY: The caller must ensure the validness of the pointer arguments.
    unsafe { setup_sequencer(runtime, args, args_len) }.map_or_else(
        InitializedSequencerServiceFFIResult::from_error,
        InitializedSequencerServiceFFIResult::from_value,
    )
}

/// Use the caller's runtime if one was supplied, otherwise create (and own)
/// our own. The `Runtime` wrapper drops the underlying tokio runtime only
/// when we own it; a borrowed one is left to its external owner.
///
/// # Safety
/// `runtime` must be null or a valid pointer to a [`Runtime`] that outlives the sequencer.
unsafe fn runtime_or_new(runtime: *const Runtime) -> Result<Runtime, FfiOperationError> {
    if runtime.is_null() {
        Runtime::new().map_err(|e| {
            tracing::error!(error = %e, "Could not create tokio runtime");
            FfiOperationError::SequencerInitializationError
        })
    } else {
        // SAFETY: the caller guarantees `runtime` is valid and outlives the sequencer.
        let caller = unsafe { &*runtime };
        Ok(unsafe { Runtime::from_borrowed(caller.as_ref()) })
    }
}

/// See [`sequencer_ffi_start_sequencer`].
///
/// # Safety
/// As for [`sequencer_ffi_start_sequencer`].
unsafe fn setup_sequencer(
    runtime: *const Runtime,
    args: *const *const c_char,
    args_len: usize,
) -> Result<SequencerServiceFFI, FfiOperationError> {
    let args = if args_len == 0 {
        &[][..]
    } else if args.is_null() {
        tracing::error!("Attempted to give a null args pointer. This is a bug. Aborting.");
        return Err(FfiOperationError::NullPointer);
    } else {
        // SAFETY: the caller guarantees `args` points to `args_len` pointers.
        unsafe { std::slice::from_raw_parts(args, args_len) }
    };
    let args = args
        .iter()
        .map(|&arg| {
            if arg.is_null() {
                tracing::error!("Attempted to give a null argument. This is a bug. Aborting.");
                return Err(FfiOperationError::NullPointer);
            }
            // SAFETY: the caller guarantees each argument is a valid C string.
            unsafe { std::ffi::CStr::from_ptr(arg) }
                .to_str()
                .map_err(|e| {
                    tracing::error!(error = %e, "Argument is not valid UTF-8");
                    FfiOperationError::InvalidUtf8
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let StartCommand { args } = StartCommand::try_parse_from(args).map_err(|e| {
        tracing::error!(error = %e, "Invalid sequencer arguments");
        FfiOperationError::InvalidArgument
    })?;

    let start = || -> anyhow::Result<_> {
        let config = args.load_config()?;
        let public_key = sequencer_service::channel_public_key(&config)?;
        Ok((config, public_key))
    };
    let (config, public_key) = start().map_err(|e| {
        tracing::error!(
            error = format_args!("{e:#}"),
            "Failed to load the sequencer config"
        );
        FfiOperationError::SequencerInitializationError
    })?;

    // SAFETY: the caller guarantees `runtime` is null or valid and outlives the sequencer.
    let runtime = unsafe { runtime_or_new(runtime) }?;

    let (handle, ops) = runtime
        .block_on(async move {
            // Served from the start, so probes and metrics answer while startup waits on Bedrock.
            let ops = OpsServer::start(config.metrics_listen_address, &public_key).await?;
            match sequencer_service::run(config, args.rpc_listen_address).await {
                Ok(handle) => {
                    let handle = Arc::new(handle);
                    if let Some(ops) = &ops {
                        ops.set_sequencer(Arc::clone(&handle));
                    }
                    Ok((handle, ops))
                }
                Err(err) => {
                    if let Some(ops) = ops {
                        ops.stop().await;
                    }
                    Err(err)
                }
            }
        })
        .map_err(|e| {
            tracing::error!(
                error = format_args!("{e:#}"),
                "Could not start the sequencer"
            );
            FfiOperationError::SequencerInitializationError
        })?;

    Ok(SequencerServiceFFI::new(handle, ops, runtime))
}

/// Whether every task of the sequencer is still running, as its `/health` reports.
///
/// Gossip is not part of it: without gossip the node keeps running on L1 alone. A sequencer that
/// is no longer healthy stays so; stop it and start a new one.
///
/// # Safety
/// `sequencer` must be a valid pointer to a `SequencerServiceFFI` created by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sequencer_ffi_is_healthy(sequencer: *const SequencerServiceFFI) -> bool {
    // SAFETY: the caller guarantees `sequencer` is null or valid.
    unsafe { sequencer.as_ref() }.map_or_else(
        || {
            tracing::error!("Attempted to query a null sequencer pointer. This is a bug.");
            false
        },
        SequencerServiceFFI::is_healthy,
    )
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
) -> FfiOperationError {
    if sequencer.is_null() {
        tracing::error!("Attempted to stop a null sequencer pointer. This is a bug. Aborting.");
        return FfiOperationError::NullPointer;
    }

    let sequencer = unsafe { Box::from_raw(sequencer) };

    drop(sequencer);

    FfiOperationError::Success
}
