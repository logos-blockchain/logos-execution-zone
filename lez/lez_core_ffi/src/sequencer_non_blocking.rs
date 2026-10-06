use std::{ffi::c_char, os::raw::c_void};

use sequencer_service::SequencerHandle;
use tokio::task::JoinHandle;

use crate::{
    primitives::{result::PointerResult, runtime::Runtime}, sequencer::{SequencerServiceFFI, api::lifecycle::spawn_setup_sequencer, error::OperationStatus},
};

/// FFI-owned sequencer setup process.
///
/// - `task`: a [`JoinHandle`] owning sequencer setup process.
#[repr(C)]
pub struct FfiSequencerSetupNonBlocking {
    pub task: *mut c_void,
}

impl Default for FfiSequencerSetupNonBlocking {
    fn default() -> Self {
        Self {
            task: std::ptr::null_mut(),
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sequencer_ffi_spawn_sequencer_setup(
    runtime: *const Runtime,
    config_path: *const c_char,
) -> PointerResult<FfiSequencerSetupNonBlocking, OperationStatus> {
    // SAFETY: The caller must ensure the validness of the pointer arguments.
    unsafe { spawn_setup_sequencer(runtime, config_path) }.map_or_else(
        PointerResult::from_error,
        |res| PointerResult::from_value(
            FfiSequencerSetupNonBlocking { task: Box::into_raw(Box::new(res)).cast::<c_void>() }
        ),
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sequencer_ffi_check_sequencer_task(
    setup: *mut FfiSequencerSetupNonBlocking,
) -> bool {
    let setup = unsafe {
        &setup.read()
    };

    unsafe {
        setup.task
                .cast::<JoinHandle<Result<SequencerHandle, OperationStatus>>>()
                .as_ref()
                .expect("task must be a non-null pointer")
                .is_finished()
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sequencer_ffi_fetch_sequencer_handle(
    setup: *mut FfiSequencerSetupNonBlocking,
    runtime: *const Runtime,
) -> PointerResult<SequencerServiceFFI, OperationStatus> {
    let setup = unsafe {
        &setup.read()
    };

    // Use the caller's runtime if one was supplied, otherwise create (and own)
    // our own. The `Runtime` wrapper drops the underlying tokio runtime only
    // when we own it; a borrowed one is left to its external owner.
    let runtime = if runtime.is_null() {
        match Runtime::new() {
            Ok(runtime) => runtime,
            Err(e) =>{
                log::error!("Could not create tokio runtime: {e}");
                return PointerResult::from_error(OperationStatus::InitializationError)
            }
        }
    } else {
        // SAFETY: the caller guarantees `runtime` is valid and outlives the sequencer.
        let caller = unsafe { &*runtime };
        unsafe { Runtime::from_borrowed(caller.as_ref()) }
    };

    let task = unsafe {
        setup.task
                .cast::<JoinHandle<Result<SequencerHandle, OperationStatus>>>()
                .read()          
    };

    let join_resp = runtime.block_on(task);

    match join_resp {
        Ok(task_res) => {
            match task_res {
                Ok(handle) => {
                    PointerResult::from_value(SequencerServiceFFI::new(handle, runtime))
                },
                Err(t_err) => {
                    log::error!("Could not create sequencer handle: {t_err:?}");
                    PointerResult::from_error(OperationStatus::InitializationError)
                }
            }
        },
        Err(j_err) => {
            log::error!("Could not join tokio task: {j_err}");
            PointerResult::from_error(OperationStatus::InitializationError)
        }
    }
}
