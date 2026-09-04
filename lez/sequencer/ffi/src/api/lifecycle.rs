use std::{ffi::c_char, path::PathBuf};

use anyhow::Context;
use kameo::actor::Spawn;
use sequencer_core::{config::SequencerConfig, load_or_create_signing_key};
use sequencer_executor_actor::ExecutorActor;
use sequencer_storage_actor::StorageActor;

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
pub unsafe extern "C" fn start_sequencer(
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

    let gossip_config = config.gossip.clone();
    let bedrock_config = config.bedrock_config.clone();
    let sequencer_home = config.home.clone();
    let max_block_size = config.max_block_size;

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

    let storage = StorageActor::new(&config.db_path())
        .context("Failed to initialize Storage Actor")
        .map_err(|e| {
            log::error!("Could not create sequencer storage: {e}");
            OperationStatus::InitializationError
        })?;
    let storage_ref = StorageActor::spawn(storage);
    log::info!("Storage Actor spawned");

    let executor = runtime.block_on(ExecutorActor::new(config, storage_ref.clone()));

    let mempool_handle = executor.mempool_handle();

    let executor_ref = ExecutorActor::spawn(executor);
    log::info!("Executor Actor spawned");

    // TODO: Should be a separate actor
    let gossip_network = match gossip_config {
        None => None,
        Some(gossip_config) => {
            // The node's L1 bedrock signing key is deliberately reused as the
            // libp2p identity; `GossipNetwork::start` derives the keypair.
            let signing_key = load_or_create_signing_key(
                &sequencer_home.join("bedrock_signing_key"),
            )
            .map_err(|e| {
                log::error!("Could not load signing key: {e}");
                OperationStatus::InitializationError
            })?;
            let channel_id = *bedrock_config.channel_id.as_ref();
            let network = runtime
                .block_on(sequencer_core::gossip::GossipNetwork::start(
                    gossip_config,
                    channel_id,
                    signing_key,
                    mempool_handle,
                    max_block_size.as_u64(),
                ))
                .context("Failed to start sequencer gossip network")
                .map_err(|e| {
                    log::error!("Could not start gossip network: {e}");
                    OperationStatus::InitializationError
                })?;
            log::info!("Gossip network started as {}", network.local_peer_id());
            Some(network)
        }
    };

    Ok(SequencerServiceFFI::new(
        storage_ref,
        executor_ref,
        gossip_network,
        runtime,
    ))
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
pub unsafe extern "C" fn stop_sequencer(sequencer: *mut SequencerServiceFFI) -> OperationStatus {
    if sequencer.is_null() {
        log::error!("Attempted to stop a null sequencer pointer. This is a bug. Aborting.");
        return OperationStatus::NullPointer;
    }

    let sequencer = unsafe { Box::from_raw(sequencer) };
    drop(sequencer);

    OperationStatus::Ok
}
