use std::{ffi::c_char, path::PathBuf};

use anyhow::Context as _;
use kameo::actor::{ActorRef, Spawn as _};
use kameo_actors::scheduler::{Scheduler, SetInterval};
use sequencer_core::{
    block_publisher::ZoneSdkPublisher, config::SequencerConfig, gossip::GossipNetwork,
    load_or_create_signing_key,
};
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

async fn make_sequencer_compoments(
    config: SequencerConfig,
) -> Result<
    (
        ActorRef<StorageActor>,
        ActorRef<ExecutorActor<StorageActor, ZoneSdkPublisher>>,
        Option<GossipNetwork>,
        ActorRef<Scheduler>,
    ),
    OperationStatus,
> {
    let block_timeout = config.block_create_timeout;
    let gossip_config = config.gossip.clone();
    let bedrock_config = config.bedrock_config.clone();
    let sequencer_home = config.home.clone();
    let max_block_size = config.max_block_size;

    let storage = StorageActor::new(&config.db_path())
        .context("Failed to initialize Storage Actor")
        .map_err(|e| {
            log::error!("Could not create sequencer storage: {e}");
            OperationStatus::InitializationError
        })?;
    let storage_ref = StorageActor::spawn(storage);
    log::info!("Storage Actor spawned");

    let executor = ExecutorActor::new(config, storage_ref.clone()).await;
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
            // Gossiped transactions enter through the executor's admission
            // door (fee screen + mempool push), same as RPC submissions —
            // gossip never touches the mempool directly.
            let submit_ref = executor_ref.clone();
            let submit: sequencer_core::gossip::IngestSubmit =
                std::sync::Arc::new(move |transaction| {
                    let executor_submit_ref = submit_ref.clone();
                    Box::pin(async move {
                        use sequencer_executor_actor::protocol::{Transaction, TransactionOrigin};
                        let message = Transaction {
                            transaction,
                            origin: TransactionOrigin::Gossip,
                        };
                        executor_submit_ref.ask(message).await.map_err(Into::into)
                    })
                });

            let network = sequencer_core::gossip::GossipNetwork::start(
                gossip_config,
                channel_id,
                signing_key,
                max_block_size.as_u64(),
                submit,
            )
            .await
            .context("Failed to start sequencer gossip network")
            .map_err(|e| {
                log::error!("Could not start gossip network: {e}");
                OperationStatus::InitializationError
            })?;
            log::info!("Gossip network started as {}", network.local_peer_id());
            Some(network)
        }
    };

    let scheduler_ref = Scheduler::spawn(Scheduler::new());
    scheduler_ref
        .tell(
            SetInterval::new(
                executor_ref.downgrade(),
                block_timeout,
                sequencer_executor_actor::protocol::ProduceBlock,
            )
            .start_delay(block_timeout)
            .set_missed_tick_behaviour(tokio::time::MissedTickBehavior::Delay),
        )
        .await
        .map_err(|e| {
            log::error!("Could not start sheduler actor: {e}");
            OperationStatus::InitializationError
        })?;
    log::info!("Block production scheduler started");

    Ok((storage_ref, executor_ref, gossip_network, scheduler_ref))
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

    let (storage_ref, executor_ref, gossip_network, scheduler_ref) =
        runtime.block_on(make_sequencer_compoments(config))?;

    Ok(SequencerServiceFFI::new(
        storage_ref,
        executor_ref,
        gossip_network,
        scheduler_ref,
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

    log::info!("=================== DESTRUCTION: SEQUENCER BOXED");

    drop(sequencer);

    OperationStatus::Ok
}
