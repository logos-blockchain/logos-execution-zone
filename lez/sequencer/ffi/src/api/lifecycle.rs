use std::{ffi::c_char, path::PathBuf};

use anyhow::Context as _;
use glob::Pattern;
use kameo::actor::{ActorRef, Spawn as _};
use kameo_actors::{
    DeliveryStrategy,
    broker::{Broker, Subscribe},
    scheduler::{Scheduler, SetInterval},
};
use sequencer_bedrock_actor::{BedrockActor, protocol::ChannelEvent};
use sequencer_channel_config_actor::SetSubmitter;
use sequencer_core::{SubmitConfig, config::SequencerConfig, load_or_create_signing_key};
use sequencer_executor_actor::ExecutorActor;
use sequencer_service::{Gossip, setup_gossip};
use sequencer_slasher_actor::SlasherActor;
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

/// Creates all components of sequencer service except RPC.
///
/// TODO: Make RPC construction optional. Probably needs modification of configs to be alighned
/// with mainline sequencer.
async fn make_sequencer_compoments(
    config: SequencerConfig,
) -> Result<
    (
        ActorRef<StorageActor>,
        ActorRef<SlasherActor>,
        ActorRef<BedrockActor>,
        ActorRef<Broker<ChannelEvent>>,
        ActorRef<ExecutorActor<StorageActor, BedrockActor>>,
        ActorRef<Scheduler>,
        Option<Gossip>,
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

    // Prepared up front so the broker has a subscriber before the bedrock actor
    // starts publishing channel events.
    let executor_prepared = ExecutorActor::prepare_with_mailbox(kameo::mailbox::unbounded());

    let bedrock_broker_ref = Broker::spawn(Broker::new(DeliveryStrategy::Guaranteed));
    let topic =
        Pattern::new(&format!("channel/{}/*", bedrock_config.channel_id)).expect("Valid pattern");
    bedrock_broker_ref
        .tell(Subscribe {
            topic,
            recipient: executor_prepared.actor_ref().clone().recipient(),
        })
        .await
        .map_err(|e| {
            log::error!("Could not subscribe executor to the bedrock broker: {e}");
            OperationStatus::InitializationError
        })?;
    log::info!("Bedrock Broker Actor spawned");

    let bedrock = setup_bedrock_actor(&config, storage_ref.clone(), bedrock_broker_ref.clone())
        .await
        .map_err(|e| {
            log::error!("Could not create bedrock actor: {e}");
            OperationStatus::InitializationError
        })?;
    let bedrock_ref = BedrockActor::spawn(bedrock);
    log::info!("Bedrock Actor spawned");

    let executor = ExecutorActor::new(config, storage_ref.clone(), bedrock_ref.clone())
        .await
        .map_err(|e| {
            log::error!("Could not create executor actor: {e}");
            OperationStatus::InitializationError
        })?;
    let slasher_ref = executor.slasher_ref();
    let config_manager_ref = executor.config_manager_ref();
    // The core has already read a committee by the time this returns.
    let accredited_keys_rx = executor.accredited_keys_watch();
    let staked_keys_rx = executor.staked_keys_watch();
    let executor_ref = executor_prepared.actor_ref().clone();
    executor_prepared.spawn(executor);
    log::info!("Executor Actor spawned");

    // A config needs no turn, so the actor tells the executor to submit it
    // the moment the signatures are in. Weak, because the executor owns
    // the actor that holds this.
    config_manager_ref
        .tell(SetSubmitter(
            executor_ref.clone().recipient::<SubmitConfig>().downgrade(),
        ))
        .await
        .map_err(|e| {
            log::error!("Could not start config manager actor: {e}");
            OperationStatus::InitializationError
        })?;

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

    let (gossip, _) = match gossip_config {
        None => None,
        Some(gossip_config) => Some(
            setup_gossip(
                gossip_config,
                *bedrock_config.channel_id.as_ref(),
                &sequencer_home,
                max_block_size.as_u64(),
                accredited_keys_rx,
                staked_keys_rx,
                &executor_ref,
                &slasher_ref,
                &config_manager_ref,
                &scheduler_ref,
            )
            .await
            .map_err(|e| {
                log::error!("Could not setup gossip: {e}");
                OperationStatus::InitializationError
            })?,
        ),
    }
    .unzip();

    Ok((
        storage_ref,
        slasher_ref,
        bedrock_ref,
        bedrock_broker_ref,
        executor_ref,
        scheduler_ref,
        gossip,
    ))
}

/// Builds the actor that talks to bedrock, loading (or creating) the key it signs with.
async fn setup_bedrock_actor(
    config: &SequencerConfig,
    storage_ref: ActorRef<StorageActor>,
    bedrock_broker_ref: ActorRef<Broker<ChannelEvent>>,
) -> sequencer_bedrock_actor::Result<BedrockActor> {
    let bedrock_signing_key = load_or_create_signing_key(&config.home.join("bedrock_signing_key"))
        .expect("Failed to load or create bedrock signing key");

    let bedrock_actor_config = sequencer_bedrock_actor::config::Config {
        node_url: config.bedrock_config.node_url.clone(),
        basic_auth: config.bedrock_config.auth.clone().map(Into::into),
        channel_id: config.bedrock_config.channel_id,
        bedrock_signing_key,
        funding_pk: config.bedrock_config.funding_key,
        priority_fee_percent: config.bedrock_config.priority_fee_percent,
        resubmit_interval: config.retry_pending_blocks_timeout,
    };

    BedrockActor::new(bedrock_actor_config, storage_ref, bedrock_broker_ref).await
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

    let (
        storage_ref,
        slasher_ref,
        bedrock_ref,
        bedrock_broker_ref,
        executor_ref,
        scheduler_ref,
        gossip,
    ) = runtime.block_on(make_sequencer_compoments(config))?;

    Ok(SequencerServiceFFI::new(
        storage_ref,
        slasher_ref,
        bedrock_ref,
        bedrock_broker_ref,
        executor_ref,
        scheduler_ref,
        gossip,
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
