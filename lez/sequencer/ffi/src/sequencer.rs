use std::ffi::c_void;

use kameo::actor::ActorRef;
use kameo_actors::{broker::Broker, scheduler::Scheduler};
use sequencer_bedrock_actor::{BedrockActor, BedrockActorTrait, protocol::ChannelEvent};
use sequencer_executor_actor::ExecutorActor;
use sequencer_service::Gossip;
use sequencer_slasher_actor::SlasherActor;
use sequencer_storage_actor::StorageActor;

use crate::Runtime;

/// FFI-owned sequencer.
///
/// - `storage_ref`: an [`ActorRef<StorageActor>`] used to get acess to db.
/// - `slasher_ref`: an [`ActorRef<SlasherActor>`] right now is unused and exists only for gracial
///   shutdown.
/// - `bedrock_ref`: an [`ActorRef<BedrockActor>`] right now is unused and exists only for gracial
///   shutdown.
/// - `bedrock_broker_ref`: an [`ActorRef<Broker<ChannelEvent>>`] right now is unused and exists
///   only for gracial shutdown.
/// - `executor_ref`: an [`ActorRef<ExecutorActor<StorageActor, BedrockActor>>`] used to query the
///   node.
/// - `scheduler_ref`: an [`ActorRef<Scheduler>`] right now is unused and exists only for gracial
///   shutdown.
/// - `gossip`: an [`Option<Gossip>`] right now is unused and exists only to pin gossip.
/// - `runtime`: the [`Runtime`] used to run async queries against the store (either owned or
///   borrowed), already FFI-safe.
#[repr(C)]
pub struct SequencerServiceFFI {
    storage_ref: *mut c_void,
    slasher_ref: *mut c_void,
    bedrock_ref: *mut c_void,
    bedrock_broker_ref: *mut c_void,
    executor_ref: *mut c_void,
    scheduler_ref: *mut c_void,
    gossip: *mut c_void,
    runtime: Runtime,
}

impl SequencerServiceFFI {
    #[must_use]
    #[expect(
        clippy::too_many_arguments,
        reason = "Every actor the sequencer owns has to be handed over for graceful shutdown"
    )]
    pub fn new(
        storage_ref: ActorRef<StorageActor>,
        slasher_ref: ActorRef<SlasherActor>,
        bedrock_ref: ActorRef<BedrockActor>,
        bedrock_broker_ref: ActorRef<Broker<ChannelEvent>>,
        executor_ref: ActorRef<ExecutorActor<StorageActor, impl BedrockActorTrait + 'static>>,
        scheduler_ref: ActorRef<Scheduler>,
        gossip: Option<Gossip>,
        runtime: Runtime,
    ) -> Self {
        Self {
            storage_ref: Box::into_raw(Box::new(storage_ref)).cast::<c_void>(),
            slasher_ref: Box::into_raw(Box::new(slasher_ref)).cast::<c_void>(),
            bedrock_ref: Box::into_raw(Box::new(bedrock_ref)).cast::<c_void>(),
            bedrock_broker_ref: Box::into_raw(Box::new(bedrock_broker_ref)).cast::<c_void>(),
            executor_ref: Box::into_raw(Box::new(executor_ref)).cast::<c_void>(),
            scheduler_ref: Box::into_raw(Box::new(scheduler_ref)).cast::<c_void>(),
            gossip: Box::into_raw(Box::new(gossip)).cast::<c_void>(),
            runtime,
        }
    }

    /// Borrow the [`StorageActor`] to run a query against the store.
    #[must_use]
    pub const fn storage_ref(&self) -> &ActorRef<StorageActor> {
        unsafe {
            self.storage_ref
                .cast::<ActorRef<StorageActor>>()
                .as_ref()
                .expect("StorageActor must be a non-null pointer")
        }
    }

    /// Borrow the [`ExecutorActor`] to run a query against the node.
    #[must_use]
    pub const fn executor_ref(&self) -> &ActorRef<ExecutorActor<StorageActor, BedrockActor>> {
        unsafe {
            self.executor_ref
                .cast::<ActorRef<ExecutorActor<StorageActor, BedrockActor>>>()
                .as_ref()
                .expect("ExecutorActor must be a non-null pointer")
        }
    }

    /// Borrow the runtime to `block_on` an async store query.
    #[must_use]
    pub const fn runtime(&self) -> &Runtime {
        &self.runtime
    }
}

impl Drop for SequencerServiceFFI {
    fn drop(&mut self) {
        if !self.scheduler_ref.is_null() {
            let scheduler_ref =
                unsafe { Box::from_raw(self.scheduler_ref.cast::<ActorRef<Scheduler>>()) };
            // stop the sheduler first.
            let send_res = self.runtime.block_on(scheduler_ref.stop_gracefully());
            if let Err(err) = send_res {
                log::error!("Failed to send shutdown signal: {err}");
            }
            drop(scheduler_ref);
        }

        if !self.gossip.is_null() {
            let gossip = unsafe { Box::from_raw(self.gossip.cast::<Option<Gossip>>()) };
            // stop the gossip next.
            drop(gossip);
        }

        if !self.bedrock_broker_ref.is_null() {
            let bedrock_broker_ref = unsafe {
                Box::from_raw(
                    self.bedrock_broker_ref
                        .cast::<ActorRef<Broker<ChannelEvent>>>(),
                )
            };
            // stop the broker before the actors it fans out to.
            let send_res = self.runtime.block_on(bedrock_broker_ref.stop_gracefully());
            if let Err(err) = send_res {
                log::error!("Failed to send shutdown signal: {err}");
            }
            drop(bedrock_broker_ref);
        }

        if !self.executor_ref.is_null() {
            let executor_ref = unsafe {
                Box::from_raw(
                    self.executor_ref
                        .cast::<ActorRef<ExecutorActor<StorageActor, BedrockActor>>>(),
                )
            };
            // stop the executor actor before slasher.
            let send_res = self.runtime.block_on(executor_ref.stop_gracefully());
            if let Err(err) = send_res {
                log::error!("Failed to send shutdown signal: {err}");
            }
            drop(executor_ref);
        }

        if !self.slasher_ref.is_null() {
            let slasher_ref =
                unsafe { Box::from_raw(self.slasher_ref.cast::<ActorRef<SlasherActor>>()) };
            // stop the slasher actor before storage.
            let send_res = self.runtime.block_on(slasher_ref.stop_gracefully());
            if let Err(err) = send_res {
                log::error!("Failed to send shutdown signal: {err}");
            }
            drop(slasher_ref);
        }

        if !self.bedrock_ref.is_null() {
            let bedrock_ref =
                unsafe { Box::from_raw(self.bedrock_ref.cast::<ActorRef<BedrockActor>>()) };
            // stop the bedrock actor before storage, which it writes through.
            let send_res = self.runtime.block_on(bedrock_ref.stop_gracefully());
            if let Err(err) = send_res {
                log::error!("Failed to send shutdown signal: {err}");
            }
            drop(bedrock_ref);
        }

        if !self.storage_ref.is_null() {
            let storage_ref =
                unsafe { Box::from_raw(self.storage_ref.cast::<ActorRef<StorageActor>>()) };

            let send_res = self.runtime.block_on(storage_ref.stop_gracefully());
            if let Err(err) = send_res {
                log::error!("Failed to send shutdown signal: {err}");
            }
            drop(storage_ref);
        }

        // `runtime` field is dropped automatically on return here:
        // - if runtime was owned, it is shutdown at this point
        // - if it was borrowed, it continues to live within the external owner
    }
}
