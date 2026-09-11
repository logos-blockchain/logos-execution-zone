use std::ffi::c_void;

use kameo::actor::ActorRef;
use kameo_actors::scheduler::Scheduler;
use sequencer_core::block_publisher::ZoneSdkPublisher;
use sequencer_executor_actor::ExecutorActor;
use sequencer_service::Gossip;
use sequencer_slasher_actor::SlasherActor;
use sequencer_storage_actor::StorageActor;

use crate::Runtime;

/// FFI-owned sequencer.
///
/// - A [`ActorRef<StorageActor>`] used to get acess to db.
/// - A [`ActorRef<SlasherActor>`] right now is unused and exists only for gracial shutdown.
/// - An [`ActorRef<ExecutorActor<StorageActor, ZoneSdkPublisher>>`] used to query the node.
/// - A [`ActorRef<Scheduler>`] right now is unused and exists only for gracial shutdown.
/// - A [`Option<Gossip>`] right now is unused and exists only to pin gossip.
/// - The [`Runtime`] used to run async queries against the store (either owned or borrowed),
///   already FFI-safe.
#[repr(C)]
pub struct SequencerServiceFFI {
    storage_ref: *mut c_void,
    slasher_ref: *mut c_void,
    executor_ref: *mut c_void,
    scheduler_ref: *mut c_void,
    gossip: *mut c_void,
    runtime: Runtime,
}

impl SequencerServiceFFI {
    #[must_use]
    pub fn new(
        storage_ref: ActorRef<StorageActor>,
        slasher_ref: ActorRef<SlasherActor>,
        executor_ref: ActorRef<ExecutorActor<StorageActor, ZoneSdkPublisher>>,
        scheduler_ref: ActorRef<Scheduler>,
        gossip: Option<Gossip>,
        runtime: Runtime,
    ) -> Self {
        Self {
            storage_ref: Box::into_raw(Box::new(storage_ref)).cast::<c_void>(),
            slasher_ref: Box::into_raw(Box::new(slasher_ref)).cast::<c_void>(),
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
    pub const fn executor_ref(&self) -> &ActorRef<ExecutorActor<StorageActor, ZoneSdkPublisher>> {
        unsafe {
            self.executor_ref
                .cast::<ActorRef<ExecutorActor<StorageActor, ZoneSdkPublisher>>>()
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
        if !self.gossip.is_null() {
            let gossip = unsafe { Box::from_raw(self.gossip.cast::<Option<Gossip>>()) };
            // stop the gossip before everyone else.
            drop(gossip);
        }

        if !self.scheduler_ref.is_null() {
            let scheduler_ref =
                unsafe { Box::from_raw(self.scheduler_ref.cast::<ActorRef<Scheduler>>()) };
            // stop the sheduler actor next.
            let send_res = self.runtime.block_on(scheduler_ref.stop_gracefully());
            if let Err(err) = send_res {
                log::error!("Failed to send shutdown signal: {err}");
            }
            drop(scheduler_ref);
        }

        if !self.executor_ref.is_null() {
            let executor_ref = unsafe {
                Box::from_raw(
                    self.executor_ref
                        .cast::<ActorRef<ExecutorActor<StorageActor, ZoneSdkPublisher>>>(),
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
