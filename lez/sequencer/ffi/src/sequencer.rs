use std::ffi::c_void;

use sequencer_core::block_publisher::ZoneSdkPublisher;
use sequencer_executor_actor::ExecutorActor;
use sequencer_storage_actor::StorageActor;

use crate::Runtime;

/// FFI-owned sequencer.
///
/// - A [`StorageActor`] used to get acess to db.
/// - An [`ExecutorActor`] used to query the node.
/// - The [`Runtime`] used to run async queries against the store (either owned or borrowed),
///   already FFI-safe.
#[repr(C)]
pub struct SequencerServiceFFI {
    storage_actor: *mut c_void,
    executor_actor: *mut c_void,
    runtime: Runtime,
}

impl SequencerServiceFFI {
    #[must_use]
    pub fn new(storage_actor: StorageActor, executor_actor: ExecutorActor<ZoneSdkPublisher, StorageActor>, runtime: Runtime) -> Self {
        Self {
            storage_actor: Box::into_raw(Box::new(storage_actor)).cast::<c_void>(),
            executor_actor: Box::into_raw(Box::new(executor_actor)).cast::<c_void>(),
            runtime,
        }
    }

    /// Borrow the [`StorageActor`] to run a query against the store.
    #[must_use]
    pub const fn storage_actor(&self) -> &StorageActor {
        unsafe {
            self.storage_actor
                .cast::<StorageActor>()
                .as_ref()
                .expect("StorageActor must be a non-null pointer")
        }
    }

    /// Borrow the [`ExecutorActor`] to run a query against the node.
    #[must_use]
    pub const fn executor_actor(&self) -> &ExecutorActor<ZoneSdkPublisher, StorageActor> {
        unsafe {
            self.executor_actor
                .cast::<ExecutorActor<ZoneSdkPublisher, StorageActor>>()
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
        if !self.executor_actor.is_null() {
            let executor_actor = unsafe { Box::from_raw(self.executor_actor.cast::<ExecutorActor<ZoneSdkPublisher, StorageActor>>()) };
            // stop the executor actor before storage.
            drop(executor_actor);
        }
        if !self.storage_actor.is_null() {
            let storage_actor = unsafe { Box::from_raw(self.executor_actor.cast::<StorageActor>()) };
            drop(storage_actor);
        }

        // `runtime` field is dropped automatically on return here:
        // - if runtime was owned, it is shutdown at this point
        // - if it was borrowed, it continues to live within the external owner
    }
}
