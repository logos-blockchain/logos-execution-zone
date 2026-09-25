use std::ffi::c_void;

use kameo::actor::ActorRef;
use sequencer_service::{ExecutorActor, SequencerHandle};
use sequencer_storage_actor::StorageActor;

use crate::Runtime;

/// FFI-owned sequencer.
///
/// - `handle`: a [`SequencerHandle`] owning every actor the sequencer runs.
/// - `runtime`: the [`Runtime`] used to run async queries against the node (either owned or
///   borrowed), already FFI-safe.
#[repr(C)]
pub struct SequencerServiceFFI {
    handle: *mut c_void,
    runtime: Runtime,
}

impl SequencerServiceFFI {
    #[must_use]
    pub fn new(handle: SequencerHandle, runtime: Runtime) -> Self {
        Self {
            handle: Box::into_raw(Box::new(handle)).cast::<c_void>(),
            runtime,
        }
    }

    /// Borrow the [`Executor`] to run a query against the node.
    #[must_use]
    pub const fn executor_ref(&self) -> &ActorRef<ExecutorActor> {
        self.handle().executor_ref()
    }

    /// Borrow the [`Storage`] to run a query against the node's db.
    #[must_use]
    pub const fn storage_ref(&self) -> &ActorRef<StorageActor> {
        self.handle().storage_ref()
    }

    /// Borrow the runtime to `block_on` an async query.
    #[must_use]
    pub const fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    const fn handle(&self) -> &SequencerHandle {
        unsafe {
            self.handle
                .cast::<SequencerHandle>()
                .as_ref()
                .expect("SequencerHandle must be a non-null pointer")
        }
    }
}

impl Drop for SequencerServiceFFI {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            let handle = unsafe { Box::from_raw(self.handle.cast::<SequencerHandle>()) };
            // The handle stops the actors in dependency order and waits for each.
            self.runtime.block_on(handle.shutdown());
        }

        // `runtime` field is dropped automatically on return here:
        // - if runtime was owned, it is shutdown at this point
        // - if it was borrowed, it continues to live within the external owner
    }
}
