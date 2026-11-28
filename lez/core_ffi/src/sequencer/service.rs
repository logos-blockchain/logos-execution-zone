use std::{ffi::c_void, sync::Arc};

use kameo::actor::ActorRef;
use sequencer_gossip_actor::GossipActor;
use sequencer_service::{ExecutorActor, SequencerHandle, ops::OpsServer};
use sequencer_storage_actor::StorageActor;

use crate::primitives::runtime::Runtime;

/// FFI-owned sequencer.
///
/// - `handle`: the [`SequencerHandle`] owning every actor the sequencer runs, with the ops server
///   serving its health and metrics, if any.
/// - `runtime`: the [`Runtime`] used to run async queries against the node (either owned or
///   borrowed), already FFI-safe.
#[repr(C)]
pub struct SequencerServiceFFI {
    handle: *mut c_void,
    runtime: Runtime,
}

/// What `SequencerServiceFFI::handle` points to.
struct Inner {
    handle: Arc<SequencerHandle>,
    ops: Option<OpsServer>,
}

impl SequencerServiceFFI {
    /// Owns the sequencer behind `handle`, and the ops server serving its health and metrics.
    #[must_use]
    pub fn new(handle: Arc<SequencerHandle>, ops: Option<OpsServer>, runtime: Runtime) -> Self {
        Self {
            handle: Box::into_raw(Box::new(Inner { handle, ops })).cast::<c_void>(),
            runtime,
        }
    }

    /// Whether every task of the sequencer is still running.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.handle().is_healthy()
    }

    /// Borrow the [`Executor`] to run a query against the node.
    #[must_use]
    pub fn executor_ref(&self) -> &ActorRef<ExecutorActor> {
        self.handle().executor_ref()
    }

    /// Borrow the gossip handle for specific gossip requests.
    #[must_use]
    pub fn gossip_ref(&self) -> Option<&ActorRef<GossipActor>> {
        self.handle().gossip_ref()
    }

    /// Borrow the [`Storage`] to run a query against the node's db.
    #[must_use]
    pub fn storage_ref(&self) -> &ActorRef<StorageActor> {
        self.handle().storage_ref()
    }

    /// Borrow the runtime to `block_on` an async query.
    #[must_use]
    pub const fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    fn handle(&self) -> &SequencerHandle {
        unsafe {
            &self
                .handle
                .cast::<Inner>()
                .as_ref()
                .expect("SequencerHandle must be a non-null pointer")
                .handle
        }
    }
}

impl Drop for SequencerServiceFFI {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            let Inner { handle, ops } = *unsafe { Box::from_raw(self.handle.cast::<Inner>()) };
            self.runtime.block_on(async move {
                // Stop serving `/health` before the sequencer behind it goes away.
                if let Some(ops) = ops {
                    ops.stop().await;
                }
                // The handle stops the actors in dependency order and waits for each. The ops
                // server only holds a `Weak`, so this is the last strong reference; never panic
                // here regardless, as this runs under an `extern "C"` fn.
                if let Some(handle) = Arc::into_inner(handle) {
                    handle.shutdown().await;
                } else {
                    tracing::error!(
                        "Sequencer handle still shared, dropping it without waiting for shutdown"
                    );
                }
            });
        }

        // `runtime` field is dropped automatically on return here:
        // - if runtime was owned, it is shutdown at this point
        // - if it was borrowed, it continues to live within the external owner
    }
}
