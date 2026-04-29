use std::{ffi::c_void, net::SocketAddr};

use indexer_service::IndexerHandle;
use sequencer_core::indexer_client::IndexerClient;
use tokio::runtime::Runtime;

#[repr(C)]
pub struct IndexerServiceFFI {
    indexer_handle: *mut c_void,
    runtime: *mut c_void,
    indexer_client: *mut c_void,
}

impl IndexerServiceFFI {
    pub fn new(
        indexer_handle: indexer_service::IndexerHandle,
        runtime: Runtime,
        indexer_client: IndexerClient,
    ) -> Self {
        Self {
            // Box the complex types and convert to opaque pointers
            indexer_handle: Box::into_raw(Box::new(indexer_handle)).cast::<c_void>(),
            runtime: Box::into_raw(Box::new(runtime)).cast::<c_void>(),
            indexer_client: Box::into_raw(Box::new(indexer_client)).cast::<c_void>(),
        }
    }

    /// Helper to take ownership back.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `self` is a valid object(contains valid pointers in all fields)
    #[must_use]
    pub unsafe fn into_parts(self) -> (Box<IndexerHandle>, Box<Runtime>, Box<IndexerClient>) {
        let indexer_handle = unsafe { Box::from_raw(self.indexer_handle.cast::<IndexerHandle>()) };
        let runtime = unsafe { Box::from_raw(self.runtime.cast::<Runtime>()) };
        let indexer_client = unsafe { Box::from_raw(self.indexer_client.cast::<IndexerClient>()) };
        (indexer_handle, runtime, indexer_client)
    }

    /// Helper to get indexer handle addr.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `self` is a valid object(contains valid pointers in all fields)
    #[must_use]
    pub const unsafe fn addr(&self) -> SocketAddr {
        let indexer_handle = unsafe {
            self.indexer_handle
                .cast::<IndexerHandle>()
                .as_ref()
                .expect("Indexer Handle must be non-null pointer")
        };

        indexer_handle.addr()
    }

    /// Helper to get indexer handle ref.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `self` is a valid object(contains valid pointers in all fields)
    #[must_use]
    pub const unsafe fn handle(&self) -> &IndexerHandle {
        unsafe {
            self.indexer_handle
                .cast::<IndexerHandle>()
                .as_ref()
                .expect("Indexer Handle must be non-null pointer")
        }
    }

    /// Helper to get indexer client ref.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `self` is a valid object(contains valid pointers in all fields)
    #[must_use]
    pub const unsafe fn client(&self) -> &IndexerClient {
        unsafe {
            self.indexer_client
                .cast::<IndexerClient>()
                .as_ref()
                .expect("Indexer Client must be non-null pointer")
        }
    }

    /// Helper to get indexer runtime ref.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `self` is a valid object(contains valid pointers in all fields)
    #[must_use]
    pub const unsafe fn runtime(&self) -> &Runtime {
        unsafe {
            self.runtime
                .cast::<Runtime>()
                .as_ref()
                .expect("Indexer Runtime must be non-null pointer")
        }
    }
}

// Implement Drop to prevent memory leaks
impl Drop for IndexerServiceFFI {
    fn drop(&mut self) {
        let Self {
            indexer_handle,
            runtime,
            indexer_client,
        } = self;

        if indexer_handle.is_null() {
            log::error!("Attempted to drop a null indexer pointer. This is a bug");
        }
        if runtime.is_null() {
            log::error!("Attempted to drop a null tokio runtime pointer. This is a bug");
        }
        if indexer_client.is_null() {
            log::error!("Attempted to drop a null client pointer. This is a bug");
        }
        drop(unsafe { Box::from_raw(indexer_handle.cast::<IndexerHandle>()) });
        drop(unsafe { Box::from_raw(runtime.cast::<Runtime>()) });
        drop(unsafe { Box::from_raw(indexer_client.cast::<IndexerClient>()) });
    }
}
