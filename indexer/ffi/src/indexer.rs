use std::{ffi::c_void, net::SocketAddr};

use indexer_service::IndexerHandle;

use crate::client::IndexerClient;

#[repr(C)]
pub struct IndexerServiceFFI {
    indexer_handle: *mut c_void,
    indexer_client: *mut c_void,
}

impl IndexerServiceFFI {
    #[must_use]
    pub fn new(
        indexer_handle: indexer_service::IndexerHandle,
        indexer_client: IndexerClient,
    ) -> Self {
        Self {
            // Box the complex types and convert to opaque pointers
            indexer_handle: Box::into_raw(Box::new(indexer_handle)).cast::<c_void>(),
            indexer_client: Box::into_raw(Box::new(indexer_client)).cast::<c_void>(),
        }
    }

    /// Helper to take ownership back.
    #[must_use]
    pub fn into_parts(mut self) -> (Box<IndexerHandle>, Box<IndexerClient>) {
        let Self {
            indexer_handle,
            indexer_client,
        } = &mut self;

        let indexer_handle_boxed = unsafe { Box::from_raw(indexer_handle.cast::<IndexerHandle>()) };
        let indexer_client_boxed = unsafe { Box::from_raw(indexer_client.cast::<IndexerClient>()) };

        // Assigning nulls to prevent double free on drop, since ownership is transferred to caller
        *indexer_handle = std::ptr::null_mut();
        *indexer_client = std::ptr::null_mut();

        (indexer_handle_boxed, indexer_client_boxed)
    }

    /// Helper to get indexer handle addr.
    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        let indexer_handle = unsafe {
            self.indexer_handle
                .cast::<IndexerHandle>()
                .as_ref()
                .expect("Indexer Handle must be non-null pointer")
        };

        indexer_handle.addr()
    }

    /// Helper to get indexer handle ref.
    #[must_use]
    pub const fn handle(&self) -> &IndexerHandle {
        unsafe {
            self.indexer_handle
                .cast::<IndexerHandle>()
                .as_ref()
                .expect("Indexer Handle must be non-null pointer")
        }
    }

    /// Helper to get indexer client ref.
    #[must_use]
    pub const fn client(&self) -> &IndexerClient {
        unsafe {
            self.indexer_client
                .cast::<IndexerClient>()
                .as_ref()
                .expect("Indexer Client must be non-null pointer")
        }
    }
}

// Implement Drop to prevent memory leaks
impl Drop for IndexerServiceFFI {
    fn drop(&mut self) {
        let Self {
            indexer_handle,
            indexer_client,
        } = self;

        if !indexer_handle.is_null() {
            drop(unsafe { Box::from_raw(indexer_handle.cast::<IndexerHandle>()) });
        }
        if !indexer_client.is_null() {
            drop(unsafe { Box::from_raw(indexer_client.cast::<IndexerClient>()) });
        }
    }
}
