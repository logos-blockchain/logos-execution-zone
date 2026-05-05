use std::{ffi::c_void, net::SocketAddr};

use indexer_service::IndexerHandle;
use tokio::runtime::Runtime;

#[repr(C)]
pub struct IndexerServiceFFI {
    indexer_handle: *mut c_void,
    runtime: *mut c_void,
}

impl IndexerServiceFFI {
    pub fn new(indexer_handle: indexer_service::IndexerHandle, runtime: Runtime) -> Self {
        Self {
            // Box the complex types and convert to opaque pointers
            indexer_handle: Box::into_raw(Box::new(indexer_handle)).cast::<c_void>(),
            runtime: Box::into_raw(Box::new(runtime)).cast::<c_void>(),
        }
    }

    /// Helper to take ownership back.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `self` is a valid object(contains valid pointers in all fields)
    #[must_use]
    pub unsafe fn into_parts(mut self) -> (Box<IndexerHandle>, Box<Runtime>) {
        let Self {
            indexer_handle,
            runtime,
        } = &mut self;

        let indexer_handle_boxed = unsafe { Box::from_raw(indexer_handle.cast::<IndexerHandle>()) };
        let runtime_boxed = unsafe { Box::from_raw(runtime.cast::<Runtime>()) };

        // Assigning nulls to prevent double free on drop, since ownership is transferred to caller
        *indexer_handle = std::ptr::null_mut();
        *runtime = std::ptr::null_mut();

        (indexer_handle_boxed, runtime_boxed)
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

    /// Helper to get indexer handle addr.
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
}

// Implement Drop to prevent memory leaks
impl Drop for IndexerServiceFFI {
    fn drop(&mut self) {
        let Self {
            indexer_handle,
            runtime,
        } = self;

        if !indexer_handle.is_null() {
            drop(unsafe { Box::from_raw(indexer_handle.cast::<IndexerHandle>()) });
        }
        if !runtime.is_null() {
            drop(unsafe { Box::from_raw(runtime.cast::<Runtime>()) });
        }
    }
}
