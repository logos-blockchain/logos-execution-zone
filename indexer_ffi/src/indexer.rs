use std::ffi::c_void;

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

    // Helper to safely take ownership back
    #[must_use]
    pub fn into_parts(self) -> (Box<IndexerHandle>, Box<Runtime>) {
        let overwatch = unsafe { Box::from_raw(self.indexer_handle.cast::<IndexerHandle>()) };
        let runtime = unsafe { Box::from_raw(self.runtime.cast::<Runtime>()) };
        (overwatch, runtime)
    }
}

// Implement Drop to prevent memory leaks
impl Drop for IndexerServiceFFI {
    fn drop(&mut self) {
        if self.indexer_handle.is_null() {
            log::error!("Attempted to drop a null indexer pointer. This is a bug");
        }
        if self.runtime.is_null() {
            log::error!("Attempted to drop a null tokio runtime pointer. This is a bug");
        }
        drop(unsafe { Box::from_raw(self.indexer_handle.cast::<IndexerHandle>()) });
        drop(unsafe { Box::from_raw(self.runtime.cast::<Runtime>()) });
    }
}
