//! A [`MockStorageActor`] serving a canned store.

use std::sync::{Arc, Mutex, MutexGuard};

use super::{MockStorageActor, StoredValues};

/// What a mocked store holds.
///
/// A clone copies [`Self::values`] too, so it is a snapshot of the store.
#[derive(Default)]
pub struct CannedStore {
    /// Values of generic messages.
    pub values: StoredValues,
}

impl Clone for CannedStore {
    fn clone(&self) -> Self {
        Self {
            values: self.values.deep_clone(),
        }
    }
}

impl CannedStore {
    #[must_use]
    pub fn share(self) -> SharedStore {
        SharedStore {
            store: Arc::new(Mutex::new(self)),
        }
    }
}

/// A [`CannedStore`] every mock built from it serves and writes to, so a test can inspect it and
/// keep it across restarts.
#[derive(Clone, Default)]
pub struct SharedStore {
    store: Arc<Mutex<CannedStore>>,
}

impl SharedStore {
    /// A mock serving every read of this store and applying every write to it.
    #[must_use]
    pub fn mock(&self) -> MockStorageActor {
        MockStorageActor::with_values(self.values())
    }

    /// Values of generic messages every mock built from this store keeps.
    #[must_use]
    pub fn values(&self) -> StoredValues {
        self.lock().values.clone()
    }

    /// # Panics
    ///
    /// If a mock panicked while holding the store.
    pub fn lock(&self) -> MutexGuard<'_, CannedStore> {
        self.store.lock().expect("canned store lock poisoned")
    }
}
