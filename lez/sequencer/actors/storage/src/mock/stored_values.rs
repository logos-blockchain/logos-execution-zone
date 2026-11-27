//! Values of generic messages, kept in memory by a
//! [`MockStorageActor`](super::MockStorageActor).

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, MutexGuard},
};

use crate::{
    ColumnFamily, Result, Storable,
    error::Error,
    storable::{decode_key, encode_key, key_range, range_bounds},
    writes::{StagedWrite, StagedWrites, Writes},
};

/// Encoded values by column family and encoded key, shared by every clone.
#[derive(Clone, Default)]
pub struct StoredValues(Arc<Mutex<Values>>);

type Values = BTreeMap<(ColumnFamily, Vec<u8>), Vec<u8>>;

impl StoredValues {
    pub fn get<T: Storable>(&self, key: &T::Key) -> Result<Option<T>> {
        self.lock()
            .get(&(T::COLUMN_FAMILY, encode_key::<T>(key)))
            .map(|bytes| decode(bytes))
            .transpose()
    }

    pub fn store<T: Storable>(&self, key: &T::Key, value: &T) -> Result<()> {
        let bytes = borsh::to_vec(value).map_err(Error::Encoding)?;
        self.lock()
            .insert((T::COLUMN_FAMILY, encode_key::<T>(key)), bytes);
        Ok(())
    }

    pub fn delete<T: Storable>(&self, key: &T::Key) {
        self.lock()
            .remove(&(T::COLUMN_FAMILY, encode_key::<T>(key)));
    }

    /// Up to `limit` values of `T`, from `start` to `end`, both included if stored.
    pub fn range<T: Storable>(
        &self,
        start: Option<&T::Key>,
        end: Option<&T::Key>,
        limit: usize,
    ) -> Result<Vec<T>> {
        let entries = self.read_range::<T>(start.map(encode_key::<T>), end, limit)?;
        Ok(entries.into_iter().map(|(_key, value)| value).collect())
    }

    /// Up to `limit` values of `T` with their keys, from the encoded `start` to `end`.
    pub(crate) fn read_range<T: Storable>(
        &self,
        start: Option<Vec<u8>>,
        end: Option<&T::Key>,
        limit: usize,
    ) -> Result<Vec<(T::Key, T)>> {
        let bounds = range_bounds::<T>(start, end);
        if bounds.start >= bounds.end {
            return Ok(Vec::new());
        }
        self.lock()
            .range((T::COLUMN_FAMILY, bounds.start)..(T::COLUMN_FAMILY, bounds.end))
            .take(limit)
            .map(|((_family, key), bytes)| decode_entry::<T>(key, bytes))
            .collect()
    }

    /// The `T` with the highest key, with its key.
    pub fn last<T: Storable>(&self) -> Result<Option<(T::Key, T)>> {
        let keys = key_range::<T>();
        self.lock()
            .range((T::COLUMN_FAMILY, keys.start)..(T::COLUMN_FAMILY, keys.end))
            .next_back()
            .map(|((_family, key), bytes)| decode_entry::<T>(key, bytes))
            .transpose()
    }

    /// A copy of the values held now, not shared with this one.
    #[must_use]
    pub fn deep_clone(&self) -> Self {
        Self(Arc::new(Mutex::new(self.lock().clone())))
    }

    #[must_use]
    pub fn count<T: Storable>(&self) -> usize {
        let keys = key_range::<T>();
        self.lock()
            .range((T::COLUMN_FAMILY, keys.start)..(T::COLUMN_FAMILY, keys.end))
            .count()
    }

    /// Applies every write of `writes` in order, or none if a value fails to encode.
    pub fn write(&self, writes: &dyn Writes) -> Result<()> {
        let mut staged = StagedWrites::new();
        writes.write_to(&mut staged)?;

        let mut values = self.lock();
        for StagedWrite {
            column_family,
            key,
            value,
        } in staged.writes
        {
            match value {
                Some(value) => values.insert((column_family, key), value),
                None => values.remove(&(column_family, key)),
            };
        }
        Ok(())
    }

    fn lock(&self) -> MutexGuard<'_, Values> {
        self.0
            .lock()
            .expect("Stored values lock must not be poisoned")
    }
}

fn decode<T: Storable>(bytes: &[u8]) -> Result<T> {
    T::try_from_slice(bytes).map_err(Error::Encoding)
}

/// The key and the value of a `T` stored as `encoded_key` and `bytes`.
fn decode_entry<T: Storable>(encoded_key: &[u8], bytes: &[u8]) -> Result<(T::Key, T)> {
    let key = decode_key::<T>(encoded_key).ok_or(Error::KeyDecoding(T::TYPE_NAME))?;
    Ok((key, decode(bytes)?))
}
