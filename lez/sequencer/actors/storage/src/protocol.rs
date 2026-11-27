use std::marker::PhantomData;

use crate::{Storable, encoding::SingletonKey, writes::Writes};

/// Stores `value` under `key`, replacing what was stored there.
pub struct Store<T: Storable> {
    pub key: T::Key,
    pub value: T,
}

impl<T: Storable> Store<T> {
    pub const fn new(key: T::Key, value: T) -> Self {
        Self { key, value }
    }
}

impl<T: Storable<Key = SingletonKey>> Store<T> {
    pub const fn from_value(value: T) -> Self {
        Self::new(SingletonKey, value)
    }
}

pub struct Get<T: Storable> {
    pub key: T::Key,
}

impl<T: Storable> Get<T> {
    pub const fn new(key: T::Key) -> Self {
        Self { key }
    }
}

impl<T: Storable<Key = SingletonKey>> Default for Get<T> {
    fn default() -> Self {
        Self::new(SingletonKey)
    }
}

pub struct Delete<T: Storable> {
    pub key: T::Key,
}

impl<T: Storable> Delete<T> {
    pub const fn new(key: T::Key) -> Self {
        Self { key }
    }
}

impl<T: Storable<Key = SingletonKey>> Default for Delete<T> {
    fn default() -> Self {
        Self::new(SingletonKey)
    }
}

/// Up to `limit` values of `T` with their keys, in key order from `start` to `end`.
pub struct GetRange<T: Storable> {
    pub start: RangeStart<T>,
    /// Key to stop at, included if stored. `None` stops at the last key.
    pub end: Option<T::Key>,
    pub limit: usize,
}

impl<T: Storable> GetRange<T> {
    /// From `start` to `end`, both included if stored. `None` starts from the first key, or stops
    /// at the last one.
    pub fn new(start: Option<T::Key>, end: Option<T::Key>, limit: usize) -> Self {
        Self {
            start: start.map_or(RangeStart::First, RangeStart::At),
            end,
            limit,
        }
    }

    /// From the key past `last_key`, the key of the last entry of the range before, to `end`.
    pub const fn after(last_key: T::Key, end: Option<T::Key>, limit: usize) -> Self {
        Self {
            start: RangeStart::After(last_key),
            end,
            limit,
        }
    }
}

/// Where a [`GetRange`] starts.
pub enum RangeStart<T: Storable> {
    /// At the first key.
    First,
    /// At the key, included if stored.
    At(T::Key),
    /// Past the key, not included.
    After(T::Key),
}

/// The `T` with the lowest key, with its key.
pub struct GetFirst<T: Storable>(PhantomData<fn() -> T>);

impl<T: Storable> GetFirst<T> {
    #[must_use]
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<T: Storable> Default for GetFirst<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// The `T` with the highest key, with its key.
pub struct GetLast<T: Storable>(PhantomData<fn() -> T>);

impl<T: Storable> GetLast<T> {
    #[must_use]
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<T: Storable> Default for GetLast<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// How many `T` are stored, counted without decoding any of them.
pub struct Count<T: Storable>(PhantomData<fn() -> T>);

impl<T: Storable> Count<T> {
    #[must_use]
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<T: Storable> Default for Count<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Writes committed together or not at all.
///
/// Its type names the shape of the writes, e.g. `WriteBatch<(Store<A>, Vec<Delete<B>>)>`.
pub struct WriteBatch<W: Writes>(pub W);

pub struct DumpDb;

/// Schema-agnostic snapshot of a whole store, opaque by design.
pub struct DbDump {
    pub bytes: Vec<u8>,
}
