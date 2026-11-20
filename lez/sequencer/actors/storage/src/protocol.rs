use std::marker::PhantomData;

use crate::{
    ColumnFamily, Storable,
    encoding::SingletonKey,
    storable::{DynStorable, encode_key},
};

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

/// [`Store`] and [`Delete`] messages of any stored types, committed together
/// or not at all.
///
/// Writes are applied in the order they were added, so a later write to a key
/// replaces an earlier one.
#[derive(Default)]
pub struct WriteBatch {
    pub(crate) writes: Vec<Write>,
}

/// One message of a [`WriteBatch`].
///
/// Keys are already prefixed with the name of their type.
#[cfg_attr(
    not(any(feature = "actor", feature = "mock")),
    expect(dead_code, reason = "Only the actor and its mock read the writes")
)]
pub(crate) enum Write {
    Store {
        key: Vec<u8>,
        value: Box<dyn DynStorable>,
    },
    Delete {
        column_family: ColumnFamily,
        key: Vec<u8>,
    },
}

impl WriteBatch {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn store<T: Storable>(&mut self, msg: Store<T>) {
        self.writes.push(Write::Store {
            key: encode_key::<T>(&msg.key),
            value: Box::new(msg.value),
        });
    }

    pub fn delete<T: Storable>(&mut self, msg: &Delete<T>) {
        self.writes.push(Write::Delete {
            column_family: T::COLUMN_FAMILY,
            key: encode_key::<T>(&msg.key),
        });
    }

    /// Adds the writes of `other` after the ones already added.
    pub fn append(&mut self, mut other: Self) {
        self.writes.append(&mut other.writes);
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }
}

impl<T: Storable> From<Store<T>> for WriteBatch {
    fn from(msg: Store<T>) -> Self {
        let mut batch = Self::new();
        batch.store(msg);
        batch
    }
}

pub struct DumpDb;

/// Schema-agnostic snapshot of a whole store, opaque by design.
pub struct DbDump {
    pub bytes: Vec<u8>,
}
