//! Writes a store commits together, or not at all.

pub use sequencer_storage_actor_derive::Writes;

use crate::{
    ColumnFamily, Result, Storable,
    error::Error,
    protocol::{Delete, Store},
    storable::encode_key,
};

/// [`Store`] and [`Delete`] messages, committed together or not at all, sent in a
/// [`WriteBatch`](crate::protocol::WriteBatch).
///
/// Derive it with [`Writes`](sequencer_storage_actor_derive::Writes).
///
/// Implemented for the messages themselves and for [`Option`]s and [`Vec`]s of writes.
pub trait Writes: Send + Sync + 'static {
    /// Stages every write in `staged`, in order.
    fn write_to(&self, staged: &mut StagedWrites) -> Result<()>;
}

/// Writes a store stages before committing them, with their keys and values encoded.
pub struct StagedWrites {
    pub(crate) writes: Vec<StagedWrite>,
}

/// One write of [`StagedWrites`]: the encoded value to store under `key`, or `None` to delete it.
#[cfg_attr(
    not(any(feature = "actor", feature = "mock")),
    expect(dead_code, reason = "Only the actor and its mock commit the writes")
)]
pub(crate) struct StagedWrite {
    pub column_family: ColumnFamily,
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
}

impl StagedWrites {
    #[cfg(any(feature = "actor", feature = "mock"))]
    pub(crate) const fn new() -> Self {
        Self { writes: Vec::new() }
    }

    /// Stages storing `value` under `key`, failing if `value` does not encode.
    pub fn store<T: Storable>(&mut self, key: &T::Key, value: &T) -> Result<()> {
        let value = borsh::to_vec(value).map_err(Error::Encoding)?;
        self.writes.push(StagedWrite {
            column_family: T::COLUMN_FAMILY,
            key: encode_key::<T>(key),
            value: Some(value),
        });
        Ok(())
    }

    /// Stages deleting the value under `key`.
    pub fn delete<T: Storable>(&mut self, key: &T::Key) {
        self.writes.push(StagedWrite {
            column_family: T::COLUMN_FAMILY,
            key: encode_key::<T>(key),
            value: None,
        });
    }
}

impl<T: Storable> Writes for Store<T> {
    fn write_to(&self, staged: &mut StagedWrites) -> Result<()> {
        staged.store(&self.key, &self.value)
    }
}

impl<T: Storable> Writes for Delete<T> {
    fn write_to(&self, staged: &mut StagedWrites) -> Result<()> {
        staged.delete::<T>(&self.key);
        Ok(())
    }
}

impl<W: Writes> Writes for Option<W> {
    fn write_to(&self, staged: &mut StagedWrites) -> Result<()> {
        self.as_ref()
            .map_or(Ok(()), |writes| writes.write_to(staged))
    }
}

impl<W: Writes> Writes for Vec<W> {
    fn write_to(&self, staged: &mut StagedWrites) -> Result<()> {
        self.iter().try_for_each(|writes| writes.write_to(staged))
    }
}
