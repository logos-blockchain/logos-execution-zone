//! Encoding utilities for database.

use std::sync::Arc;

use borsh::{BorshDeserialize, BorshSerialize};

/// Big Endian numbers encoding.
///
/// Useful for preserving ascending order.
pub struct BigEndian<T: num_traits::ToBytes> {
    bytes: T::Bytes,
}

impl<T: num_traits::ToBytes> BigEndian<T> {
    pub fn new(value: &T) -> Self {
        Self {
            bytes: value.to_be_bytes(),
        }
    }
}

impl<T: num_traits::ToBytes> AsRef<[u8]> for BigEndian<T> {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

/// Singleton key for a type.
///
/// This means that only one value of that type can be stored in the database at a time.
pub struct SingletonKey;

impl AsRef<[u8]> for SingletonKey {
    fn as_ref(&self) -> &[u8] {
        &[]
    }
}

/// Wrapper around Arc<T> that implements [`BorshSerialize`] and [`BorshDeserialize`].
pub struct BorshArc<T>(pub Arc<T>);

impl<T: BorshSerialize> BorshSerialize for BorshArc<T> {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.0.serialize(writer)
    }
}

impl<T: BorshDeserialize> BorshDeserialize for BorshArc<T> {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        let value = T::deserialize(buf)?;
        Ok(Self(Arc::new(value)))
    }

    fn deserialize_reader<R: std::io::prelude::Read>(reader: &mut R) -> std::io::Result<Self> {
        let value = T::deserialize_reader(reader)?;
        Ok(Self(Arc::new(value)))
    }
}
