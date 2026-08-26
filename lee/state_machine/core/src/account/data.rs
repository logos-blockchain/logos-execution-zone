use std::ops::Deref;

use borsh::{BorshDeserialize, BorshSerialize};
use bytesize::ByteSize;
use serde::{Deserialize, Serialize};

/// TODO: Temporarily raised cap to 700 KiB from 100 KiB. This is a placeholder
/// until multiple accounts are used to store the entire elf.
pub const DATA_MAX_LENGTH: ByteSize = ByteSize::kib(700);
#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "usize::try_from is not yet const-stable; the value is tiny and always fits"
)]
pub const DATA_MAX_LENGTH_BYTES: usize = DATA_MAX_LENGTH.as_u64() as usize;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, BorshSerialize)]
pub struct Data(Vec<u8>);

impl Data {
    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }

    /// Reads data from a cursor.
    #[cfg(feature = "host")]
    pub fn from_cursor(
        cursor: &mut std::io::Cursor<&[u8]>,
    ) -> Result<Self, crate::error::LeeCoreError> {
        use std::io::Read as _;

        let mut u32_bytes = [0_u8; 4];
        cursor.read_exact(&mut u32_bytes)?;
        let data_length = u32::from_le_bytes(u32_bytes);
        if u64::from(data_length) > DATA_MAX_LENGTH.as_u64() {
            return Err(
                std::io::Error::new(std::io::ErrorKind::InvalidData, DataTooBigError).into(),
            );
        }

        let mut data =
            vec![0; usize::try_from(data_length).expect("data length is expected to fit in usize")];
        cursor.read_exact(&mut data)?;
        Ok(Self(data))
    }
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[error("data length exceeds maximum allowed length of {} bytes", DATA_MAX_LENGTH.as_u64())]
pub struct DataTooBigError;

impl From<Data> for Vec<u8> {
    fn from(data: Data) -> Self {
        data.0
    }
}

impl TryFrom<Vec<u8>> for Data {
    type Error = DataTooBigError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() > DATA_MAX_LENGTH_BYTES {
            Err(DataTooBigError)
        } else {
            Ok(Self(value))
        }
    }
}

impl Deref for Data {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for Data {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Data {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        /// Data deserialization visitor.
        ///
        /// Compared to a simple deserialization into a `Vec<u8>`, this visitor enforces
        /// early length check defined by [`DATA_MAX_LENGTH`].
        struct DataVisitor;

        impl<'de> serde::de::Visitor<'de> for DataVisitor {
            type Value = Data;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(
                    formatter,
                    "a byte array with length not exceeding {} bytes",
                    DATA_MAX_LENGTH.as_u64()
                )
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut vec =
                    Vec::with_capacity(seq.size_hint().unwrap_or(0).min(DATA_MAX_LENGTH_BYTES));

                while let Some(value) = seq.next_element()? {
                    vec.push(value);
                    check_len(vec.len())?;
                }

                Ok(Data(vec))
            }
        }

        deserializer.deserialize_seq(DataVisitor)
    }
}

impl BorshDeserialize for Data {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        // Implementation adapted from `impl BorshDeserialize for Vec<T>`

        let len = u32::deserialize_reader(reader)?;
        match len {
            0 => Ok(Self::default()),
            len if u64::from(len) > DATA_MAX_LENGTH.as_u64() => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                DataTooBigError,
            )),
            len => {
                let vec_bytes = u8::vec_from_reader(len, reader)?
                    .expect("can't be None in current borsh crate implementation");
                Ok(Self(vec_bytes))
            }
        }
    }
}

fn check_len<E: serde::de::Error>(len: usize) -> Result<(), E> {
    if len > DATA_MAX_LENGTH_BYTES {
        Err(serde::de::Error::custom(DataTooBigError))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_max_length_allowed() {
        let max_vec = vec![0_u8; DATA_MAX_LENGTH_BYTES];
        let result = Data::try_from(max_vec);
        assert!(result.is_ok());
    }

    #[test]
    fn data_too_big_error() {
        let big_vec = vec![0_u8; DATA_MAX_LENGTH_BYTES + 1];
        let result = Data::try_from(big_vec);
        assert!(matches!(result, Err(DataTooBigError)));
    }

    #[test]
    fn borsh_deserialize_exceeding_limit_error() {
        let too_big_data = vec![0_u8; DATA_MAX_LENGTH_BYTES + 1];
        let mut serialized = Vec::new();
        <_ as BorshSerialize>::serialize(&too_big_data, &mut serialized).unwrap();

        let result = <Data as BorshDeserialize>::deserialize(&mut serialized.as_ref());
        assert!(result.is_err());
    }

    #[test]
    fn json_deserialize_exceeding_limit_error() {
        let data = vec![0_u8; DATA_MAX_LENGTH_BYTES + 1];
        let json = serde_json::to_string(&data).unwrap();

        let result: Result<Data, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }
}
