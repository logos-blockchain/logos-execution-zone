use std::ops::Deref;

use borsh::{BorshDeserialize, BorshSerialize};
use bytesize::ByteSize;
use serde::{Deserialize, Serialize};

/// Raised from the original 100 KiB to accommodate program elfs stored directly in
/// `Account.data` under the Program-as-Account migration.
///
/// Observed elfs currently run 375 KB-520 KB, plus 631 KB for the fixed
/// privacy-preserving circuit itself. This value is a rough placeholder, not a considered
/// protocol constant yet — it still needs to be refined against real transaction/block-size
/// budgets (e.g. `SequencerConfig::max_block_size`, currently 1 MiB) before this is something
/// production traffic should rely on.
pub const DATA_MAX_LENGTH: ByteSize = ByteSize::kib(700);

#[derive(Debug, Default, Clone, PartialEq, Eq, BorshSerialize)]
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
        if value.len()
            > usize::try_from(DATA_MAX_LENGTH.as_u64()).expect("DATA_MAX_LENGTH fits in usize")
        {
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

impl Serialize for Data {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Explicit `serialize_bytes` lets `risc0_zkvm::serde` pack these bytes densely.
        serializer.serialize_bytes(&self.0)
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

            // A human-readable format like `serde_json` routes a JSON array through here (its
            // `deserialize_bytes` delegates to `deserialize_seq` for a `[...]` token) — checked
            // incrementally, one element at a time, so an oversized claim is rejected without
            // ever over-allocating.
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut vec =
                    Vec::with_capacity(seq.size_hint().unwrap_or(0).min(data_max_length()));

                while let Some(value) = seq.next_element()? {
                    if vec.len() >= data_max_length() {
                        return Err(serde::de::Error::custom(DataTooBigError));
                    }
                    vec.push(value);
                }

                Ok(Data(vec))
            }

            // A binary format like `risc0_zkvm::serde` calls this directly for `deserialize_bytes`.
            // Note this check is necessarily a post-hoc reject, not a preventive cap: `v`
            // arrives already fully materialized by the deserializer (RISC0's own implementation
            // allocates the claimed length up front, before any visitor method runs) — accepted
            // because no untrusted, unreconstructed bytes ever reach this path in this codebase
            // today (see the -7-2 design notes for the audit of every call site).
            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                check_len(v.len())?;
                Ok(Data(v))
            }

            // Defensive completeness for a deserializer that hands over borrowed bytes instead of
            // an owned buffer; not exercised by any format currently in use in this codebase.
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                check_len(v.len())?;
                Ok(Data(v.to_vec()))
            }
        }

        deserializer.deserialize_bytes(DataVisitor)
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

fn data_max_length() -> usize {
    usize::try_from(DATA_MAX_LENGTH.as_u64()).expect("DATA_MAX_LENGTH fits in usize")
}

fn check_len<E: serde::de::Error>(len: usize) -> Result<(), E> {
    if len > data_max_length() {
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
        let max_vec = vec![
            0_u8;
            usize::try_from(DATA_MAX_LENGTH.as_u64())
                .expect("DATA_MAX_LENGTH fits in usize")
        ];
        let result = Data::try_from(max_vec);
        assert!(result.is_ok());
    }

    #[test]
    fn data_too_big_error() {
        let big_vec = vec![
            0_u8;
            usize::try_from(DATA_MAX_LENGTH.as_u64())
                .expect("DATA_MAX_LENGTH fits in usize")
                + 1
        ];
        let result = Data::try_from(big_vec);
        assert!(matches!(result, Err(DataTooBigError)));
    }

    #[test]
    fn borsh_deserialize_exceeding_limit_error() {
        let too_big_data = vec![
            0_u8;
            usize::try_from(DATA_MAX_LENGTH.as_u64())
                .expect("DATA_MAX_LENGTH fits in usize")
                + 1
        ];
        let mut serialized = Vec::new();
        <_ as BorshSerialize>::serialize(&too_big_data, &mut serialized).unwrap();

        let result = <Data as BorshDeserialize>::deserialize(&mut serialized.as_ref());
        assert!(result.is_err());
    }

    #[test]
    fn json_deserialize_exceeding_limit_error() {
        let data = vec![
            0_u8;
            usize::try_from(DATA_MAX_LENGTH.as_u64())
                .expect("DATA_MAX_LENGTH fits in usize")
                + 1
        ];
        let json = serde_json::to_string(&data).unwrap();

        let result: Result<Data, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn risc0_round_trip_survives_non_word_aligned_lengths() {
        // 7 bytes doesn't divide evenly by the 4-byte word size, exercising the padding path.
        let data = Data::try_from(vec![1, 2, 3, 4, 5, 6, 7]).unwrap();
        let words = risc0_zkvm::serde::to_vec(&data).unwrap();
        let round_tripped: Data = risc0_zkvm::serde::from_slice(&words).unwrap();
        assert_eq!(data, round_tripped);
    }

    #[test]
    fn risc0_encoding_packs_four_bytes_per_word() {
        // Locks in the actual win: one length word plus ceil(N/4) packed data words, not the old
        // one-word-per-byte encoding (which would be 1 + N words here).
        let data = Data::try_from(vec![0_u8; 101]).unwrap();
        let words = risc0_zkvm::serde::to_vec(&data).unwrap();
        assert_eq!(words.len(), 1 + 101_usize.div_ceil(4));
    }

    #[test]
    fn risc0_deserialize_rejects_oversized_claimed_length() {
        // Hand-built word stream: a length word claiming one more byte than DATA_MAX_LENGTH
        // allows, followed by enough (zero) data words to satisfy RISC0's own length-vs-buffer
        // bounds check — otherwise it rejects with its own DeserializeUnexpectedEnd before ever
        // reaching Data's own cap check, which isn't what this test means to exercise.
        let claimed_len = u32::try_from(DATA_MAX_LENGTH.as_u64())
            .unwrap()
            .checked_add(1)
            .unwrap();
        let mut words = vec![claimed_len];
        let data_word_count = usize::try_from(claimed_len).unwrap().div_ceil(4);
        words.resize(1_usize.checked_add(data_word_count).unwrap(), 0_u32);

        let result: Result<Data, _> = risc0_zkvm::serde::from_slice(&words);
        assert!(result.is_err());
    }
}
