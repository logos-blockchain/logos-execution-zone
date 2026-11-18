//! The binary form of a canonical Logos Storage manifest CID.

use borsh::{BorshDeserialize, BorshSerialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

/// Bytes of a [`StorageCid`].
pub const STORAGE_CID_BYTES: usize = 38;

/// What precedes the digest in every manifest CID a canonical upload returns: `CIDv1`, the
/// `storage-manifest` codec (`0xCD01`) and a SHA-256 multihash header.
pub const STORAGE_CID_PREFIX: [u8; 6] = [0x01, 0x81, 0x9A, 0x03, 0x12, 0x20];

/// A Logos Storage manifest CID in the form a block inscribes it.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    BorshSerialize,
    SerializeDisplay,
    DeserializeFromStr,
)]
pub struct StorageCid([u8; STORAGE_CID_BYTES]);

impl StorageCid {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; STORAGE_CID_BYTES] {
        &self.0
    }
}

/// Bytes that are not a manifest CID of the canonical form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not a canonical Logos Storage manifest CID")]
pub struct NotAStorageCid;

impl TryFrom<&[u8]> for StorageCid {
    type Error = NotAStorageCid;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; STORAGE_CID_BYTES] = bytes.try_into().map_err(|_err| NotAStorageCid)?;
        if !bytes.starts_with(&STORAGE_CID_PREFIX) {
            return Err(NotAStorageCid);
        }
        Ok(Self(bytes))
    }
}

impl BorshDeserialize for StorageCid {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let bytes = <[u8; STORAGE_CID_BYTES]>::deserialize_reader(reader)?;
        Self::try_from(bytes.as_slice())
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    }
}

impl std::fmt::Display for StorageCid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl std::fmt::Debug for StorageCid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

impl std::str::FromStr for StorageCid {
    type Err = NotAStorageCid;

    fn from_str(hex_form: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(hex_form).map_err(|_err| NotAStorageCid)?;
        Self::try_from(bytes.as_slice())
    }
}
