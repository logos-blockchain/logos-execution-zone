#[cfg(feature = "host")]
use std::io::Cursor;

#[cfg(feature = "host")]
use crate::Nullifier;
#[cfg(feature = "host")]
use crate::encryption::EphemeralPublicKey;
#[cfg(feature = "host")]
use crate::error::LeeCoreError;
use crate::{
    Commitment, NullifierPublicKey,
    account::{Account, AccountId},
    encryption::Ciphertext,
};

impl Account {
    /// Serializes the account to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("borsh serialization is infallible")
    }

    /// Deserializes an account from a cursor.
    #[cfg(feature = "host")]
    pub fn from_cursor(cursor: &mut Cursor<&[u8]>) -> Result<Self, LeeCoreError> {
        use borsh::BorshDeserialize as _;

        Ok(Self::deserialize_reader(cursor)?)
    }
}

impl Commitment {
    #[must_use]
    pub const fn to_byte_array(&self) -> [u8; 32] {
        self.0
    }

    #[cfg(feature = "host")]
    #[must_use]
    pub const fn from_byte_array(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl NullifierPublicKey {
    #[must_use]
    pub const fn to_byte_array(&self) -> [u8; 32] {
        self.0
    }
}

#[cfg(feature = "host")]
impl Nullifier {
    #[cfg(feature = "host")]
    #[must_use]
    pub const fn from_byte_array(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Ciphertext {
    /// Serializes the ciphertext to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let ciphertext_length: u32 =
            u32::try_from(self.0.len()).expect("ciphertext length fits in u32");
        bytes.extend_from_slice(&ciphertext_length.to_le_bytes());
        bytes.extend_from_slice(&self.0);

        bytes
    }

    #[cfg(feature = "host")]
    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }

    #[cfg(feature = "host")]
    #[must_use]
    pub const fn from_inner(inner: Vec<u8>) -> Self {
        Self(inner)
    }
}

#[cfg(feature = "host")]
impl EphemeralPublicKey {
    /// Serializes the ML-KEM-768 ciphertext to bytes (always 1088 bytes).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl AccountId {
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; 32] {
        *self.value()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shard_bearing_account() -> Account {
        Account {
            nonce: 42_u128.into(),
            ..Account::funded(123_456_789_012_345_678_901_234_567_890_123_456).with_shard(
                AccountId::new([7; 32]),
                b"hola mundo".to_vec().try_into().unwrap(),
            )
        }
    }

    #[test]
    fn encoding() {
        let account = shard_bearing_account();

        let expected_bytes = [
            42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 186, 220, 114, 113, 65, 236, 234,
            222, 15, 215, 191, 227, 198, 23, 0, 1, 0, 0, 0, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
            7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 10, 0, 0, 0, 104, 111, 108,
            97, 32, 109, 117, 110, 100, 111,
        ];

        let bytes = account.to_bytes();
        assert_eq!(bytes, expected_bytes);
    }

    #[test]
    fn commitment_to_bytes() {
        let commitment = Commitment((0..32).collect::<Vec<u8>>().try_into().unwrap());
        let expected_bytes: [u8; 32] = (0..32).collect::<Vec<u8>>().try_into().unwrap();

        let bytes = commitment.to_byte_array();
        assert_eq!(expected_bytes, bytes);
    }

    #[cfg(feature = "host")]
    #[test]
    fn nullifier_to_bytes() {
        let nullifier = Nullifier((0..32).collect::<Vec<u8>>().try_into().unwrap());
        let expected_bytes: [u8; 32] = (0..32).collect::<Vec<u8>>().try_into().unwrap();

        let bytes = nullifier.to_byte_array();
        assert_eq!(expected_bytes, bytes);
    }

    #[cfg(feature = "host")]
    #[test]
    fn account_to_bytes_roundtrip() {
        let account = shard_bearing_account();
        let bytes = account.to_bytes();
        let mut cursor = Cursor::new(bytes.as_ref());
        let account_from_cursor = Account::from_cursor(&mut cursor).unwrap();
        assert_eq!(account, account_from_cursor);
    }
}
