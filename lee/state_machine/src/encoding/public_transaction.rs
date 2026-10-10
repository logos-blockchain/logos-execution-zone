use crate::{PublicTransaction, error::LeeError};

impl PublicTransaction {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(&self).expect("Autoderived borsh serialization failure")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LeeError> {
        Ok(borsh::from_slice(bytes)?)
    }
}
