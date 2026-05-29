use crate::{
    PrivacyPreservingTransaction, error::LeeError, privacy_preserving_transaction::message::Message,
};

impl Message {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(&self).expect("Autoderived borsh serialization failure")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LeeError> {
        Ok(borsh::from_slice(bytes)?)
    }
}

impl PrivacyPreservingTransaction {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(&self).expect("Autoderived borsh serialization failure")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LeeError> {
        Ok(borsh::from_slice(bytes)?)
    }
}
