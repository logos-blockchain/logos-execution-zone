use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Message {
    #[serde(with = "crate::base64")]
    pub(crate) bytecode: Vec<u8>,
}

impl Message {
    #[must_use]
    pub const fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    #[must_use]
    pub fn into_bytecode(self) -> Vec<u8> {
        self.bytecode
    }
}
