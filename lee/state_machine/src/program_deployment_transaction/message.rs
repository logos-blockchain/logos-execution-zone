use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Message {
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
