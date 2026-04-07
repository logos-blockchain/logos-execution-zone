use borsh::{BorshDeserialize, BorshSerialize};
use nssa_core::account::AccountId;
use sha2::{Digest as _, digest::FixedOutput as _};

use crate::program_deployment_transaction::message::Message;

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ProgramDeploymentTransaction {
    pub message: Message,
}

impl ProgramDeploymentTransaction {
    #[must_use]
    pub const fn new(message: Message) -> Self {
        Self { message }
    }

    #[must_use]
    pub fn into_message(self) -> Message {
        self.message
    }

    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        let bytes = self.to_bytes();
        let mut hasher = sha2::Sha256::new();
        hasher.update(&bytes);
        hasher.finalize_fixed().into()
    }

    #[must_use]
    pub const fn affected_public_account_ids(&self) -> Vec<AccountId> {
        vec![]
    }
}
