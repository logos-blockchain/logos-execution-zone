use borsh::{BorshDeserialize, BorshSerialize};
use nssa_core::account::AccountId;
use sha2::{Digest as _, digest::FixedOutput as _};

use crate::{
    V03State, error::NssaError, program::Program, program_deployment_transaction::message::Message,
};

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

    pub(crate) fn validate_and_produce_public_state_diff(
        &self,
        state: &V03State,
    ) -> Result<Program, NssaError> {
        // TODO: remove clone
        let program = Program::new(self.message.bytecode.clone())?;
        if state.programs().contains_key(&program.id()) {
            Err(NssaError::ProgramAlreadyExists)
        } else {
            Ok(program)
        }
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
