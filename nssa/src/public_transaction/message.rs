use borsh::{BorshDeserialize, BorshSerialize};
use nssa_core::{
    account::Nonce,
    program::{InstructionData, ProgramId},
};
use serde::Serialize;

use crate::{AccountId, error::NssaError, program::Program};

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Message {
    pub program_id: ProgramId,
    pub account_ids: Vec<AccountId>,
    pub nonces: Vec<Nonce>,
    pub instruction_data: InstructionData,
}

impl Message {
    pub fn try_new<T: Serialize>(
        program_id: ProgramId,
        account_ids: Vec<AccountId>,
        nonces: Vec<Nonce>,
        instruction: T,
    ) -> Result<Self, NssaError> {
        let instruction_data = Program::serialize_instruction(instruction)?;

        Ok(Self {
            program_id,
            account_ids,
            nonces,
            instruction_data,
        })
    }

    #[must_use]
    pub const fn new_preserialized(
        program_id: ProgramId,
        account_ids: Vec<AccountId>,
        nonces: Vec<Nonce>,
        instruction_data: InstructionData,
    ) -> Self {
        Self {
            program_id,
            account_ids,
            nonces,
            instruction_data,
        }
    }
}
