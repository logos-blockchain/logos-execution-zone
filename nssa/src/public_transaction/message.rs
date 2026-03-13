use borsh::{BorshDeserialize, BorshSerialize};
use nssa_core::{
    account::Nonce,
    program::{InstructionData, ProgramId},
};
use serde::Serialize;

use crate::{AccountId, error::NssaError, program::Program};

#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Message {
    pub program_id: ProgramId,
    pub account_ids: Vec<AccountId>,
    pub nonces: Vec<Nonce>,
    pub instruction_data: InstructionData,
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let program_id_hex = hex::encode(
            self.program_id
                .iter()
                .flat_map(|n| n.to_le_bytes())
                .collect::<Vec<u8>>(),
        );
        f.debug_struct("Message")
            .field("program_id", &program_id_hex)
            .field("account_ids", &self.account_ids)
            .field("nonces", &self.nonces)
            .field("instruction_data", &self.instruction_data)
            .finish()
    }
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

    pub fn new_preserialized(
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
