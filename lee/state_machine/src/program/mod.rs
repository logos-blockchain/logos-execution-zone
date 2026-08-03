use std::borrow::Cow;

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{Account, AccountWithMetadata, Data},
    program::{CallKind, InstructionData, ProgramId, ProgramOutput},
};
use risc0_zkvm::{ExecutorEnv, ExecutorEnvBuilder, default_executor, serde::to_vec};
use serde::Serialize;

use crate::error::LeeError;

/// Maximum number of cycles for a public execution.
/// TODO: Make this variable when fees are implemented.
const MAX_NUM_CYCLES_PUBLIC_EXECUTION: u64 = 1024 * 1024 * 32; // 32M cycles

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Program {
    id: ProgramId,
    elf: Cow<'static, [u8]>,
}

impl Program {
    pub fn new(elf: Cow<'static, [u8]>) -> Result<Self, LeeError> {
        let binary = risc0_binfmt::ProgramBinary::decode(elf.as_ref())
            .map_err(LeeError::InvalidProgramBytecode)?;
        let id = binary
            .compute_image_id()
            .map_err(LeeError::InvalidProgramBytecode)?
            .into();
        Ok(Self { id, elf })
    }

    #[must_use]
    pub const fn new_unchecked(id: ProgramId, elf: Cow<'static, [u8]>) -> Self {
        Self { id, elf }
    }

    #[must_use]
    pub const fn id(&self) -> ProgramId {
        self.id
    }

    #[must_use]
    pub fn elf(&self) -> &[u8] {
        &self.elf
    }

    pub fn serialize_instruction<T: Serialize>(
        instruction: T,
    ) -> Result<InstructionData, LeeError> {
        to_vec(&instruction).map_err(|e| LeeError::InstructionSerializationError(e.to_string()))
    }

    pub(crate) fn execute(
        &self,
        caller_program_id: Option<ProgramId>,
        pre_states: &[AccountWithMetadata],
        instruction_data: &InstructionData,
    ) -> Result<ProgramOutput, LeeError> {
        // Write inputs to the program
        let mut env_builder = ExecutorEnv::builder();
        env_builder.session_limit(Some(MAX_NUM_CYCLES_PUBLIC_EXECUTION));
        Self::write_inputs(
            self.id,
            caller_program_id,
            pre_states,
            instruction_data,
            &mut env_builder,
        )?;
        let env = env_builder.build().unwrap();

        // Execute the program (without proving)
        let executor = default_executor();
        let session_info = executor
            .execute(env, self.elf())
            .map_err(|e| LeeError::ProgramExecutionFailed(e.to_string()))?;

        // Get outputs
        let program_output = session_info
            .journal
            .decode()
            .map_err(|e| LeeError::ProgramExecutionFailed(e.to_string()))?;

        Ok(program_output)
    }

    /// Writes inputs to `env_builder` in the order expected by the programs, as a
    /// `CallKind::Execute` invocation.
    pub(crate) fn write_inputs(
        program_id: ProgramId,
        caller_program_id: Option<ProgramId>,
        pre_states: &[AccountWithMetadata],
        instruction_data: &[u32],
        env_builder: &mut ExecutorEnvBuilder,
    ) -> Result<(), LeeError> {
        env_builder
            .write(&CallKind::Execute)
            .map_err(|e| LeeError::ProgramWriteInputFailed(e.to_string()))?;
        env_builder
            .write(&program_id)
            .map_err(|e| LeeError::ProgramWriteInputFailed(e.to_string()))?;
        env_builder
            .write(&caller_program_id)
            .map_err(|e| LeeError::ProgramWriteInputFailed(e.to_string()))?;
        let pre_states = pre_states.to_vec();
        env_builder
            .write(&pre_states)
            .map_err(|e| LeeError::ProgramWriteInputFailed(e.to_string()))?;
        env_builder
            .write(&instruction_data)
            .map_err(|e| LeeError::ProgramWriteInputFailed(e.to_string()))?;
        Ok(())
    }

    /// Invokes a program's `update_from_diff` entrypoint to materialize an `AccountDiff`'s
    /// `diff_data` into the account's new `data`, unproven (mirrors `execute`).
    pub(crate) fn execute_update_from_diff(
        &self,
        pre_state: Account,
        diff_data: Vec<u8>,
    ) -> Result<Data, LeeError> {
        let mut env_builder = ExecutorEnv::builder();
        env_builder.session_limit(Some(MAX_NUM_CYCLES_PUBLIC_EXECUTION));
        env_builder
            .write(&CallKind::UpdateFromDiff)
            .map_err(|e| LeeError::ProgramWriteInputFailed(e.to_string()))?;
        env_builder
            .write(&pre_state)
            .map_err(|e| LeeError::ProgramWriteInputFailed(e.to_string()))?;
        env_builder
            .write(&diff_data)
            .map_err(|e| LeeError::ProgramWriteInputFailed(e.to_string()))?;
        let env = env_builder.build().unwrap();

        let executor = default_executor();
        let session_info = executor
            .execute(env, self.elf())
            .map_err(|e| LeeError::ProgramExecutionFailed(e.to_string()))?;

        session_info
            .journal
            .decode()
            .map_err(|e| LeeError::ProgramExecutionFailed(e.to_string()))
    }
}

#[cfg(test)]
mod tests;
