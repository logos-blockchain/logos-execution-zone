use std::borrow::Cow;

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, AccountWithMetadata},
    program::{InstructionData, ProgramId, ProgramOutput},
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
        caller_account_id: Option<AccountId>,
        pre_states: &[AccountWithMetadata],
        instruction_data: &InstructionData,
    ) -> Result<ProgramOutput, LeeError> {
        self.execute_with_session_limit(
            caller_program_id,
            pre_states,
            instruction_data,
            MAX_NUM_CYCLES_PUBLIC_EXECUTION,
        )
    }

    fn execute_with_session_limit(
        &self,
        caller_program_id: Option<ProgramId>,
        pre_states: &[AccountWithMetadata],
        instruction_data: &InstructionData,
        session_limit: u64,
    ) -> Result<ProgramOutput, LeeError> {
        // Write inputs to the program
        let mut env_builder = ExecutorEnv::builder();
        env_builder.session_limit(Some(session_limit));
        Self::write_inputs(
            AccountId::from(self.id),
            caller_account_id,
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

    /// Writes inputs to `env_builder` in the order expected by the programs.
    pub(crate) fn write_inputs(
        self_account_id: AccountId,
        caller_account_id: Option<AccountId>,
        pre_states: &[AccountWithMetadata],
        instruction_data: &[u32],
        env_builder: &mut ExecutorEnvBuilder,
    ) -> Result<(), LeeError> {
        env_builder
            .write(&self_account_id)
            .map_err(|e| LeeError::ProgramWriteInputFailed(e.to_string()))?;
        env_builder
            .write(&caller_account_id)
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
}

#[cfg(feature = "test-utils")]
impl Program {
    /// Test-only: like `execute`, but with a session limit far above the production
    /// `MAX_NUM_CYCLES_PUBLIC_EXECUTION` cap.
    ///
    /// Exists so tests can run a real, possibly large guest program to completion — e.g.
    /// comparing the loader guest's actual execution against its native dispatch fast-path
    /// (see `RESERVED_DEPLOYMENT_PROGRAM_ACCOUNT_ID`) — without hitting the budget that exists
    /// specifically to bound production dispatch cost, which this is deliberately not testing.
    pub fn execute_for_test(
        &self,
        caller_program_id: Option<ProgramId>,
        pre_states: &[AccountWithMetadata],
        instruction_data: &InstructionData,
    ) -> Result<ProgramOutput, LeeError> {
        self.execute_with_session_limit(
            caller_program_id,
            pre_states,
            instruction_data,
            MAX_NUM_CYCLES_PUBLIC_EXECUTION * 64,
        )
    }
}

#[cfg(test)]
mod tests;
