use std::borrow::Cow;

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::AccountWithMetadata,
    from_frame,
    program::{InstructionData, ProgramId, ProgramInput, ProgramOutput},
    to_frame,
};
use risc0_zkvm::{ExecutorEnv, ExecutorEnvBuilder, default_executor};

use crate::error::LeeError;

/// The cycle budget applied to public execution paths that do not yet carry
/// a transaction-specific budget. Enforcement of the fee spec's per-block cap
/// replaces this in the charging transition.
pub const DEFAULT_PUBLIC_CYCLE_BUDGET: u64 = 1024 * 1024 * 32; // 32M cycles

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

    pub fn serialize_instruction<T: BorshSerialize>(
        instruction: T,
    ) -> Result<InstructionData, LeeError> {
        borsh::to_vec(&instruction)
            .map_err(|e| LeeError::InstructionSerializationError(e.to_string()))
    }

    pub(crate) fn execute(
        &self,
        caller_program_id: Option<ProgramId>,
        pre_states: &[AccountWithMetadata],
        instruction_data: &InstructionData,
        cycle_budget: u64,
    ) -> Result<(ProgramOutput, u64), LeeError> {
        // Write inputs to the program
        let mut env_builder = ExecutorEnv::builder();
        env_builder.session_limit(Some(cycle_budget));
        self.write_inputs(
            caller_program_id,
            pre_states,
            instruction_data,
            &mut env_builder,
        )?;
        let env = env_builder.build().unwrap();

        // Execute the program (without proving)
        let session_info = Self::execute_session(env, self.elf(), cycle_budget)?;
        let cycles = session_info.cycles();

        // Get outputs
        let payload = from_frame(&session_info.journal.bytes).ok_or_else(|| {
            LeeError::ProgramExecutionFailed("malformed program journal frame".to_owned())
        })?;
        let program_output = borsh::from_slice(payload)
            .map_err(|e| LeeError::ProgramExecutionFailed(e.to_string()))?;

        Ok((program_output, cycles))
    }

    /// Runs the session, translating the executor's session-limit bail into the
    /// typed [`LeeError::OutOfGas`]. The only place that error string is
    /// recognized.
    ///
    /// FIXME: This is a brittle string match; the executor should provide a typed error
    fn execute_session(
        env: ExecutorEnv<'_>,
        elf: &[u8],
        cycle_budget: u64,
    ) -> Result<risc0_zkvm::SessionInfo, LeeError> {
        default_executor().execute(env, elf).map_err(|e| {
            if format!("{e:#}").contains("Session limit exceeded") {
                LeeError::OutOfGas {
                    budget: cycle_budget,
                }
            } else {
                LeeError::ProgramExecutionFailed(e.to_string())
            }
        })
    }

    /// Writes the guest's [`ProgramInput`] as a single length-prefixed borsh frame, the form
    /// `read_lee_inputs` expects.
    pub fn write_inputs(
        &self,
        caller_program_id: Option<ProgramId>,
        pre_states: &[AccountWithMetadata],
        instruction_data: &[u8],
        env_builder: &mut ExecutorEnvBuilder,
    ) -> Result<(), LeeError> {
        let input = ProgramInput {
            self_program_id: self.id,
            caller_program_id,
            pre_states: pre_states.to_vec(),
            instruction: instruction_data.to_vec(),
        };
        let payload =
            borsh::to_vec(&input).map_err(|e| LeeError::ProgramWriteInputFailed(e.to_string()))?;
        env_builder.write_slice(&to_frame(&payload));
        Ok(())
    }
}

#[cfg(test)]
mod tests;
