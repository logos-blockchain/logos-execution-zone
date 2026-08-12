use std::borrow::Cow;

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::AccountWithMetadata,
    program::{InstructionData, ProgramId, ProgramOutput},
};
use risc0_zkvm::{ExecutorEnv, ExecutorEnvBuilder, SessionInfo, default_executor, serde::to_vec};
use serde::Serialize;

use crate::error::LeeError;

/// Message the risc0 executor bails with when a session goes past its `session_limit`.
/// Only [`execute_session`] may rely on it.
const SESSION_LIMIT_EXCEEDED: &str = "Session limit exceeded";

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

    /// Executes the program under a `cycle_budget` of user cycles, returning its output together
    /// with the user cycles it consumed.
    ///
    /// Outgrowing the budget is [`LeeError::OutOfGas`]. Two of the three error arms carry **no**
    /// cycle count, because risc0 bails out of `execute` without a `SessionInfo` for both the
    /// session limit and a guest panic; `ValidatedStateDiff::execute_public_transaction` meters
    /// those at the whole budget. The third — [`LeeError::MalformedProgramOutput`], a guest that
    /// halted cleanly without writing a decodable output — *does* carry the real count, because
    /// risc0 returns `Ok(SessionInfo)` for any `Halted(n)`.
    ///
    /// The returned count may exceed `cycle_budget`: the executor tests its limit between
    /// instructions, so a session that terminates on the instruction crossing the line reports the
    /// cost of that instruction on top of the budget (one cycle for a plain instruction, more for
    /// an accelerator ecall or a paging step).
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
        Self::write_inputs(
            self.id,
            caller_program_id,
            pre_states,
            instruction_data,
            &mut env_builder,
        )?;
        let env = env_builder.build().unwrap();

        // Execute the program (without proving)
        let session_info = execute_session(env, self.elf(), cycle_budget)?;

        // Sum of the per-segment user cycles: the metered cost of this session.
        let cycles = session_info.cycles();

        // Get outputs. A journal that does not decode means the guest halted cleanly without
        // writing its output — the early-`return` shape. That comes back as `Ok(SessionInfo)`, so
        // unlike the panic and out-of-gas paths this failure *does* know what it cost; the count
        // rides on the error rather than being thrown away with it.
        let program_output =
            session_info
                .journal
                .decode()
                .map_err(|e| LeeError::MalformedProgramOutput {
                    cycles,
                    reason: e.to_string(),
                })?;

        Ok((program_output, cycles))
    }

    /// Writes inputs to `env_builder` in the order expected by the programs.
    pub(crate) fn write_inputs(
        program_id: ProgramId,
        caller_program_id: Option<ProgramId>,
        pre_states: &[AccountWithMetadata],
        instruction_data: &[u32],
        env_builder: &mut ExecutorEnvBuilder,
    ) -> Result<(), LeeError> {
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
}

/// Runs the executor and turns its untyped failures into [`LeeError`].
///
/// This is the single place allowed to recognise the executor's "session limit exceeded" bail:
/// it becomes [`LeeError::OutOfGas`] so no caller ever has to inspect an error string.
fn execute_session(
    env: ExecutorEnv<'_>,
    elf: &[u8],
    cycle_budget: u64,
) -> Result<SessionInfo, LeeError> {
    default_executor().execute(env, elf).map_err(|e| {
        if e.chain()
            .any(|cause| cause.to_string().contains(SESSION_LIMIT_EXCEEDED))
        {
            LeeError::OutOfGas {
                budget: cycle_budget,
            }
        } else {
            LeeError::ProgramExecutionFailed(e.to_string())
        }
    })
}

#[cfg(test)]
mod tests;
