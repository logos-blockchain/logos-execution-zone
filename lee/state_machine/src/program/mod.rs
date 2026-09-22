use std::borrow::Cow;

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::Cycles,
    from_frame,
    program::{
        CallKind, GuestOutput, InstructionData, ProgramId, ProgramInput, ProgramOutput,
        ResolveInput, ResolveOutput,
    },
    to_borsh_frame, to_frame,
};
#[cfg(not(feature = "prove"))]
use risc0_zkvm::default_executor;
use risc0_zkvm::{ExecutorEnv, ExecutorEnvBuilder};

use crate::error::LeeError;

#[cfg(feature = "prove")]
pub(crate) mod image_cache;

#[cfg(test)]
mod tests;

/// The cycle budget applied to public execution paths that do not carry a
/// transaction-specific budget; charged transactions supply their own
/// `gas_limit` instead.
pub const DEFAULT_PUBLIC_CYCLE_BUDGET: Cycles = 1024 * 1024 * 32; // 32M cycles

/// What `execute_session` needs off a no-proof run: the committed journal and the user-cycle
/// count. Narrower than `risc0_zkvm::SessionInfo`, which is `#[non_exhaustive]` and so cannot be
/// built outside risc0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionOutcome {
    pub journal: Vec<u8>,
    pub cycles: Cycles,
}

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
        input: &ProgramInput<InstructionData>,
        cycle_budget: Cycles,
    ) -> Result<(ProgramOutput, Cycles), LeeError> {
        let (journal, cycles) =
            self.run(|env| Self::write_execute_inputs(input, env), cycle_budget)?;
        Ok((planner_journal(&journal)?, cycles))
    }

    pub(crate) fn resolve(
        &self,
        input: &ResolveInput,
        cycle_budget: Cycles,
    ) -> Result<(ResolveOutput, Cycles), LeeError> {
        let (journal, cycles) =
            self.run(|env| Self::write_resolve_inputs(input, env), cycle_budget)?;
        Ok((resolver_journal(&journal)?, cycles))
    }

    fn run(
        &self,
        write: impl FnOnce(&mut ExecutorEnvBuilder) -> Result<(), LeeError>,
        cycle_budget: Cycles,
    ) -> Result<(Vec<u8>, Cycles), LeeError> {
        let mut env_builder = ExecutorEnv::builder();
        env_builder.session_limit(Some(cycle_budget));
        write(&mut env_builder)?;
        let env = env_builder.build().unwrap();

        let session = Self::execute_session(env, self.elf(), cycle_budget)?;
        Ok((session.journal, session.cycles))
    }

    /// Runs the session, translating the executor's session-limit bail into the
    /// typed [`LeeError::OutOfGas`]. The only place that error string is
    /// recognized.
    ///
    /// FIXME: This is a brittle string match; the executor should provide a typed error.
    pub(crate) fn execute_session(
        env: ExecutorEnv<'_>,
        elf: &[u8],
        cycle_budget: Cycles,
    ) -> Result<SessionOutcome, LeeError> {
        #[cfg(feature = "prove")]
        let raw = image_cache::execute(env, elf);
        #[cfg(not(feature = "prove"))]
        let raw = default_executor().execute(env, elf).map(|info| {
            // Cycles first so the journal moves instead of cloning.
            let cycles = info.cycles();
            SessionOutcome {
                journal: info.journal.bytes,
                cycles,
            }
        });

        raw.map_err(|e| {
            // check for "Guest panicked" to prevent spoofing
            // via `panic!("Session limit exceeded")` cases
            let message = format!("{e:#}");
            if message.contains("Session limit exceeded") && !message.contains("Guest panicked") {
                LeeError::OutOfGas {
                    budget: cycle_budget,
                }
            } else {
                LeeError::ProgramExecutionFailed(e.to_string())
            }
        })
    }

    pub fn write_execute_inputs(
        input: &ProgramInput<InstructionData>,
        env_builder: &mut ExecutorEnvBuilder,
    ) -> Result<(), LeeError> {
        Self::write_call(CallKind::Execute, input, env_builder)
    }

    pub fn write_resolve_inputs(
        input: &ResolveInput,
        env_builder: &mut ExecutorEnvBuilder,
    ) -> Result<(), LeeError> {
        Self::write_call(CallKind::Resolve, input, env_builder)
    }

    /// Writes the call-kind frame followed by the entrypoint's payload as a single
    /// length-prefixed borsh frame, the form `read_lee_call` expects.
    fn write_call<T: BorshSerialize>(
        kind: CallKind,
        payload: &T,
        env_builder: &mut ExecutorEnvBuilder,
    ) -> Result<(), LeeError> {
        env_builder.write_slice(&to_borsh_frame(&kind));

        let payload =
            borsh::to_vec(payload).map_err(|e| LeeError::ProgramWriteInputFailed(e.to_string()))?;
        env_builder.write_slice(&to_frame(&payload));
        Ok(())
    }
}

/// Program deployment is permissionless, so a malformed frame or payload is an error rather
/// than a panic.
pub(crate) fn decode_guest_output(journal: &[u8]) -> Result<GuestOutput, LeeError> {
    let payload = from_frame(journal).ok_or_else(|| {
        LeeError::ProgramExecutionFailed("malformed program journal frame".to_owned())
    })?;
    borsh::from_slice(payload).map_err(|e| LeeError::ProgramExecutionFailed(e.to_string()))
}

/// A journal of the other entrypoint's shape is a hard reject, not a decode fallback: it is
/// what stops a planner receipt standing in for a resolver receipt under one image id.
pub(crate) fn planner_journal(journal: &[u8]) -> Result<ProgramOutput, LeeError> {
    match decode_guest_output(journal)? {
        GuestOutput::Execute(plan) => Ok(plan),
        GuestOutput::Resolve(_) => Err(wrong_entrypoint("plan", "resolution")),
    }
}

pub(crate) fn resolver_journal(journal: &[u8]) -> Result<ResolveOutput, LeeError> {
    match decode_guest_output(journal)? {
        GuestOutput::Resolve(resolution) => Ok(resolution),
        GuestOutput::Execute(_) => Err(wrong_entrypoint("resolution", "plan")),
    }
}

fn wrong_entrypoint(scheduled: &str, returned: &str) -> LeeError {
    LeeError::ProgramExecutionFailed(format!(
        "a scheduled {scheduled} returned a {returned} journal"
    ))
}
