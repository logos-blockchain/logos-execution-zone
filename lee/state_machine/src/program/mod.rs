use std::borrow::Cow;

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::Cycles,
    from_frame,
    program::{
        ApplyInput, ApplyOutput, CallKind, GuestOutput, InstructionData, PlanInput, PlanOutput,
        ProgramId,
    },
    to_borsh_frame, to_frame,
};
#[cfg(not(feature = "prove"))]
use risc0_zkvm::default_executor;
use risc0_zkvm::{ExecutorEnv, ExecutorEnvBuilder, ExitCode};

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
    pub exit_code: ExitCode,
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

    pub fn user_elf(&self) -> Result<Vec<u8>, LeeError> {
        Ok(risc0_binfmt::ProgramBinary::decode(&self.elf)
            .map_err(LeeError::InvalidProgramBytecode)?
            .user_elf
            .to_vec())
    }

    pub fn serialize_instruction<T: BorshSerialize>(
        instruction: T,
    ) -> Result<InstructionData, LeeError> {
        borsh::to_vec(&instruction)
            .map_err(|e| LeeError::InstructionSerializationError(e.to_string()))
    }

    pub(crate) fn plan(
        &self,
        input: &PlanInput,
        cycle_budget: Cycles,
    ) -> Result<(PlanOutput, Cycles), LeeError> {
        let (journal, cycles) =
            self.run(|env| Self::write_plan_inputs(input, env), cycle_budget)?;
        Ok((plan_journal(&journal)?, cycles))
    }

    pub(crate) fn apply(
        &self,
        input: &ApplyInput,
        cycle_budget: Cycles,
    ) -> Result<(ApplyOutput, Cycles), LeeError> {
        let (journal, cycles) =
            self.run(|env| Self::write_apply_inputs(input, env), cycle_budget)?;
        Ok((apply_journal(&journal)?, cycles))
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
                exit_code: info.exit_code,
            }
        });

        // NOTE: risc0 bails with an untyped anyhow error and the r0vm IPC path
        // flattens it to a string. the best we can do is a string match...
        let outcome = raw.map_err(|e| {
            // check the root cause specifically to avoid spoofed errors
            // like "Guest panicked: Session limit exceeded"
            if e.root_cause()
                .to_string()
                .starts_with("Session limit exceeded:")
            {
                LeeError::OutOfGas {
                    budget: cycle_budget,
                }
            } else {
                LeeError::ProgramExecutionFailed(e.to_string())
            }
        })?;

        check_exit_code(
            outcome.exit_code,
            outcome.cycles,
            LeeError::ProgramExecutionFailed,
        )?;
        Ok(outcome)
    }

    pub fn write_plan_inputs(
        input: &PlanInput,
        env_builder: &mut ExecutorEnvBuilder,
    ) -> Result<(), LeeError> {
        Self::write_call(CallKind::Plan, input, env_builder)
    }

    pub fn write_apply_inputs(
        input: &ApplyInput,
        env_builder: &mut ExecutorEnvBuilder,
    ) -> Result<(), LeeError> {
        Self::write_call(CallKind::Apply, input, env_builder)
    }

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

/// Gates a finished session on its exit code.
///
/// - `ExitCode::Halted(0)` is a success
/// - `ExitCode::Halted(code)` with a non-zero `code` is a cycle-counted failure
/// - `ExitCode::Paused(code)` is treated as a full failure as we do not expect `Pause`'s to occur
/// - Any other exit code is treated as a full failure
pub(crate) fn check_exit_code(
    exit_code: ExitCode,
    cycles: Cycles,
    on_failure: fn(String) -> LeeError,
) -> Result<(), LeeError> {
    match exit_code {
        ExitCode::Halted(0) => Ok(()),
        ExitCode::Halted(code) => Err(LeeError::ProgramExitedWithCode { code, cycles }),
        // A pause keeps its journal and count, but a program is one call to a final output and
        // the circuit's `env::verify` only resolves a `Halted(0)` claim, so it is a plain
        // failure on both paths and pays the full budget like a panic.
        ExitCode::Paused(code) => Err(on_failure(format!("program paused with code {code}"))),
        // `SystemSplit` never ends a session and `SessionLimit` is documented as never emitted
        // (risc0-binfmt `exit_code.rs`): the executor bails with "Session limit exceeded"
        // instead, which `execute_session` maps to `OutOfGas`.
        ExitCode::SessionLimit | ExitCode::SystemSplit | _ => {
            Err(on_failure(format!("unexpected exit {exit_code:?}")))
        }
    }
}

/// Re-attaches the protocol's fixed kernel ELF to `user_elf`, producing a full `ProgramBinary`
/// blob ready to decode and execute.
pub(crate) fn attach_kernel(user_elf: &[u8]) -> Vec<u8> {
    risc0_binfmt::ProgramBinary::new(user_elf, risc0_zkos_v1compat::V1COMPAT_ELF).encode()
}

pub(crate) fn decode_guest_output(journal: &[u8]) -> Result<GuestOutput, LeeError> {
    let payload = from_frame(journal).ok_or_else(|| {
        LeeError::ProgramExecutionFailed("malformed program journal frame".to_owned())
    })?;
    borsh::from_slice(payload).map_err(|e| LeeError::ProgramExecutionFailed(e.to_string()))
}

/// A journal of the other entrypoint's shape is a hard reject, not a decode fallback: it is
/// what stops a plan receipt standing in for an apply receipt under one image id.
pub(crate) fn plan_journal(journal: &[u8]) -> Result<PlanOutput, LeeError> {
    match decode_guest_output(journal)? {
        GuestOutput::Plan(plan) => Ok(plan),
        GuestOutput::Apply(_) => Err(wrong_entrypoint("plan", "an apply")),
    }
}

pub(crate) fn apply_journal(journal: &[u8]) -> Result<ApplyOutput, LeeError> {
    match decode_guest_output(journal)? {
        GuestOutput::Apply(output) => Ok(output),
        GuestOutput::Plan(_) => Err(wrong_entrypoint("apply", "a plan")),
    }
}

fn wrong_entrypoint(scheduled: &str, returned: &str) -> LeeError {
    LeeError::ProgramExecutionFailed(format!(
        "a scheduled {scheduled} returned {returned} journal"
    ))
}
