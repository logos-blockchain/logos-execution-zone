/// This file will be compiled into the Guest Program.

use nssa_core::program::ProgramId;
use serde::{Deserialize, Serialize};

/// Return Route entrusted to Program B.
/// Program B must return this route when performing a tail-call back to A.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReturnRoute {
    pub caller_program_id: ProgramId,
    pub continuation_id: String,
    pub ticket_hash: [u8; 32],
    pub context_payload: Vec<u32>, // Program A's preserved local state
}

/// Instruction wrapper for compatibility with General/CPS calling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralCallInstruction {
    pub route: Option<ReturnRoute>, // None if this is the initial Tx from the user
    pub function_id: String,
    pub args: Vec<u32>,
}

/// Helper structure for reading the ZKVM environment (RISC Zero)
#[derive(Debug, Clone)]
pub struct ExecCtx {
    pub self_program_id: ProgramId,
    pub caller_program_id: Option<ProgramId>,
    pub pre_states: Vec<nssa_core::account::AccountWithMetadata>,
    pub raw_instruction_data: Vec<u32>,
}

impl ExecCtx {
    /// Reads the input injected by `Program::write_inputs` in the Sequencer
    pub fn read() -> Self {
        use risc0_zkvm::guest::env;
        Self {
            self_program_id: env::read(),
            caller_program_id: env::read(),
            pre_states: env::read(),
            raw_instruction_data: env::read(),
        }
    }
}

/// Global flag to inform the dispatcher that execution has been
/// redirected (tail-call), so the dispatcher does not need to write the output again.
pub static mut IS_TAIL_CALL: bool = false;