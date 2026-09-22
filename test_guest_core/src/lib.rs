//! Instruction types shared between the test guests and the hosts that drive them, so a guest
//! and its callers cannot drift apart.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::AccountId,
    program::{InstructionData, PdaSeed},
};

/// What `chain_caller` dispatches.
///
/// The callee is named by address rather than by bytecode identity: a program may be deployed at
/// an address that is not its own bijection, and a native program has no bytecode to identify.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ChainCall {
    pub callee_account_id: AccountId,
    pub instruction_data: InstructionData,
    pub calls: u32,
    pub pda_seed: Option<PdaSeed>,
}

impl ChainCall {
    #[must_use]
    pub const fn new(callee_account_id: AccountId, instruction_data: InstructionData) -> Self {
        Self {
            callee_account_id,
            instruction_data,
            calls: 1,
            pda_seed: None,
        }
    }

    #[must_use]
    pub const fn repeated(mut self, calls: u32) -> Self {
        self.calls = calls;
        self
    }

    #[must_use]
    pub const fn delegating(mut self, seed: PdaSeed) -> Self {
        self.pda_seed = Some(seed);
        self
    }
}
