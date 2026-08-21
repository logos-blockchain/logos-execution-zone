//! Core data structures and constants for the Fee Program.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, Balance, Gas},
    program::{PdaSeed, ProgramId},
};

pub mod market;
pub mod state;

const FEE_STATE_SEED: [u8; 32] = *b"/LEZ/v0.3/FeeSeed/State/0000000/";
const FEE_ESCROW_SEED: [u8; 32] = *b"/LEZ/v0.3/FeeSeed/Escrow/000000/";
const FEE_INBOX_SEED: [u8; 32] = *b"/LEZ/v0.3/FeeSeed/Inbox/0000000/";

/// Per-block fee summary carried as the fee invocation's instruction and
/// validated byte-for-byte by the transition. All-zero until fee metering
/// lands.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BlockFeeSummary {
    pub gas_used_exec: Gas,
    pub gas_used_stor: Gas,
    pub revenue_base: Balance,
    pub revenue_tip: Balance,
}

/// The instruction type for the Fee Program.
pub type Instruction = BlockFeeSummary;

#[must_use]
pub const fn fee_state_seed() -> PdaSeed {
    PdaSeed::new(FEE_STATE_SEED)
}

#[must_use]
pub const fn fee_escrow_seed() -> PdaSeed {
    PdaSeed::new(FEE_ESCROW_SEED)
}

#[must_use]
pub const fn fee_inbox_seed() -> PdaSeed {
    PdaSeed::new(FEE_INBOX_SEED)
}

/// The fee-state account: base fees, payout window, and carry live in its `data`.
#[must_use]
pub fn compute_fee_state_account_id(fee_program_id: ProgramId) -> AccountId {
    AccountId::for_public_pda(&fee_program_id, &fee_state_seed())
}

/// The escrow account: its balance is the fee payout escrow.
#[must_use]
pub fn compute_fee_escrow_account_id(fee_program_id: ProgramId) -> AccountId {
    AccountId::for_public_pda(&fee_program_id, &fee_escrow_seed())
}

/// The inbox account: per-block fee collection point, zero outside the fee
/// invocation.
#[must_use]
pub fn compute_fee_inbox_account_id(fee_program_id: ProgramId) -> AccountId {
    AccountId::for_public_pda(&fee_program_id, &fee_inbox_seed())
}
