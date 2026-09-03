//! Core data structures and constants for the Fee Program.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, Balance, Gas},
    program::{PdaSeed, ProgramId},
};

pub mod assess;
pub mod market;
pub mod state;
pub mod validity;

const FEE_STATE_SEED: [u8; 32] = *b"/LEZ/v0.3/FeeSeed/State/0000000/";
const FEE_ESCROW_SEED: [u8; 32] = *b"/LEZ/v0.3/FeeSeed/Escrow/000000/";
const FEE_INBOX_SEED: [u8; 32] = *b"/LEZ/v0.3/FeeSeed/Inbox/0000000/";

/// Per-block fee summary carried as the fee invocation's instruction and
/// validated byte-for-byte by the transition.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BlockFeeSummary {
    pub gas_used_exec: Gas,
    pub gas_used_stor: Gas,
    pub revenue_base: Balance,
    pub revenue_tip: Balance,
}

/// The instruction type for the Fee Program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Block-tail distribution: apply the market update, drain the inbox (base
    /// revenue to escrow, tips to the producer), and pay the smoothed payout.
    ///
    /// Accounts: `[state, escrow, inbox, producer]`.
    Distribute(BlockFeeSummary),
    /// Per-transaction refund: return `amount` (the unspent part of the reserve)
    /// from the inbox to the payer.
    ///
    /// Accounts: `[inbox, payer]`.
    Refund { amount: Balance },
}

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
