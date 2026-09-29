//! Core data structures and constants for the Fee Program.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, Balance, Gas},
    program::PdaSeed,
};

pub mod assess;
pub mod market;
pub mod state;
pub mod validity;

const FEE_STATE_SEED: [u8; 32] = *b"/LEZ/v0.3/FeeSeed/State/0000000/";
const FEE_ESCROW_SEED: [u8; 32] = *b"/LEZ/v0.3/FeeSeed/Escrow/000000/";
const FEE_INBOX_SEED: [u8; 32] = *b"/LEZ/v0.3/FeeSeed/Inbox/0000000/";

pub const FEE_NAME: [u8; 3] = *b"fee";

/// Per-block fee summary carried as the fee invocation's instruction and
/// validated byte-for-byte by the transition.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BlockFeeSummary {
    pub gas_used_exec: Gas,
    pub gas_used_stor: Gas,
    pub revenue_base: Balance,
    pub revenue_tip: Balance,
}

/// The message type for the Fee Program, sent to the fee-state actor
/// `(compute_fee_state_account_id(self), fee)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Message {
    /// Block-tail distribution: apply the market update, drain the inbox (base
    /// revenue to escrow, tips to `producer`), and pay `producer` the smoothed
    /// payout. `payout` is that smoothed share; [`state::FeeState::apply_block`]
    /// returns it.
    Distribute {
        summary: BlockFeeSummary,
        payout: Balance,
        producer: AccountId,
    },
    /// Per-transaction refund: return `amount` (the unspent part of the reserve)
    /// from the inbox to `payer`.
    Refund { amount: Balance, payer: AccountId },
}

#[must_use]
pub fn fee_account_id() -> AccountId {
    AccountId::from_builtin_program_name(&FEE_NAME)
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

/// The fee-state account, which stores base fees, the payout window, and carry.
#[must_use]
pub fn compute_fee_state_account_id(fee_account_id: AccountId) -> AccountId {
    AccountId::for_public_pda(&fee_account_id, &fee_state_seed())
}

/// The escrow account: its balance is the fee payout escrow.
#[must_use]
pub fn compute_fee_escrow_account_id(fee_account_id: AccountId) -> AccountId {
    AccountId::for_public_pda(&fee_account_id, &fee_escrow_seed())
}

/// The inbox account: per-block fee collection point, zero outside the fee
/// invocation.
#[must_use]
pub fn compute_fee_inbox_account_id(fee_account_id: AccountId) -> AccountId {
    AccountId::for_public_pda(&fee_account_id, &fee_inbox_seed())
}
