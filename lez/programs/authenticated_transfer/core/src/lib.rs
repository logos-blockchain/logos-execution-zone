//! Core data structures for the Authenticated Transfer Program.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::AccountWithMetadata,
    program::{ChainedCall, PdaSeed, ProgramId},
};

/// Instruction type for the Authenticated Transfer program.
#[derive(BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Transfer `amount` of native balance from sender to recipient.
    ///
    /// Required accounts: `[sender, recipient]`.
    Transfer { amount: u128 },
}

/// A chained transfer out of an account the caller holds under `seed`.
#[must_use]
pub fn custody_transfer(
    program_id: ProgramId,
    mut from: AccountWithMetadata,
    seed: PdaSeed,
    to: AccountWithMetadata,
    amount: u128,
) -> ChainedCall {
    from.is_authorized = true;
    ChainedCall::new(
        program_id,
        vec![from, to],
        &Instruction::Transfer { amount },
    )
    .with_pda_seeds(vec![seed])
}
