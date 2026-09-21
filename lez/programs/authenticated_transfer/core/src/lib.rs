//! Core data structures for the Authenticated Transfer Program.

use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(feature = "image_id")]
use lee_core::{
    account::{AccountId, ProgramShardSelector},
    program::{ChainedCall, PdaSeed},
};

#[cfg(feature = "image_id")]
include!(concat!(
    env!("OUT_DIR"),
    "/authenticated_transfer_image_id.rs"
));

/// This program's stable, `image_id`-independent name (see
/// [`lee_core::account::AccountId::from_builtin_program_name`]). Lives here, not in the
/// `programs` aggregator crate, since `programs` depends on this crate and `custody_transfer`
/// needs its own address.
pub const AUTHENTICATED_TRANSFER_NAME: [u8; 32] =
    lee_core::account::AccountId::pad_builtin_program_name(b"authenticated_transfer");

#[cfg(feature = "image_id")]
#[must_use]
pub fn authenticated_transfer_account_id() -> AccountId {
    AccountId::from_builtin_program_name(&AUTHENTICATED_TRANSFER_NAME)
}

/// Instruction type for the Authenticated Transfer program.
#[derive(BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Transfer `amount` of native balance from sender to recipient.
    ///
    /// Required accounts: `[sender, recipient]`.
    Transfer { amount: u128 },
}

/// A chained transfer out of an account the caller holds under `seed`.
#[cfg(feature = "image_id")]
#[must_use]
pub fn custody_transfer(
    from: AccountId,
    seed: PdaSeed,
    to: AccountId,
    amount: u128,
) -> ChainedCall {
    ChainedCall::new(
        authenticated_transfer_account_id(),
        vec![
            ProgramShardSelector::balance(from),
            ProgramShardSelector::balance(to),
        ],
        &Instruction::Transfer { amount },
    )
    .with_pda_seeds(vec![seed])
}
