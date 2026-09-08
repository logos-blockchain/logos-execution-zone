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
        AUTHENTICATED_TRANSFER_IMAGE_ID.into(),
        vec![
            ProgramShardSelector::balance_only(from),
            ProgramShardSelector::balance_only(to),
        ],
        &Instruction::Transfer { amount },
    )
    .with_pda_seeds(vec![seed])
}
