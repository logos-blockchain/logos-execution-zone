//! The Token Program implementation.

use lee_core::{
    account::{AccountId, AccountWithMetadata},
    program::{PdaSeed, ProgramId},
};
pub use token_core as core;

pub mod burn;
pub mod initialize;
pub mod mint;
pub mod new_definition;
pub mod print_nft;
pub mod transfer;

mod tests;

pub(crate) fn seed_authorized(
    account: &AccountWithMetadata,
    caller_program_id: Option<ProgramId>,
    seed: Option<PdaSeed>,
) -> bool {
    account.is_authorized
        || caller_program_id.zip(seed).is_some_and(|(caller, seed)| {
            account.account_id == AccountId::for_public_pda(&caller, &seed)
        })
}
