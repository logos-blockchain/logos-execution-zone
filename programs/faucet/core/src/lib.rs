pub use nssa_core::program::PdaSeed;
use nssa_core::{account::AccountId, program::ProgramId};
use serde::{Deserialize, Serialize};

const FAUCET_SEED_DOMAIN_SEPARATOR: [u8; 32] = *b"/LEZ/v0.3/FaucetSeed/0000000000/";

#[derive(Serialize, Deserialize)]
pub enum Instruction {
    /// Transfers native tokens from system faucet to recipient's vault.
    ///
    /// Required accounts (2):
    /// - Faucet PDA account
    /// - Recipient vault PDA account
    Transfer {
        vault_program_id: ProgramId,
        recipient_id: AccountId,
        amount: u128,
    },
}

#[must_use]
pub const fn compute_faucet_seed() -> PdaSeed {
    PdaSeed::new(FAUCET_SEED_DOMAIN_SEPARATOR)
}

#[must_use]
pub fn compute_faucet_account_id(faucet_program_id: ProgramId) -> AccountId {
    AccountId::for_public_pda(&faucet_program_id, &compute_faucet_seed())
}
