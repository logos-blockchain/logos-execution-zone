use borsh::{BorshDeserialize, BorshSerialize};
pub use lee_core::program::PdaSeed;
use lee_core::{account::AccountId, program::ProgramId};

const FAUCET_SEED_DOMAIN_SEPARATOR: [u8; 32] = *b"/LEZ/v0.3/FaucetSeed/0000000000/";

#[derive(BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Transfers native tokens from the system faucet directly to a recipient account,
    /// crediting `slots[recipient_program]` there.
    ///
    /// Executed only in genesis block by sequencer it-self. User transactions will be denied.
    ///
    /// Required accounts (2):
    /// - Faucet PDA account
    /// - Recipient account
    GenesisTransferDirect {
        recipient_program: ProgramId,
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
