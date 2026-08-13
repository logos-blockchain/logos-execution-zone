pub use lee_core::program::PdaSeed;
use lee_core::{account::AccountId, program::ProgramId};

const PINATA_PRIZE_SEED_DOMAIN_SEPARATOR: [u8; 32] = *b"/LEZ/v0.3/PinataPrizeSeed/00000/";

#[must_use]
pub const fn compute_pinata_prize_seed() -> PdaSeed {
    PdaSeed::new(PINATA_PRIZE_SEED_DOMAIN_SEPARATOR)
}

#[must_use]
pub fn compute_pinata_prize_account_id(pinata_program_id: ProgramId) -> AccountId {
    AccountId::for_public_pda(&pinata_program_id, &compute_pinata_prize_seed())
}
