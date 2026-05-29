pub use lee_core::program::PdaSeed;
use lee_core::{account::AccountId, program::ProgramId};
use serde::{Deserialize, Serialize};

const BRIDGE_SEED_DOMAIN_SEPARATOR: [u8; 32] = *b"/LEZ/v0.3/BridgeSeed/0000000000/";

#[derive(Serialize, Deserialize)]
pub enum Instruction {
    /// Transfers native tokens from the bridge PDA account to a recipient vault.
    ///
    /// Required accounts (2):
    /// - Bridge PDA account
    /// - Recipient vault PDA account
    Deposit {
        /// Deposit OP ID from L1, stored here to pin each [`Deposit`](Instruction::Deposit) to a
        /// Deposit Event on L1.
        l1_deposit_op_id: [u8; 32],
        vault_program_id: ProgramId,
        recipient_id: AccountId,
        amount: u128,
    },
}

#[must_use]
pub const fn compute_bridge_seed() -> PdaSeed {
    PdaSeed::new(BRIDGE_SEED_DOMAIN_SEPARATOR)
}

#[must_use]
pub fn compute_bridge_account_id(bridge_program_id: ProgramId) -> AccountId {
    AccountId::for_public_pda(&bridge_program_id, &compute_bridge_seed())
}
