use borsh::{BorshDeserialize, BorshSerialize};
pub use lee_core::program::PdaSeed;
use lee_core::{account::AccountId, program::ProgramId};

const FAUCET_SEED_DOMAIN_SEPARATOR: [u8; 32] = *b"/LEZ/v0.3/FaucetSeed/0000000000/";

#[derive(BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Transfers native tokens from system faucet to recipient's vault.
    ///
    /// Executed only in genesis block by sequencer it-self. User transactions will be denied.
    ///
    /// Required accounts (2):
    /// - Faucet PDA account
    /// - Recipient vault PDA account
    GenesisTransferVault {
        /// This program's own image id. The guest cannot learn this at runtime (a RISC0 guest
        /// has no way to read its own image id), so the trusted genesis caller supplies it to
        /// recompute the faucet PDA; a wrong value only fails the guest's own self-consistency
        /// assertion, since real authorization is independently enforced by the state layer
        /// against the account's `program_owner`.
        self_program_id: ProgramId,
        /// The vault program's real dispatch address.
        vault_account_id: AccountId,
        recipient_id: AccountId,
        amount: u128,
    },

    /// Transfers native tokens from system faucet directly to a recipient account.
    ///
    /// Executed only in genesis block by sequencer it-self. User transactions will be denied.
    ///
    /// Required accounts (2):
    /// - Faucet PDA account
    /// - Recipient account
    GenesisTransferDirect {
        /// See `GenesisTransferVault::self_program_id`.
        self_program_id: ProgramId,
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
