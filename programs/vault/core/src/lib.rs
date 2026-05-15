pub use nssa_core::program::PdaSeed;
use nssa_core::{account::AccountId, program::ProgramId};
use serde::{Deserialize, Serialize};

const VAULT_SEED_DOMAIN_SEPARATOR: &[u8] = b"/LEZ/v0.3/VaultSeed/00000000000/";

const _: () = assert!(
    VAULT_SEED_DOMAIN_SEPARATOR.len() == 32,
    "Domain separator must be exactly 32 bytes long"
);

#[derive(Serialize, Deserialize)]
pub enum Instruction {
    /// Transfers native tokens from sender to recipient's vault.
    ///
    /// Required accounts (3):
    /// - Sender account
    /// - Recipient account
    /// - Recipient vault PDA account
    Transfer {
        recipient_id: AccountId,
        amount: u128,
    },

    /// Claims native tokens from owner's vault into owner's account.
    ///
    /// Required accounts (2):
    /// - Owner account
    /// - Owner vault PDA account
    Claim { amount: u128 },
}

#[must_use]
pub fn compute_vault_seed(owner_id: AccountId) -> PdaSeed {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    let mut bytes = [0_u8; 64];
    bytes[..32].copy_from_slice(VAULT_SEED_DOMAIN_SEPARATOR);
    bytes[32..64].copy_from_slice(&owner_id.to_bytes());

    PdaSeed::new(
        Impl::hash_bytes(&bytes)
            .as_bytes()
            .try_into()
            .expect("Hash output must be exactly 32 bytes long"),
    )
}

#[must_use]
pub fn compute_vault_account_id(vault_program_id: ProgramId, owner_id: AccountId) -> AccountId {
    let seed = compute_vault_seed(owner_id);
    AccountId::for_public_pda(&vault_program_id, &seed)
}
