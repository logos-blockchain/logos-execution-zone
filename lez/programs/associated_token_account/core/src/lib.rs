use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::account::{AccountId, Input};
pub use lee_core::program::PdaSeed;

/// Every variant carries `token_program_id`, the token program this ATA belongs to. It is the
/// caller's pin, and the namespace the definition and holding positions name; this program's own
/// address, which the ATA derivation needs, is `self_account_id`.
#[derive(BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Create the Associated Token Account for (owner, definition).
    /// Idempotent: no-op if the account already exists.
    ///
    /// Required accounts (3):
    /// - Owner account (address only)
    /// - Token definition account (under `token_program_id`)
    /// - Associated token account (under `token_program_id`; empty, or already initialized)
    Create { token_program_id: AccountId },

    /// Transfer tokens FROM owner's ATA to a recipient holding account.
    /// Uses PDA seeds to authorize the ATA in the chained Token::Transfer call.
    ///
    /// Required accounts (3):
    /// - Owner account (address only, authorized)
    /// - Sender ATA (owner's token holding, under `token_program_id`)
    /// - Recipient token holding (any account, under `token_program_id`; auto-created if empty)
    Transfer {
        token_program_id: AccountId,
        amount: u128,
    },

    /// Burn tokens FROM owner's ATA.
    /// Uses PDA seeds to authorize the ATA in the chained Token::Burn call.
    ///
    /// Required accounts (3):
    /// - Owner account (address only, authorized)
    /// - Owner's ATA (the holding to burn from, under `token_program_id`)
    /// - Token definition account (under `token_program_id`)
    Burn {
        token_program_id: AccountId,
        amount: u128,
    },
}

pub fn compute_ata_seed(owner_id: AccountId, definition_id: AccountId) -> PdaSeed {
    use risc0_zkvm::sha::{Impl, Sha256};
    let mut bytes = [0_u8; 64];
    bytes[0..32].copy_from_slice(&owner_id.to_bytes());
    bytes[32..64].copy_from_slice(&definition_id.to_bytes());
    PdaSeed::new(
        Impl::hash_bytes(&bytes)
            .as_bytes()
            .try_into()
            .expect("Hash output must be exactly 32 bytes long"),
    )
}

pub fn get_associated_token_account_id(ata_program_id: &AccountId, seed: &PdaSeed) -> AccountId {
    AccountId::for_public_pda(ata_program_id, seed)
}

/// Verify the ATA's address matches `(self_account_id, owner, definition)` and return
/// the [`PdaSeed`] for use in chained calls.
pub fn verify_ata_and_get_seed(
    ata_account: &Input,
    owner: &Input,
    definition_id: AccountId,
    self_account_id: AccountId,
) -> PdaSeed {
    let seed = compute_ata_seed(owner.account_id, definition_id);
    let expected_id = get_associated_token_account_id(&self_account_id, &seed);
    assert_eq!(
        ata_account.account_id, expected_id,
        "ATA account ID does not match expected derivation"
    );
    seed
}
