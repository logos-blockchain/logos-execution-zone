pub use nssa_core::program::PdaSeed;
use nssa_core::{
    account::{AccountId, AccountWithMetadata},
    program::ProgramId,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub enum Instruction {
    /// Create the Associated Token Account for (owner, definition).
    /// Idempotent: no-op if the account already exists.
    ///
    /// Required accounts (3):
    /// - Owner account
    /// - Token definition account
    /// - Associated token account (default/uninitialized, or already initialized)
    ///
    /// `token_program_id` is derived from `token_definition.account.program_owner`.
    Create { ata_program_id: ProgramId },

    /// Transfer tokens FROM owner's ATA to a recipient holding account.
    /// Uses PDA seeds to authorize the ATA in the chained Token::Transfer call.
    ///
    /// Required accounts (3):
    /// - Owner account (authorized)
    /// - Sender ATA (owner's token holding)
    /// - Recipient token holding (any account; auto-created if default)
    ///
    /// `token_program_id` is derived from `sender_ata.account.program_owner`.
    Transfer {
        ata_program_id: ProgramId,
        amount: u128,
    },

    /// Burn tokens FROM owner's ATA.
    /// Uses PDA seeds to authorize the ATA in the chained Token::Burn call.
    ///
    /// Required accounts (3):
    /// - Owner account (authorized)
    /// - Owner's ATA (the holding to burn from)
    /// - Token definition account
    ///
    /// `token_program_id` is derived from `holder_ata.account.program_owner`.
    Burn {
        ata_program_id: ProgramId,
        amount: u128,
    },
}

pub fn compute_ata_seed(owner_id: AccountId, definition_id: AccountId) -> PdaSeed {
    use risc0_zkvm::sha::{Impl, Sha256};
    let mut bytes = [0u8; 64];
    bytes[0..32].copy_from_slice(&owner_id.to_bytes());
    bytes[32..64].copy_from_slice(&definition_id.to_bytes());
    PdaSeed::new(
        Impl::hash_bytes(&bytes)
            .as_bytes()
            .try_into()
            .expect("Hash output must be exactly 32 bytes long"),
    )
}

pub fn get_associated_token_account_id(ata_program_id: &ProgramId, seed: &PdaSeed) -> AccountId {
    AccountId::from((ata_program_id, seed))
}

/// Verify the ATA's address matches `(ata_program_id, owner, definition)` and return
/// the [`PdaSeed`] for use in chained calls.
pub fn verify_ata_and_get_seed(
    ata_account: &AccountWithMetadata,
    owner: &AccountWithMetadata,
    definition_id: AccountId,
    ata_program_id: ProgramId,
) -> PdaSeed {
    let seed = compute_ata_seed(owner.account_id, definition_id);
    let expected_id = get_associated_token_account_id(&ata_program_id, &seed);
    assert_eq!(
        ata_account.account_id, expected_id,
        "ATA account ID does not match expected derivation"
    );
    seed
}
