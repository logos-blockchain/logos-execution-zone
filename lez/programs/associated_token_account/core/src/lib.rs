use borsh::{BorshDeserialize, BorshSerialize};
pub use lee_core::program::PdaSeed;
use lee_core::{
    account::{AccountId, AccountWithMetadata},
    program::ProgramId,
};

#[derive(BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Create the Associated Token Account for (owner, definition).
    /// Idempotent: no-op if the account already exists.
    ///
    /// Required accounts (3):
    /// - Owner account
    /// - Token definition account
    /// - Associated token account (uninitialized, or already initialized)
    Create { token_program_id: ProgramId },

    /// Transfer tokens FROM owner's ATA to a recipient holding account.
    /// Passes the ATA's seed to the chained Token::Transfer call to authorize it.
    ///
    /// Required accounts (3):
    /// - Owner account (authorized)
    /// - Sender ATA (owner's token holding)
    /// - Recipient token holding (any account; auto-created if uninitialized)
    Transfer {
        token_program_id: ProgramId,
        amount: u128,
    },

    /// Burn tokens FROM owner's ATA.
    /// Passes the ATA's seed to the chained Token::Burn call to authorize it.
    ///
    /// Required accounts (3):
    /// - Owner account (authorized)
    /// - Owner's ATA (the holding to burn from)
    /// - Token definition account
    Burn {
        token_program_id: ProgramId,
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

pub fn get_associated_token_account_id(ata_program_id: &ProgramId, seed: &PdaSeed) -> AccountId {
    AccountId::for_public_pda(ata_program_id, seed)
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
