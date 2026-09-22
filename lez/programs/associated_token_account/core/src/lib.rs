use borsh::{BorshDeserialize, BorshSerialize};
pub use lee_core::program::PdaSeed;
use lee_core::{
    account::{AccountId, ShardData},
    program::AccountMeta,
};
use token_core::{TokenDescriptor, TokenHolding, TokenKind};

/// Associated token account instructions.
///
/// `token_program_id` selects the token definition and holding shards.
#[derive(BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Create the Associated Token Account for (owner, definition).
    ///
    /// Required accounts (3):
    /// - Owner account (address only)
    /// - Token definition account (under `token_program_id`)
    /// - Associated token account (under `token_program_id`)
    Create {
        token_program_id: AccountId,
        kind: TokenKind,
        contents: AtaContents,
    },

    /// Transfer tokens FROM owner's ATA to a recipient holding account.
    /// Uses PDA seeds to authorize the ATA in the chained Token::Transfer call.
    ///
    /// Required accounts (3):
    /// - Owner account (address only, authorized)
    /// - Sender ATA (owner's token holding, under `token_program_id`)
    /// - Recipient token holding (any account, under `token_program_id`; auto-created if empty)
    Transfer {
        token_program_id: AccountId,
        descriptor: TokenDescriptor,
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
        kind: TokenKind,
        amount: u128,
    },
}

// Untrusted: the guest is handed handles, not contents, so the branch `Create` used to read
// off the ATA's token shard now travels in the instruction, pinned by an effect on that shard.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum AtaContents {
    Empty,
    Intended,
    Squatted,
}

// The wallet calls this on observed state to propose a branch; the resolver calls it on actual
// state to verify that branch.
#[must_use]
pub fn classify(pre_data: &ShardData, descriptor: &TokenDescriptor) -> AtaContents {
    if pre_data.is_empty() {
        return AtaContents::Empty;
    }
    let Ok(holding) = TokenHolding::try_from(pre_data) else {
        return AtaContents::Squatted;
    };
    if holding.definition_id() == descriptor.definition_id
        && holds_definition_kind(holding.kind(), descriptor.kind)
    {
        AtaContents::Intended
    } else {
        AtaContents::Squatted
    }
}

// A non-fungible definition's master holding and its printed copies are both that definition's
// asset, which is the pairing the single-state `holds_intended_asset` accepted.
const fn holds_definition_kind(holding: TokenKind, definition: TokenKind) -> bool {
    match definition {
        TokenKind::Fungible => matches!(holding, TokenKind::Fungible),
        TokenKind::NftMaster | TokenKind::NftPrintedCopy => {
            matches!(holding, TokenKind::NftMaster | TokenKind::NftPrintedCopy)
        }
    }
}

pub fn compute_ata_seed(
    owner_id: AccountId,
    definition_id: AccountId,
    token_program_id: AccountId,
) -> PdaSeed {
    use risc0_zkvm::sha::{Impl, Sha256};
    let mut bytes = [0_u8; 96];
    bytes[0..32].copy_from_slice(&owner_id.to_bytes());
    bytes[32..64].copy_from_slice(&definition_id.to_bytes());
    bytes[64..96].copy_from_slice(&token_program_id.to_bytes());
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

/// Verifies the ATA address and returns its seed for chained calls.
pub fn verify_ata_and_get_seed(
    ata_account: &AccountMeta,
    owner: &AccountMeta,
    definition_id: AccountId,
    self_account_id: AccountId,
    token_program_id: AccountId,
) -> PdaSeed {
    let seed = compute_ata_seed(owner.account_id, definition_id, token_program_id);
    let expected_id = get_associated_token_account_id(&self_account_id, &seed);
    assert_eq!(
        ata_account.account_id, expected_id,
        "ATA account ID does not match expected derivation"
    );
    seed
}
