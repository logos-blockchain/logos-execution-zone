use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::account::AccountId;
pub use lee_core::program::PdaSeed;
use token_core::{TokenDescriptor, TokenKind};

pub const ASSOCIATED_TOKEN_ACCOUNT_NAME: [u8; 24] = *b"associated_token_account";

#[derive(BorshSerialize, BorshDeserialize)]
pub enum Message {
    Create {
        token_program_id: AccountId,
        definition_id: AccountId,
        kind: TokenKind,
    },
    Transfer {
        token_program_id: AccountId,
        to: AccountId,
        descriptor: TokenDescriptor,
        amount: u128,
    },
    Burn {
        token_program_id: AccountId,
        descriptor: TokenDescriptor,
        amount: u128,
    },
}

#[must_use]
pub fn ata_account_id() -> AccountId {
    AccountId::from_builtin_program_name(&ASSOCIATED_TOKEN_ACCOUNT_NAME)
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

#[must_use]
pub fn ata_of(
    ata_program: AccountId,
    owner: AccountId,
    definition_id: AccountId,
    token_program_id: AccountId,
) -> (AccountId, PdaSeed) {
    let seed = compute_ata_seed(owner, definition_id, token_program_id);
    (get_associated_token_account_id(&ata_program, &seed), seed)
}
