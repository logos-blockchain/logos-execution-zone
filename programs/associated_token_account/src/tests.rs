#![cfg(test)]

use ata_core::get_associated_token_account_id;
use nssa_core::account::{Account, AccountId, AccountWithMetadata, Data};
use token_core::{TokenDefinition, TokenHolding};

const ATA_PROGRAM_ID: nssa_core::program::ProgramId = [1u32; 8];
const TOKEN_PROGRAM_ID: nssa_core::program::ProgramId = [2u32; 8];

fn owner_id() -> AccountId {
    AccountId::new([0x01u8; 32])
}

fn definition_id() -> AccountId {
    AccountId::new([0x02u8; 32])
}

fn ata_id() -> AccountId {
    get_associated_token_account_id(&ATA_PROGRAM_ID, owner_id(), definition_id())
}

fn owner_account() -> AccountWithMetadata {
    AccountWithMetadata {
        account: Account::default(),
        is_authorized: true,
        account_id: owner_id(),
    }
}

fn definition_account() -> AccountWithMetadata {
    AccountWithMetadata {
        account: Account {
            program_owner: TOKEN_PROGRAM_ID,
            balance: 0,
            data: Data::from(&TokenDefinition::Fungible {
                name: "TEST".to_string(),
                total_supply: 1000,
                metadata_id: None,
            }),
            nonce: 0,
        },
        is_authorized: false,
        account_id: definition_id(),
    }
}

fn uninitialized_ata_account() -> AccountWithMetadata {
    AccountWithMetadata {
        account: Account::default(),
        is_authorized: false,
        account_id: ata_id(),
    }
}

fn initialized_ata_account() -> AccountWithMetadata {
    AccountWithMetadata {
        account: Account {
            program_owner: TOKEN_PROGRAM_ID,
            balance: 0,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: definition_id(),
                balance: 100,
            }),
            nonce: 0,
        },
        is_authorized: false,
        account_id: ata_id(),
    }
}

#[test]
fn create_emits_chained_call_for_uninitialized_ata() {
    let (post_states, chained_calls) = crate::create::create_associated_token_account(
        owner_account(),
        definition_account(),
        uninitialized_ata_account(),
        ATA_PROGRAM_ID,
    );

    assert_eq!(post_states.len(), 3);
    assert_eq!(chained_calls.len(), 1);
    assert_eq!(chained_calls[0].program_id, TOKEN_PROGRAM_ID);
}

#[test]
fn create_is_idempotent_for_initialized_ata() {
    let (post_states, chained_calls) = crate::create::create_associated_token_account(
        owner_account(),
        definition_account(),
        initialized_ata_account(),
        ATA_PROGRAM_ID,
    );

    assert_eq!(post_states.len(), 3);
    assert!(
        chained_calls.is_empty(),
        "Should emit no chained call for already-initialized ATA"
    );
}

#[test]
#[should_panic(expected = "ATA account ID does not match expected derivation")]
fn create_panics_on_wrong_ata_address() {
    let wrong_ata = AccountWithMetadata {
        account: Account::default(),
        is_authorized: false,
        account_id: AccountId::new([0xFFu8; 32]),
    };

    crate::create::create_associated_token_account(
        owner_account(),
        definition_account(),
        wrong_ata,
        ATA_PROGRAM_ID,
    );
}

#[test]
fn get_associated_token_account_id_is_deterministic() {
    let id1 = get_associated_token_account_id(&ATA_PROGRAM_ID, owner_id(), definition_id());
    let id2 = get_associated_token_account_id(&ATA_PROGRAM_ID, owner_id(), definition_id());
    assert_eq!(id1, id2);
}

#[test]
fn get_associated_token_account_id_differs_by_owner() {
    let other_owner = AccountId::new([0x99u8; 32]);
    let id1 = get_associated_token_account_id(&ATA_PROGRAM_ID, owner_id(), definition_id());
    let id2 = get_associated_token_account_id(&ATA_PROGRAM_ID, other_owner, definition_id());
    assert_ne!(id1, id2);
}

#[test]
fn get_associated_token_account_id_differs_by_definition() {
    let other_def = AccountId::new([0x99u8; 32]);
    let id1 = get_associated_token_account_id(&ATA_PROGRAM_ID, owner_id(), definition_id());
    let id2 = get_associated_token_account_id(&ATA_PROGRAM_ID, owner_id(), other_def);
    assert_ne!(id1, id2);
}
