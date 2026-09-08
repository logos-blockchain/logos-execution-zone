#![cfg(test)]

use associated_token_account_core::{compute_ata_seed, get_associated_token_account_id};
use lee_core::account::{AccountId, AccountInput, Data};
use token_core::{TokenDefinition, TokenHolding};

const ATA_PROGRAM_ID: AccountId = AccountId::new([1u8; 32]);
const TOKEN_PROGRAM_ID: AccountId = AccountId::new([2u8; 32]);

fn owner_id() -> AccountId {
    AccountId::new([0x01u8; 32])
}

fn definition_id() -> AccountId {
    AccountId::new([0x02u8; 32])
}

fn ata_id() -> AccountId {
    get_associated_token_account_id(
        &ATA_PROGRAM_ID,
        &compute_ata_seed(owner_id(), definition_id(), TOKEN_PROGRAM_ID),
    )
}

fn owner_account() -> AccountInput {
    AccountInput::balance_only(owner_id(), true, 0)
}

fn definition_account() -> AccountInput {
    AccountInput::with_shard(
        definition_id(),
        false,
        0,
        TOKEN_PROGRAM_ID,
        Data::from(&TokenDefinition::Fungible {
            name: "TEST".to_string(),
            total_supply: 1000,
            metadata_id: None,
        }),
    )
}

fn uninitialized_ata_account() -> AccountInput {
    AccountInput::with_shard(ata_id(), false, 0, TOKEN_PROGRAM_ID, Data::empty())
}

fn initialized_ata_account() -> AccountInput {
    AccountInput::with_shard(
        ata_id(),
        false,
        0,
        TOKEN_PROGRAM_ID,
        Data::from(&TokenHolding::Fungible {
            definition_id: definition_id(),
            balance: 100,
        }),
    )
}

#[test]
fn create_emits_chained_call_for_uninitialized_ata() {
    let (post_diffs, chained_calls) = crate::create::create_associated_token_account(
        owner_account(),
        definition_account(),
        uninitialized_ata_account(),
        ATA_PROGRAM_ID,
        TOKEN_PROGRAM_ID,
    );

    assert_eq!(post_diffs.len(), 3);
    assert_eq!(chained_calls.len(), 1);
    assert_eq!(chained_calls[0].program_account_id, TOKEN_PROGRAM_ID);
}

#[test]
fn create_is_idempotent_for_initialized_ata() {
    let (post_diffs, chained_calls) = crate::create::create_associated_token_account(
        owner_account(),
        definition_account(),
        initialized_ata_account(),
        ATA_PROGRAM_ID,
        TOKEN_PROGRAM_ID,
    );

    assert_eq!(post_diffs.len(), 3);
    assert!(
        chained_calls.is_empty(),
        "Should emit no chained call for already-initialized ATA"
    );
}

#[test]
#[should_panic(expected = "ATA account ID does not match expected derivation")]
fn create_panics_on_wrong_ata_address() {
    let wrong_ata = AccountInput::with_shard(
        AccountId::new([0xFFu8; 32]),
        false,
        0,
        TOKEN_PROGRAM_ID,
        Data::empty(),
    );

    crate::create::create_associated_token_account(
        owner_account(),
        definition_account(),
        wrong_ata,
        ATA_PROGRAM_ID,
        TOKEN_PROGRAM_ID,
    );
}

#[test]
fn get_associated_token_account_id_is_deterministic() {
    let seed = compute_ata_seed(owner_id(), definition_id(), TOKEN_PROGRAM_ID);
    let id1 = get_associated_token_account_id(&ATA_PROGRAM_ID, &seed);
    let id2 = get_associated_token_account_id(&ATA_PROGRAM_ID, &seed);
    assert_eq!(id1, id2);
}

#[test]
fn get_associated_token_account_id_differs_by_owner() {
    let other_owner = AccountId::new([0x99u8; 32]);
    let id1 = get_associated_token_account_id(
        &ATA_PROGRAM_ID,
        &compute_ata_seed(owner_id(), definition_id(), TOKEN_PROGRAM_ID),
    );
    let id2 = get_associated_token_account_id(
        &ATA_PROGRAM_ID,
        &compute_ata_seed(other_owner, definition_id(), TOKEN_PROGRAM_ID),
    );
    assert_ne!(id1, id2);
}

#[test]
fn get_associated_token_account_id_differs_by_definition() {
    let other_def = AccountId::new([0x99u8; 32]);
    let id1 = get_associated_token_account_id(
        &ATA_PROGRAM_ID,
        &compute_ata_seed(owner_id(), definition_id(), TOKEN_PROGRAM_ID),
    );
    let id2 = get_associated_token_account_id(
        &ATA_PROGRAM_ID,
        &compute_ata_seed(owner_id(), other_def, TOKEN_PROGRAM_ID),
    );
    assert_ne!(id1, id2);
}

#[test]
fn the_ata_of_a_stranger_program_is_a_different_address() {
    let stranger = AccountId::new([0xEEu8; 32]);
    assert_ne!(
        get_associated_token_account_id(
            &ATA_PROGRAM_ID,
            &compute_ata_seed(owner_id(), definition_id(), TOKEN_PROGRAM_ID),
        ),
        get_associated_token_account_id(
            &ATA_PROGRAM_ID,
            &compute_ata_seed(owner_id(), definition_id(), stranger),
        ),
        "each token program must get its own ATA family"
    );
}

#[test]
#[should_panic(expected = "ATA account ID does not match expected derivation")]
fn create_naming_a_stranger_program_cannot_reach_the_real_ata() {
    let stranger = AccountId::new([0xEEu8; 32]);
    crate::create::create_associated_token_account(
        owner_account(),
        definition_account(),
        AccountInput::with_shard(ata_id(), false, 0, stranger, Data::empty()),
        ATA_PROGRAM_ID,
        stranger,
    );
}
