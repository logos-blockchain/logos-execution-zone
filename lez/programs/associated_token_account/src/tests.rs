#![cfg(test)]

use associated_token_account_core::{compute_ata_seed, get_associated_token_account_id};
use lee_core::account::{AccountId, Data, Input, Slot};
use token_core::{TokenDefinition, TokenHolding};

const ATA_PROGRAM_ID: lee_core::program::ProgramId = [1_u32; 8];
const TOKEN_PROGRAM_ID: lee_core::program::ProgramId = [2_u32; 8];

fn owner_id() -> AccountId {
    AccountId::new([0x01_u8; 32])
}

fn definition_id() -> AccountId {
    AccountId::new([0x02_u8; 32])
}

fn ata_id() -> AccountId {
    get_associated_token_account_id(
        &ATA_PROGRAM_ID,
        &compute_ata_seed(owner_id(), definition_id()),
    )
}

fn owner_account() -> Input {
    Input::named(owner_id(), true, TOKEN_PROGRAM_ID, Slot::default())
}

fn definition_account() -> Input {
    Input::named(
        definition_id(),
        false,
        TOKEN_PROGRAM_ID,
        Slot {
            balance: 0,
            data: Data::from(&TokenDefinition::Fungible {
                name: "TEST".to_owned(),
                total_supply: 1000,
                metadata_id: None,
            }),
        },
    )
}

fn uninitialized_ata_account() -> Input {
    Input::named(ata_id(), false, TOKEN_PROGRAM_ID, Slot::default())
}

fn initialized_ata_account() -> Input {
    Input::named(
        ata_id(),
        false,
        TOKEN_PROGRAM_ID,
        Slot {
            balance: 0,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: definition_id(),
                balance: 100,
            }),
        },
    )
}

#[test]
fn create_emits_chained_call_for_uninitialized_ata() {
    let (post_states, chained_calls) = crate::create::create_associated_token_account(
        owner_account(),
        definition_account(),
        uninitialized_ata_account(),
        ATA_PROGRAM_ID,
        TOKEN_PROGRAM_ID,
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
        TOKEN_PROGRAM_ID,
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
    let wrong_ata = Input::named(
        AccountId::new([0xFF_u8; 32]),
        false,
        TOKEN_PROGRAM_ID,
        Slot::default(),
    );

    let post_states = crate::create::create_associated_token_account(
        owner_account(),
        definition_account(),
        wrong_ata,
        ATA_PROGRAM_ID,
        TOKEN_PROGRAM_ID,
    );

    unreachable!("a mis-derived ATA address must panic, got {post_states:?}");
}

#[test]
fn get_associated_token_account_id_is_deterministic() {
    let seed = compute_ata_seed(owner_id(), definition_id());
    let id1 = get_associated_token_account_id(&ATA_PROGRAM_ID, &seed);
    let id2 = get_associated_token_account_id(&ATA_PROGRAM_ID, &seed);
    assert_eq!(id1, id2);
}

#[test]
fn get_associated_token_account_id_differs_by_owner() {
    let other_owner = AccountId::new([0x99_u8; 32]);
    let id1 = get_associated_token_account_id(
        &ATA_PROGRAM_ID,
        &compute_ata_seed(owner_id(), definition_id()),
    );
    let id2 = get_associated_token_account_id(
        &ATA_PROGRAM_ID,
        &compute_ata_seed(other_owner, definition_id()),
    );
    assert_ne!(id1, id2);
}

#[test]
fn get_associated_token_account_id_differs_by_definition() {
    let other_def = AccountId::new([0x99_u8; 32]);
    let id1 = get_associated_token_account_id(
        &ATA_PROGRAM_ID,
        &compute_ata_seed(owner_id(), definition_id()),
    );
    let id2 =
        get_associated_token_account_id(&ATA_PROGRAM_ID, &compute_ata_seed(owner_id(), other_def));
    assert_ne!(id1, id2);
}

/// An ATA cannot sign, so closing it goes through this program's seed. The seed comes
/// from the definition the ATA is derived from, not from the holding sitting there —
/// which is what makes a stranger's mismatched holding clearable.
#[test]
fn close_delegates_the_ata_seed_for_a_foreign_definition() {
    let squatted = Input::named(
        ata_id(),
        false,
        TOKEN_PROGRAM_ID,
        Slot {
            balance: 0,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: AccountId::new([0xEE_u8; 32]),
                balance: 0,
            }),
        },
    );

    let (_post_states, chained_calls) = crate::close::close_associated_token_account(
        owner_account(),
        squatted,
        definition_account(),
        ATA_PROGRAM_ID,
        TOKEN_PROGRAM_ID,
    );

    let [call] = <[_; 1]>::try_from(chained_calls).unwrap();
    assert_eq!(
        call.pda_seeds,
        vec![compute_ata_seed(owner_id(), definition_id())]
    );
    assert!(call.pre_states[0].is_authorized);
    assert_eq!(call.pre_states[0].account_id, ata_id());
}

#[should_panic(expected = "Owner authorization is missing")]
#[test]
fn close_without_owner_authorization_should_fail() {
    let owner = Input {
        is_authorized: false,
        ..owner_account()
    };
    let ata = Input::named(ata_id(), false, TOKEN_PROGRAM_ID, Slot::default());

    let post_states = crate::close::close_associated_token_account(
        owner,
        ata,
        definition_account(),
        ATA_PROGRAM_ID,
        TOKEN_PROGRAM_ID,
    );

    unreachable!("an unauthorized owner must panic, got {post_states:?}");
}

#[should_panic(expected = "ATA account ID does not match expected derivation")]
#[test]
fn close_at_a_non_ata_address_should_fail() {
    let not_an_ata = Input::named(
        AccountId::new([0x77_u8; 32]),
        false,
        TOKEN_PROGRAM_ID,
        Slot::default(),
    );

    let post_states = crate::close::close_associated_token_account(
        owner_account(),
        not_an_ata,
        definition_account(),
        ATA_PROGRAM_ID,
        TOKEN_PROGRAM_ID,
    );

    unreachable!("a non-ATA address must panic, got {post_states:?}");
}

/// A bare credit into the token slot leaves it present but empty. `Create` must still
/// chain `InitializeAccount` rather than treating the address as already in use.
#[test]
fn create_is_not_suppressed_by_a_bare_credit() {
    let ata = Input::named(
        ata_id(),
        false,
        TOKEN_PROGRAM_ID,
        Slot {
            balance: 1,
            data: Data::default(),
        },
    );

    let (_post_states, chained_calls) = crate::create::create_associated_token_account(
        owner_account(),
        definition_account(),
        ata,
        ATA_PROGRAM_ID,
        TOKEN_PROGRAM_ID,
    );

    assert_eq!(chained_calls.len(), 1);
}

/// The same bare credit must not block closing, which decodes nothing when the slot
/// carries no data.
#[test]
fn close_clears_a_bare_credit() {
    let ata = Input::named(
        ata_id(),
        false,
        TOKEN_PROGRAM_ID,
        Slot {
            balance: 1,
            data: Data::default(),
        },
    );

    let (_post_states, chained_calls) = crate::close::close_associated_token_account(
        owner_account(),
        ata,
        definition_account(),
        ATA_PROGRAM_ID,
        TOKEN_PROGRAM_ID,
    );

    assert_eq!(chained_calls.len(), 1);
}
