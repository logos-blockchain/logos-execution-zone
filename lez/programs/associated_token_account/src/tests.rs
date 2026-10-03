#![cfg(test)]

use associated_token_account_core::{
    Message, ata_of, compute_ata_seed, get_associated_token_account_id,
};
use lee_core::{
    account::{AccountId, Actor, ActorState},
    program::{Call, PdaSeed, ReceiveInput, SendMode, Transition},
};
use token_core::{TokenDescriptor, TokenKind};

const ATA_PROGRAM_ID: AccountId = AccountId::new([1u8; 32]);
const TOKEN_PROGRAM_ID: AccountId = AccountId::new([2u8; 32]);
const STRANGER_PROGRAM_ID: AccountId = AccountId::new([0xEEu8; 32]);
const RECIPIENT_ID: AccountId = AccountId::new([0x77u8; 32]);
const TRANSFER_AMOUNT: u128 = 5_000;
const BURN_AMOUNT: u128 = 500;

fn owner_id() -> AccountId {
    AccountId::new([0x01u8; 32])
}

fn definition_id() -> AccountId {
    AccountId::new([0x02u8; 32])
}

fn descriptor() -> TokenDescriptor {
    TokenDescriptor {
        definition_id: definition_id(),
        kind: TokenKind::Fungible,
    }
}

// The owner's ATA under `token_program_id`, as a send target, with the seed that grants it.
fn holding(token_program_id: AccountId) -> (Actor, Vec<PdaSeed>) {
    let (ata, seed) = ata_of(
        ATA_PROGRAM_ID,
        owner_id(),
        definition_id(),
        token_program_id,
    );
    (Actor::new(ata, token_program_id), vec![seed])
}

// Drives the real entrypoint as a root delivery to the owner's actor under the ATA program.
fn owner_transition(is_authorized: bool, message: Message) -> Transition {
    let input = ReceiveInput {
        receiver: Actor::new(owner_id(), ATA_PROGRAM_ID),
        origin: None,
        is_authorized,
        pre_state: ActorState::empty(),
        message: borsh::to_vec(&message).expect("the message serializes"),
    };
    crate::receive(&input, message).into_transition(input)
}

fn create(token_program_id: AccountId) -> Message {
    Message::Create {
        token_program_id,
        definition_id: definition_id(),
        kind: TokenKind::Fungible,
    }
}

fn transfer(token_program_id: AccountId) -> Message {
    Message::Transfer {
        token_program_id,
        to: RECIPIENT_ID,
        descriptor: descriptor(),
        amount: TRANSFER_AMOUNT,
    }
}

fn burn(token_program_id: AccountId) -> Message {
    Message::Burn {
        token_program_id,
        descriptor: descriptor(),
        amount: BURN_AMOUNT,
    }
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
    assert_ne!(
        get_associated_token_account_id(
            &ATA_PROGRAM_ID,
            &compute_ata_seed(owner_id(), definition_id(), TOKEN_PROGRAM_ID),
        ),
        get_associated_token_account_id(
            &ATA_PROGRAM_ID,
            &compute_ata_seed(owner_id(), definition_id(), STRANGER_PROGRAM_ID),
        ),
        "each token program must get its own ATA family"
    );
}

#[test]
fn create_grants_the_ata_seed_only_when_the_owner_signed() {
    let (ata, seeds) = holding(TOKEN_PROGRAM_ID);
    let assert_kind = Call::new(
        Actor::new(definition_id(), TOKEN_PROGRAM_ID),
        &token_core::Message::AssertKind {
            kind: TokenKind::Fungible,
        },
    );
    let ensure = Call::new(
        ata,
        &token_core::Message::EnsureHolding {
            descriptor: descriptor(),
        },
    );

    let unsigned = owner_transition(false, create(TOKEN_PROGRAM_ID));
    assert_eq!(unsigned.response.post_state, None);
    assert_eq!(
        (unsigned.response.calls, unsigned.response.casts),
        (vec![assert_kind.clone(), ensure.clone()], Vec::new())
    );
    let signed = owner_transition(true, create(TOKEN_PROGRAM_ID));
    assert_eq!(
        (signed.response.calls, signed.response.casts),
        (vec![assert_kind, ensure.with_pda_seeds(seeds)], Vec::new())
    );
}

#[test]
fn create_naming_a_stranger_program_cannot_reach_the_real_ata() {
    let (real_ata, _) = holding(TOKEN_PROGRAM_ID);
    let (stranger_ata, _) = holding(STRANGER_PROGRAM_ID);

    for message in [
        create(STRANGER_PROGRAM_ID),
        transfer(STRANGER_PROGRAM_ID),
        burn(STRANGER_PROGRAM_ID),
    ] {
        let mut response = owner_transition(true, message).response;
        assert!(response.casts.is_empty(), "every message sends to the ATA");
        let Some(Call { to: target, .. }) = response.calls.pop() else {
            panic!("every message sends to the ATA");
        };
        assert_eq!(target, stranger_ata);
        assert_ne!(target, real_ata);
    }
}

#[test]
fn transfer_delegates_the_proposed_descriptor_under_the_ata_seed() {
    let (ata, seeds) = holding(TOKEN_PROGRAM_ID);

    let transition = owner_transition(true, transfer(TOKEN_PROGRAM_ID));
    assert_eq!(
        (transition.response.calls, transition.response.casts),
        (
            vec![
                Call::new(
                    ata,
                    &token_core::Message::Transfer {
                        to: RECIPIENT_ID,
                        descriptor: descriptor(),
                        amount: TRANSFER_AMOUNT,
                        notify: None,
                        mode: SendMode::Call,
                    },
                )
                .with_pda_seeds(seeds)
            ],
            Vec::new()
        )
    );
}

#[test]
#[should_panic(expected = "Owner authorization is missing")]
fn transfer_rejects_an_unauthorized_owner() {
    let _transition = owner_transition(false, transfer(TOKEN_PROGRAM_ID));
}

#[test]
fn burn_delegates_the_named_definition_under_the_ata_seed() {
    let (ata, seeds) = holding(TOKEN_PROGRAM_ID);

    let transition = owner_transition(true, burn(TOKEN_PROGRAM_ID));
    assert_eq!(
        (transition.response.calls, transition.response.casts),
        (
            vec![
                Call::new(
                    ata,
                    &token_core::Message::Burn {
                        descriptor: descriptor(),
                        amount: BURN_AMOUNT,
                        definition: definition_id(),
                    },
                )
                .with_pda_seeds(seeds)
            ],
            Vec::new()
        )
    );
}

#[test]
#[should_panic(expected = "Owner authorization is missing")]
fn burn_rejects_an_unauthorized_owner() {
    let _transition = owner_transition(false, burn(TOKEN_PROGRAM_ID));
}
