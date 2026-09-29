#![cfg(test)]

use std::collections::{HashMap, VecDeque};

use lee_core::{
    account::{AccountId, Actor, ShardData},
    program::{Origin, ReceiveInput, Transition},
};
use token_core::{
    Message, MetadataStandard, NewTokenDefinition, NewTokenMetadata, TokenDefinition,
    TokenDescriptor, TokenHolding, TokenKind, TokenMetadata,
};

const TOKEN_PROGRAM_ID: AccountId = AccountId::new([5; 32]);
const DEFINITION_ID: AccountId = AccountId::new([15; 32]);
const OTHER_DEFINITION_ID: AccountId = AccountId::new([16; 32]);
const HOLDING_ID: AccountId = AccountId::new([17; 32]);
const HOLDING_ID_2: AccountId = AccountId::new([42; 32]);
const METADATA_ID: AccountId = AccountId::new([43; 32]);
const TOKEN_ORIGIN: Origin = Origin::Program(TOKEN_PROGRAM_ID);

const INIT_SUPPLY: u128 = 100_000;
const HOLDING_BALANCE: u128 = 1_000;
const INIT_SUPPLY_BURNED: u128 = 99_500;
const HOLDING_BALANCE_BURNED: u128 = 500;
const BURN_SUCCESS: u128 = 500;
const BURN_INSUFFICIENT: u128 = 1_500;
const MINT_SUCCESS: u128 = 50_000;
const HOLDING_BALANCE_MINT: u128 = 51_000;
const MINT_OVERFLOW: u128 = u128::MAX - 40_000;
const INIT_SUPPLY_MINT: u128 = 150_000;
const SENDER_POST_TRANSFER: u128 = 95_000;
const RECIPIENT_POST_TRANSFER: u128 = 105_000;
const TRANSFER_AMOUNT: u128 = 5_000;
const PRINTABLE_COPIES: u128 = 10;
const PRINTABLE_COPIES_AFTER_PRINT: u128 = 9;

const FUNGIBLE: TokenDescriptor = TokenDescriptor {
    definition_id: DEFINITION_ID,
    kind: TokenKind::Fungible,
};
const MASTER: TokenDescriptor = TokenDescriptor {
    definition_id: DEFINITION_ID,
    kind: TokenKind::NftMaster,
};
const PRINTED: TokenDescriptor = TokenDescriptor {
    definition_id: DEFINITION_ID,
    kind: TokenKind::NftPrintedCopy,
};

const fn fungible(balance: u128) -> TokenHolding {
    TokenHolding::Fungible {
        definition_id: DEFINITION_ID,
        balance,
    }
}

const fn master(print_balance: u128) -> TokenHolding {
    TokenHolding::NftMaster {
        definition_id: DEFINITION_ID,
        print_balance,
    }
}

const fn printed(owned: bool) -> TokenHolding {
    TokenHolding::NftPrintedCopy {
        definition_id: DEFINITION_ID,
        owned,
    }
}

fn fungible_definition(total_supply: u128) -> TokenDefinition {
    TokenDefinition::Fungible {
        name: String::from("test"),
        total_supply,
        metadata_id: None,
    }
}

fn non_fungible_definition(printable_supply: u128) -> TokenDefinition {
    TokenDefinition::NonFungible {
        name: String::from("test"),
        printable_supply,
        metadata_id: METADATA_ID,
    }
}

fn new_metadata() -> NewTokenMetadata {
    NewTokenMetadata {
        standard: MetadataStandard::Simple,
        uri: String::from("test_uri"),
        creators: String::from("test_creators"),
    }
}

fn metadata() -> TokenMetadata {
    TokenMetadata {
        definition_id: DEFINITION_ID,
        standard: MetadataStandard::Simple,
        uri: String::from("test_uri"),
        creators: String::from("test_creators"),
        primary_sale_date: 0_u64,
    }
}

const fn token_actor(account: AccountId) -> Actor {
    Actor::new(account, TOKEN_PROGRAM_ID)
}

fn transfer(descriptor: TokenDescriptor, amount: u128) -> Message {
    Message::Transfer {
        to: HOLDING_ID_2,
        descriptor,
        amount,
        notify: None,
    }
}

const fn credit(descriptor: TokenDescriptor, amount: u128) -> Message {
    Message::Credit {
        descriptor,
        amount,
        notify: None,
    }
}

fn turn(
    account: AccountId,
    is_authorized: bool,
    origin: Origin,
    pre_data: &ShardData,
    message: &Message,
) -> Transition {
    let input = ReceiveInput {
        receiver: token_actor(account),
        origin,
        is_authorized,
        pre_data: pre_data.clone(),
        message: borsh::to_vec(message).expect("the message serializes"),
    };
    crate::receive(&input, message.clone()).into_transition(input)
}

// Every permission is granted, so only the shard contents can refuse the message.
fn written(message: &Message, pre_data: &ShardData) -> Option<ShardData> {
    // A supply burn runs at the definition it names.
    let receiver = if let Message::BurnSupply { definition_id, .. } = message {
        *definition_id
    } else {
        HOLDING_ID
    };
    turn(receiver, true, TOKEN_ORIGIN, pre_data, message).post_data
}

fn rejection(message: &Message, pre_data: &ShardData) -> String {
    let payload = std::panic::catch_unwind(|| written(message, pre_data))
        .expect_err("the message was accepted");
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            payload
                .downcast_ref::<&str>()
                .map(|text| (*text).to_owned())
        })
        .expect("a panic carries its message")
}

fn holding_at(message: &Message, pre_data: &ShardData) -> TokenHolding {
    TokenHolding::try_from(&written(message, pre_data).expect("the message writes its shard"))
        .expect("the turn wrote a holding")
}

fn definition_at(message: &Message, pre_data: &ShardData) -> TokenDefinition {
    TokenDefinition::try_from(&written(message, pre_data).expect("the message writes its shard"))
        .expect("the turn wrote a definition")
}

fn settle(
    root_account: AccountId,
    root_message: &Message,
    authorized: &[AccountId],
    initial: &[(AccountId, ShardData)],
) -> HashMap<AccountId, ShardData> {
    let mut state: HashMap<AccountId, ShardData> = initial.iter().cloned().collect();
    let mut pending = VecDeque::from([(root_account, Origin::Root, root_message.clone())]);

    while let Some((account, origin, message)) = pending.pop_front() {
        let pre_data = state.get(&account).cloned().unwrap_or_default();
        let transition = turn(
            account,
            authorized.contains(&account),
            origin,
            &pre_data,
            &message,
        );
        if let Some(post_data) = transition.post_data {
            state.insert(account, post_data);
        }
        let sender = Origin::Program(token_actor(account).program_account_id);
        for envelope in transition.sends.into_iter().rev() {
            let sent =
                borsh::from_slice(&envelope.message).expect("a token send carries a message");
            pending.push_front((envelope.to.account_id, sender, sent));
        }
    }

    state
}

fn settled_holding(state: &HashMap<AccountId, ShardData>, account_id: AccountId) -> TokenHolding {
    TokenHolding::try_from(state.get(&account_id).expect("the account was settled"))
        .expect("the turn wrote a holding")
}

fn settled_definition(
    state: &HashMap<AccountId, ShardData>,
    account_id: AccountId,
) -> TokenDefinition {
    TokenDefinition::try_from(state.get(&account_id).expect("the account was settled"))
        .expect("the turn wrote a definition")
}

// --- new definitions -------------------------------------------------------------------------

#[test]
fn new_definition_with_valid_inputs_succeeds() {
    let state = settle(
        DEFINITION_ID,
        &Message::NewDefinition {
            definition: NewTokenDefinition::Fungible {
                name: String::from("test"),
                total_supply: INIT_SUPPLY,
            },
            holding: HOLDING_ID,
            metadata: None,
        },
        &[],
        &[],
    );

    let definition = settled_definition(&state, DEFINITION_ID);
    let holding = settled_holding(&state, HOLDING_ID);
    assert_eq!(definition, fungible_definition(INIT_SUPPLY));
    assert_eq!(holding, fungible(INIT_SUPPLY));
}

#[test]
fn new_definition_with_metadata_creates_a_master_copy_for_a_non_fungible() {
    let state = settle(
        DEFINITION_ID,
        &Message::NewDefinition {
            definition: NewTokenDefinition::NonFungible {
                name: String::from("test"),
                printable_supply: PRINTABLE_COPIES,
            },
            holding: HOLDING_ID,
            metadata: Some((METADATA_ID, new_metadata())),
        },
        &[],
        &[],
    );

    let definition = settled_definition(&state, DEFINITION_ID);
    let holding = settled_holding(&state, HOLDING_ID);
    assert_eq!(definition, non_fungible_definition(PRINTABLE_COPIES));
    assert_eq!(holding, master(PRINTABLE_COPIES));
    assert_eq!(state.get(&METADATA_ID), Some(&ShardData::from(&metadata())));
}

// --- transfer --------------------------------------------------------------------------------

#[should_panic(expected = "Sender authorization is missing")]
#[test]
fn transfer_without_sender_authorization_should_fail() {
    let _transition = turn(
        HOLDING_ID,
        false,
        Origin::Root,
        &ShardData::from(&fungible(INIT_SUPPLY)),
        &transfer(FUNGIBLE, TRANSFER_AMOUNT),
    );
}

#[should_panic(expected = "Mismatch Token Definition and Token Holding")]
#[test]
fn transfer_with_different_definition_ids_should_fail() {
    let recipient = TokenHolding::Fungible {
        definition_id: OTHER_DEFINITION_ID,
        balance: HOLDING_BALANCE,
    };
    let _written = written(
        &credit(FUNGIBLE, TRANSFER_AMOUNT),
        &ShardData::from(&recipient),
    );
}

#[should_panic(expected = "Mismatched Token Definition and Token Holding types")]
#[test]
fn transfer_with_mismatched_holding_kinds_should_fail() {
    let _written = written(
        &transfer(FUNGIBLE, PRINTABLE_COPIES),
        &ShardData::from(&master(PRINTABLE_COPIES)),
    );
}

#[should_panic(expected = "Insufficient balance")]
#[test]
fn transfer_with_insufficient_balance_should_fail() {
    let _written = written(
        &transfer(FUNGIBLE, BURN_INSUFFICIENT),
        &ShardData::from(&fungible(HOLDING_BALANCE)),
    );
}

#[test]
fn transfer_with_valid_inputs_succeeds() {
    let state = settle(
        HOLDING_ID,
        &transfer(FUNGIBLE, TRANSFER_AMOUNT),
        &[HOLDING_ID],
        &[
            (HOLDING_ID, ShardData::from(&fungible(INIT_SUPPLY))),
            (HOLDING_ID_2, ShardData::from(&fungible(INIT_SUPPLY))),
        ],
    );

    let sender = settled_holding(&state, HOLDING_ID);
    let recipient = settled_holding(&state, HOLDING_ID_2);
    assert_eq!(sender, fungible(SENDER_POST_TRANSFER));
    assert_eq!(recipient, fungible(RECIPIENT_POST_TRANSFER));
}

#[test]
fn transfer_into_an_empty_recipient_uses_the_bound_descriptor() {
    assert_eq!(
        holding_at(&credit(FUNGIBLE, TRANSFER_AMOUNT), &ShardData::empty()),
        fungible(TRANSFER_AMOUNT)
    );
}

#[test]
fn transfer_with_master_nft_invalid_balance() {
    // The whole print balance must move, and the message only *claims* how much that is.
    // Every claim other than the master's real print balance is refused by the sender's own
    // turn, so a forged claim cannot mint print capacity into the recipient.
    for claimed in [
        0,
        1,
        PRINTABLE_COPIES_AFTER_PRINT,
        TRANSFER_AMOUNT,
        u128::MAX,
    ] {
        assert!(
            rejection(
                &transfer(MASTER, claimed),
                &ShardData::from(&master(PRINTABLE_COPIES)),
            )
            .contains("Invalid balance for NFT Master transfer"),
            "Transfer accepted a claimed print balance of {claimed}"
        );
    }
}

#[should_panic(expected = "Invalid balance in recipient account for NFT transfer")]
#[test]
fn transfer_with_master_nft_invalid_recipient_balance() {
    let _written = written(
        &credit(MASTER, PRINTABLE_COPIES),
        &ShardData::from(&master(PRINTABLE_COPIES)),
    );
}

#[test]
fn transfer_with_master_nft_success() {
    assert_eq!(
        holding_at(
            &transfer(MASTER, PRINTABLE_COPIES),
            &ShardData::from(&master(PRINTABLE_COPIES)),
        ),
        master(0)
    );
    assert_eq!(
        holding_at(&credit(MASTER, PRINTABLE_COPIES), &ShardData::empty()),
        master(PRINTABLE_COPIES)
    );
}

#[test]
fn transfer_of_a_printed_copy_moves_ownership() {
    assert_eq!(
        holding_at(&transfer(PRINTED, 1), &ShardData::from(&printed(true))),
        printed(false)
    );
    assert_eq!(
        holding_at(&credit(PRINTED, 1), &ShardData::from(&printed(false))),
        printed(true)
    );
}

#[should_panic(expected = "Sender does not own the NFT Printed Copy")]
#[test]
fn transfer_of_an_unowned_printed_copy_should_fail() {
    let _written = written(&transfer(PRINTED, 1), &ShardData::from(&printed(false)));
}

// --- ensure holding and kind -----------------------------------------------------------------

// --- mint ------------------------------------------------------------------------------------

#[should_panic(expected = "Definition authorization is missing")]
#[test]
fn mint_missing_authorization() {
    let _transition = turn(
        DEFINITION_ID,
        false,
        Origin::Root,
        &ShardData::from(&fungible_definition(INIT_SUPPLY)),
        &Message::Mint {
            to: HOLDING_ID,
            amount: MINT_SUCCESS,
        },
    );
}

#[should_panic(expected = "Invalid recipient data")]
#[test]
fn mint_not_valid_holding_account() {
    let _written = written(
        &credit(FUNGIBLE, MINT_SUCCESS),
        &ShardData::from(&fungible_definition(INIT_SUPPLY)),
    );
}

#[should_panic(expected = "Definition account must be valid")]
#[test]
fn mint_not_valid_definition_account() {
    let _written = written(
        &Message::Mint {
            to: HOLDING_ID,
            amount: MINT_SUCCESS,
        },
        &ShardData::from(&fungible(HOLDING_BALANCE)),
    );
}

#[test]
fn mint_success() {
    let state = settle(
        DEFINITION_ID,
        &Message::Mint {
            to: HOLDING_ID,
            amount: MINT_SUCCESS,
        },
        &[DEFINITION_ID],
        &[
            (
                DEFINITION_ID,
                ShardData::from(&fungible_definition(INIT_SUPPLY)),
            ),
            (HOLDING_ID, ShardData::from(&fungible(HOLDING_BALANCE))),
        ],
    );

    let definition = settled_definition(&state, DEFINITION_ID);
    let holding = settled_holding(&state, HOLDING_ID);
    assert_eq!(definition, fungible_definition(INIT_SUPPLY_MINT));
    assert_eq!(holding, fungible(HOLDING_BALANCE_MINT));
}

#[test]
fn mint_uninit_holding_success() {
    let state = settle(
        DEFINITION_ID,
        &Message::Mint {
            to: HOLDING_ID,
            amount: MINT_SUCCESS,
        },
        &[DEFINITION_ID],
        &[(
            DEFINITION_ID,
            ShardData::from(&fungible_definition(INIT_SUPPLY)),
        )],
    );

    assert_eq!(settled_holding(&state, HOLDING_ID), fungible(MINT_SUCCESS));
    assert_eq!(
        settled_definition(&state, DEFINITION_ID),
        fungible_definition(INIT_SUPPLY_MINT)
    );
}

#[should_panic(expected = "Total supply overflow")]
#[test]
fn mint_total_supply_overflow() {
    let _written = written(
        &Message::Mint {
            to: HOLDING_ID,
            amount: MINT_OVERFLOW,
        },
        &ShardData::from(&fungible_definition(INIT_SUPPLY)),
    );
}

#[should_panic(expected = "Recipient balance overflow")]
#[test]
fn mint_holding_account_overflow() {
    let _written = written(
        &credit(FUNGIBLE, MINT_OVERFLOW),
        &ShardData::from(&fungible(INIT_SUPPLY)),
    );
}

#[should_panic(expected = "Cannot mint additional supply for Non-Fungible Tokens")]
#[test]
fn mint_cannot_mint_unmintable_tokens() {
    let _written = written(
        &Message::Mint {
            to: HOLDING_ID,
            amount: MINT_SUCCESS,
        },
        &ShardData::from(&non_fungible_definition(PRINTABLE_COPIES)),
    );
}

#[should_panic(expected = "Mismatched Token Definition and Token Holding types")]
#[test]
fn mint_into_a_non_fungible_holding_is_rejected() {
    let _written = written(
        &credit(FUNGIBLE, MINT_SUCCESS),
        &ShardData::from(&master(PRINTABLE_COPIES)),
    );
}

// --- burn ------------------------------------------------------------------------------------

#[should_panic(expected = "Authorization is missing")]
#[test]
fn burn_missing_authorization() {
    let _transition = turn(
        HOLDING_ID,
        false,
        Origin::Root,
        &ShardData::from(&fungible(HOLDING_BALANCE)),
        &Message::Burn {
            descriptor: FUNGIBLE,
            amount: BURN_SUCCESS,
            definition: DEFINITION_ID,
        },
    );
}

#[should_panic(expected = "Mismatch Token Definition and Token Holding")]
#[test]
fn burn_mismatch_def() {
    let other_definition = TokenHolding::Fungible {
        definition_id: OTHER_DEFINITION_ID,
        balance: HOLDING_BALANCE,
    };
    let _written = written(
        &Message::Burn {
            descriptor: FUNGIBLE,
            amount: BURN_SUCCESS,
            definition: DEFINITION_ID,
        },
        &ShardData::from(&other_definition),
    );
}

#[should_panic(expected = "Insufficient balance to burn")]
#[test]
fn burn_insufficient_balance() {
    let _written = written(
        &Message::Burn {
            descriptor: FUNGIBLE,
            amount: BURN_INSUFFICIENT,
            definition: DEFINITION_ID,
        },
        &ShardData::from(&fungible(HOLDING_BALANCE)),
    );
}

#[should_panic(expected = "Total supply underflow")]
#[test]
fn burn_total_supply_underflow() {
    let _written = written(
        &Message::BurnSupply {
            definition_id: DEFINITION_ID,
            kind: TokenKind::Fungible,
            amount: MINT_OVERFLOW,
        },
        &ShardData::from(&fungible_definition(INIT_SUPPLY)),
    );
}

#[test]
fn burn_success() {
    let state = settle(
        HOLDING_ID,
        &Message::Burn {
            descriptor: FUNGIBLE,
            amount: BURN_SUCCESS,
            definition: DEFINITION_ID,
        },
        &[HOLDING_ID],
        &[
            (
                DEFINITION_ID,
                ShardData::from(&fungible_definition(INIT_SUPPLY)),
            ),
            (HOLDING_ID, ShardData::from(&fungible(HOLDING_BALANCE))),
        ],
    );

    let definition = settled_definition(&state, DEFINITION_ID);
    let holding = settled_holding(&state, HOLDING_ID);
    assert_eq!(definition, fungible_definition(INIT_SUPPLY_BURNED));
    assert_eq!(holding, fungible(HOLDING_BALANCE_BURNED));
}

#[test]
fn burn_of_an_nft_master_drops_both_supplies() {
    assert_eq!(
        definition_at(
            &Message::BurnSupply {
                definition_id: DEFINITION_ID,
                kind: TokenKind::NftMaster,
                amount: 1,
            },
            &ShardData::from(&non_fungible_definition(PRINTABLE_COPIES)),
        ),
        non_fungible_definition(PRINTABLE_COPIES_AFTER_PRINT)
    );
    assert_eq!(
        holding_at(
            &Message::Burn {
                descriptor: MASTER,
                amount: 1,
                definition: DEFINITION_ID,
            },
            &ShardData::from(&master(PRINTABLE_COPIES)),
        ),
        master(PRINTABLE_COPIES_AFTER_PRINT)
    );
}

#[test]
fn burn_of_a_printed_copy_drops_ownership() {
    assert_eq!(
        definition_at(
            &Message::BurnSupply {
                definition_id: DEFINITION_ID,
                kind: TokenKind::NftPrintedCopy,
                amount: 1,
            },
            &ShardData::from(&non_fungible_definition(PRINTABLE_COPIES)),
        ),
        non_fungible_definition(PRINTABLE_COPIES_AFTER_PRINT)
    );
    assert_eq!(
        holding_at(
            &Message::Burn {
                descriptor: PRINTED,
                amount: 1,
                definition: DEFINITION_ID,
            },
            &ShardData::from(&printed(true)),
        ),
        printed(false)
    );
}

#[should_panic(expected = "Cannot burn unowned NFT Printed Copy")]
#[test]
fn burn_of_an_unowned_printed_copy_is_rejected() {
    let _written = written(
        &Message::Burn {
            descriptor: PRINTED,
            amount: 1,
            definition: DEFINITION_ID,
        },
        &ShardData::from(&printed(false)),
    );
}

#[test]
fn burn_rejects_a_forged_holding_kind() {
    // The claimed kind picks which of the definition's two supplies is decremented, and the
    // definition's turn never sees the holding. Both turns check the same claim against
    // their own contents.
    let definitions = [
        (
            ShardData::from(&fungible_definition(INIT_SUPPLY)),
            TokenKind::NftMaster,
        ),
        (
            ShardData::from(&fungible_definition(INIT_SUPPLY)),
            TokenKind::NftPrintedCopy,
        ),
        (
            ShardData::from(&non_fungible_definition(PRINTABLE_COPIES)),
            TokenKind::Fungible,
        ),
    ];
    for (definition, claimed) in definitions {
        assert!(
            rejection(
                &Message::BurnSupply {
                    definition_id: DEFINITION_ID,
                    kind: claimed,
                    amount: 1,
                },
                &definition,
            )
            .contains("Mismatched Token Definition and Token Holding types"),
            "BurnSupply accepted a claimed kind of {claimed:?}"
        );
    }

    let holdings = [
        (ShardData::from(&fungible(HOLDING_BALANCE)), MASTER),
        (ShardData::from(&master(PRINTABLE_COPIES)), FUNGIBLE),
        (ShardData::from(&printed(true)), MASTER),
    ];
    for (holding, claimed) in holdings {
        assert!(
            rejection(
                &Message::Burn {
                    descriptor: claimed,
                    amount: 1,
                    definition: DEFINITION_ID,
                },
                &holding,
            )
            .contains("Mismatched Token Definition and Token Holding types"),
            "Burn accepted a claimed kind of {:?}",
            claimed.kind
        );
    }
}

// --- print nft -------------------------------------------------------------------------------

fn print_nft(definition_id: AccountId) -> Message {
    Message::PrintNft {
        printed: HOLDING_ID_2,
        definition_id,
    }
}

#[should_panic(expected = "Master NFT Account must be authorized")]
#[test]
fn print_nft_master_account_must_be_authorized() {
    let _transition = turn(
        HOLDING_ID,
        false,
        Origin::Root,
        &ShardData::from(&master(PRINTABLE_COPIES)),
        &print_nft(DEFINITION_ID),
    );
}

#[should_panic(expected = "Invalid Token Holding data")]
#[test]
fn print_nft_master_nft_invalid_token_holding() {
    let _written = written(
        &print_nft(DEFINITION_ID),
        &ShardData::from(&fungible_definition(INIT_SUPPLY)),
    );
}

#[should_panic(expected = "Invalid Token Holding provided as NFT Master Account")]
#[test]
fn print_nft_master_nft_not_nft_master_account() {
    let _written = written(
        &print_nft(DEFINITION_ID),
        &ShardData::from(&fungible(INIT_SUPPLY)),
    );
}

#[should_panic(expected = "Insufficient balance to print another NFT copy")]
#[test]
fn print_nft_master_nft_insufficient_balance() {
    let _written = written(&print_nft(DEFINITION_ID), &ShardData::from(&master(1)));
}

#[should_panic(expected = "Printed copy does not belong to the master's Token Definition")]
#[test]
fn print_nft_rejects_a_forged_definition_id() {
    // The collection the new copy claims is message data, and the printed account's turn
    // never sees the master. Without this check a master of any collection could print a copy
    // of a more valuable one.
    let _written = written(
        &print_nft(OTHER_DEFINITION_ID),
        &ShardData::from(&master(PRINTABLE_COPIES)),
    );
}

#[test]
fn print_nft_success() {
    let state = settle(
        HOLDING_ID,
        &print_nft(DEFINITION_ID),
        &[HOLDING_ID],
        &[(HOLDING_ID, ShardData::from(&master(PRINTABLE_COPIES)))],
    );

    let master_holding = settled_holding(&state, HOLDING_ID);
    let copy = settled_holding(&state, HOLDING_ID_2);
    assert_eq!(master_holding, master(PRINTABLE_COPIES_AFTER_PRINT));
    assert_eq!(copy, printed(true));
    assert_eq!(
        master_holding.definition_id(),
        copy.definition_id(),
        "the turn printed a copy of a collection the master does not hold"
    );
}
