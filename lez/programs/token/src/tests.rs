#![cfg(test)]

use std::collections::{HashMap, VecDeque};

use lee_core::{
    account::{AccountId, Actor, ActorState},
    program::{Call, Cast, ReceiveInput, SendMode, Transition},
};
use token_core::{
    Message, MetadataStandard, NewTokenDefinition, NewTokenMetadata, Notification, Notify,
    TokenDefinition, TokenDescriptor, TokenHolding, TokenKind, TokenMetadata, expected_sends,
};

const TOKEN_PROGRAM_ID: AccountId = AccountId::new([5; 32]);
const DEFINITION_ID: AccountId = AccountId::new([15; 32]);
const OTHER_DEFINITION_ID: AccountId = AccountId::new([16; 32]);
const HOLDING_ID: AccountId = AccountId::new([17; 32]);
const HOLDING_ID_2: AccountId = AccountId::new([42; 32]);
const METADATA_ID: AccountId = AccountId::new([43; 32]);
const TOKEN_ORIGIN: Option<AccountId> = Some(TOKEN_PROGRAM_ID);

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
        mode: SendMode::Call,
    }
}

fn cast_transfer(descriptor: TokenDescriptor, amount: u128) -> Message {
    Message::Transfer {
        to: HOLDING_ID_2,
        descriptor,
        amount,
        notify: None,
        mode: SendMode::Cast,
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
    origin: Option<AccountId>,
    pre_state: &ActorState,
    message: &Message,
) -> Transition {
    let input = ReceiveInput {
        receiver: token_actor(account),
        origin,
        is_authorized,
        pre_state: pre_state.clone(),
        message: borsh::to_vec(message).expect("the message serializes"),
    };
    crate::receive(&input, message.clone()).into_transition(input)
}

// Every permission is granted, so only the shard contents can refuse the message.
fn written(message: &Message, pre_state: &ActorState) -> Option<ActorState> {
    // A supply burn runs at the definition it names.
    let receiver = if let Message::BurnSupply { definition_id, .. } = message {
        *definition_id
    } else {
        HOLDING_ID
    };
    turn(receiver, true, TOKEN_ORIGIN, pre_state, message)
        .response
        .post_state
}

fn rejection(message: &Message, pre_state: &ActorState) -> String {
    let payload = std::panic::catch_unwind(|| written(message, pre_state))
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

fn holding_at(message: &Message, pre_state: &ActorState) -> TokenHolding {
    TokenHolding::try_from(&written(message, pre_state).expect("the message writes its shard"))
        .expect("the turn wrote a holding")
}

fn definition_at(message: &Message, pre_state: &ActorState) -> TokenDefinition {
    TokenDefinition::try_from(&written(message, pre_state).expect("the message writes its shard"))
        .expect("the turn wrote a definition")
}

fn settle(
    root_account: AccountId,
    root_message: &Message,
    authorized: &[AccountId],
    initial: &[(AccountId, ActorState)],
) -> HashMap<AccountId, ActorState> {
    let mut state: HashMap<AccountId, ActorState> = initial.iter().cloned().collect();
    let mut pending = VecDeque::from([(root_account, None, root_message.clone())]);

    while let Some((account, origin, message)) = pending.pop_front() {
        let pre_state = state.get(&account).cloned().unwrap_or_default();
        let transition = turn(
            account,
            authorized.contains(&account),
            origin,
            &pre_state,
            &message,
        );
        if let Some(post_state) = transition.response.post_state {
            state.insert(account, post_state);
        }
        let sender = Some(token_actor(account).program_account_id);
        assert!(
            transition.response.casts.is_empty(),
            "a token send is an inline call"
        );
        for Call {
            to, message: data, ..
        } in transition.response.calls.into_iter().rev()
        {
            let sent = borsh::from_slice(&data).expect("a token send carries a message");
            pending.push_front((to.account_id, sender, sent));
        }
    }

    state
}

fn settled_holding(state: &HashMap<AccountId, ActorState>, account_id: AccountId) -> TokenHolding {
    TokenHolding::try_from(state.get(&account_id).expect("the account was settled"))
        .expect("the turn wrote a holding")
}

fn settled_definition(
    state: &HashMap<AccountId, ActorState>,
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
    assert_eq!(
        state.get(&METADATA_ID),
        Some(&ActorState::from(&metadata()))
    );
}

#[test]
fn every_sent_creation_writes_only_into_an_empty_target() {
    let new_definition = |definition, metadata| Message::NewDefinition {
        definition,
        holding: HOLDING_ID,
        metadata,
    };
    let fungible_definition_message = || NewTokenDefinition::Fungible {
        name: String::from("test"),
        total_supply: INIT_SUPPLY,
    };
    let cases = [
        (
            "NewDefinition (fungible)",
            DEFINITION_ID,
            new_definition(fungible_definition_message(), None),
            vec![HOLDING_ID],
        ),
        (
            "NewDefinition (fungible, metadata)",
            DEFINITION_ID,
            new_definition(
                fungible_definition_message(),
                Some((METADATA_ID, new_metadata())),
            ),
            vec![HOLDING_ID, METADATA_ID],
        ),
        (
            "NewDefinition (non-fungible)",
            DEFINITION_ID,
            new_definition(
                NewTokenDefinition::NonFungible {
                    name: String::from("test"),
                    printable_supply: PRINTABLE_COPIES,
                },
                Some((METADATA_ID, new_metadata())),
            ),
            vec![HOLDING_ID, METADATA_ID],
        ),
        (
            "PrintNft",
            HOLDING_ID,
            Message::PrintNft {
                printed: HOLDING_ID_2,
                definition_id: DEFINITION_ID,
            },
            vec![HOLDING_ID_2],
        ),
    ];

    for (operation, receiver, message, targets) in cases {
        let (calls, casts) = expected_sends(Actor::new(receiver, TOKEN_PROGRAM_ID), &message);
        assert!(casts.is_empty(), "a token send is an inline call");
        let creations: Vec<(AccountId, Message)> = calls
            .into_iter()
            .filter_map(
                |Call {
                     to, message: data, ..
                 }| {
                    let sent: Message =
                        borsh::from_slice(&data).expect("a token send carries a message");
                    matches!(sent, Message::Create(_)).then_some((to.account_id, sent))
                },
            )
            .collect();
        assert_eq!(
            creations
                .iter()
                .map(|(account_id, _)| *account_id)
                .collect::<Vec<_>>(),
            targets,
            "{operation} creates a different set of accounts"
        );

        for (account_id, create) in creations {
            let Message::Create(data) = &create else {
                unreachable!("only creations were kept");
            };
            assert_eq!(
                written(&create, &ActorState::empty()).as_ref(),
                Some(data),
                "{operation} wrote something other than it sent into {account_id}"
            );
            // Even the very data it would write: a creation never lands twice.
            for occupant in [data.clone(), ActorState::from(&fungible(1))] {
                assert!(
                    rejection(&create, &occupant)
                        .contains("Target account must not already hold data"),
                    "{operation} overwrote the occupied account {account_id}"
                );
            }
        }
    }

    assert!(
        rejection(
            &new_definition(fungible_definition_message(), None),
            &ActorState::from(&fungible_definition(INIT_SUPPLY))
        )
        .contains("Target account must not already hold data"),
        "NewDefinition overwrote an occupied definition"
    );
}

// --- transfer --------------------------------------------------------------------------------

#[should_panic(expected = "Sender authorization is missing")]
#[test]
fn transfer_without_sender_authorization_should_fail() {
    let _transition = turn(
        HOLDING_ID,
        false,
        None,
        &ActorState::from(&fungible(INIT_SUPPLY)),
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
        &ActorState::from(&recipient),
    );
}

#[should_panic(expected = "Mismatched Token Definition and Token Holding types")]
#[test]
fn transfer_with_mismatched_holding_kinds_should_fail() {
    let _written = written(
        &transfer(FUNGIBLE, PRINTABLE_COPIES),
        &ActorState::from(&master(PRINTABLE_COPIES)),
    );
}

#[should_panic(expected = "Insufficient balance")]
#[test]
fn transfer_with_insufficient_balance_should_fail() {
    let _written = written(
        &transfer(FUNGIBLE, BURN_INSUFFICIENT),
        &ActorState::from(&fungible(HOLDING_BALANCE)),
    );
}

#[test]
fn transfer_with_valid_inputs_succeeds() {
    let state = settle(
        HOLDING_ID,
        &transfer(FUNGIBLE, TRANSFER_AMOUNT),
        &[HOLDING_ID],
        &[
            (HOLDING_ID, ActorState::from(&fungible(INIT_SUPPLY))),
            (HOLDING_ID_2, ActorState::from(&fungible(INIT_SUPPLY))),
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
        holding_at(&credit(FUNGIBLE, TRANSFER_AMOUNT), &ActorState::empty()),
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
                &ActorState::from(&master(PRINTABLE_COPIES)),
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
        &ActorState::from(&master(PRINTABLE_COPIES)),
    );
}

#[test]
fn transfer_with_master_nft_success() {
    assert_eq!(
        holding_at(
            &transfer(MASTER, PRINTABLE_COPIES),
            &ActorState::from(&master(PRINTABLE_COPIES)),
        ),
        master(0)
    );
    assert_eq!(
        holding_at(&credit(MASTER, PRINTABLE_COPIES), &ActorState::empty()),
        master(PRINTABLE_COPIES)
    );
}

#[test]
fn transfer_of_a_printed_copy_moves_ownership() {
    assert_eq!(
        holding_at(&transfer(PRINTED, 1), &ActorState::from(&printed(true))),
        printed(false)
    );
    assert_eq!(
        holding_at(&credit(PRINTED, 1), &ActorState::from(&printed(false))),
        printed(true)
    );
}

#[should_panic(expected = "Sender does not own the NFT Printed Copy")]
#[test]
fn transfer_of_an_unowned_printed_copy_should_fail() {
    let _written = written(&transfer(PRINTED, 1), &ActorState::from(&printed(false)));
}

#[test]
fn a_transfer_requested_by_another_actor_needs_only_the_senders_authorization() {
    let requester = Some(OTHER_DEFINITION_ID);
    let sender = ActorState::from(&fungible(INIT_SUPPLY));
    let request = |is_authorized| {
        turn(
            HOLDING_ID,
            is_authorized,
            requester,
            &sender,
            &transfer(FUNGIBLE, TRANSFER_AMOUNT),
        )
    };

    assert_eq!(
        request(true).response.post_state,
        Some(ActorState::from(&fungible(SENDER_POST_TRANSFER)))
    );
    let refusal = std::panic::catch_unwind(|| request(false).response.post_state)
        .expect_err("an unauthorized transfer was accepted");
    assert_eq!(
        refusal.downcast_ref::<&str>(),
        Some(&"Sender authorization is missing")
    );
}

#[should_panic(expected = "A credit must come from the token program")]
#[test]
fn a_credit_from_the_root_is_rejected() {
    let _transition = turn(
        HOLDING_ID,
        true,
        None,
        &ActorState::empty(),
        &credit(FUNGIBLE, TRANSFER_AMOUNT),
    );
}

#[should_panic(expected = "A creation must come from the token program")]
#[test]
fn a_creation_from_another_program_is_rejected() {
    let _transition = turn(
        HOLDING_ID,
        true,
        Some(OTHER_DEFINITION_ID),
        &ActorState::empty(),
        &Message::Create(ActorState::from(&fungible(INIT_SUPPLY))),
    );
}

#[test]
fn a_credit_with_notify_sends_one_notification() {
    let listener = Actor::new(HOLDING_ID_2, OTHER_DEFINITION_ID);
    let transition = turn(
        HOLDING_ID,
        false,
        TOKEN_ORIGIN,
        &ActorState::empty(),
        &Message::Credit {
            descriptor: FUNGIBLE,
            amount: TRANSFER_AMOUNT,
            notify: Some(Notify {
                to: listener,
                payload: b"swap".to_vec(),
            }),
        },
    );

    assert_eq!(
        (transition.response.calls, transition.response.casts),
        (
            vec![Call::new(
                listener,
                &Message::Notification(Notification {
                    credited_account: HOLDING_ID,
                    descriptor: FUNGIBLE,
                    amount: TRANSFER_AMOUNT,
                    payload: b"swap".to_vec(),
                })
            )],
            Vec::new()
        )
    );
}

#[should_panic(expected = "A token actor does not accept notifications")]
#[test]
fn a_notification_from_a_token_origin_is_refused() {
    let _transition = turn(
        HOLDING_ID,
        true,
        TOKEN_ORIGIN,
        &ActorState::empty(),
        &Message::Notification(Notification {
            credited_account: HOLDING_ID,
            descriptor: FUNGIBLE,
            amount: TRANSFER_AMOUNT,
            payload: vec![0],
        }),
    );
}

#[test]
fn expected_sends_for_a_transfer_is_one_credit_to_the_recipient() {
    assert_eq!(
        expected_sends(
            Actor::new(HOLDING_ID, TOKEN_PROGRAM_ID),
            &transfer(FUNGIBLE, TRANSFER_AMOUNT)
        ),
        (
            vec![Call::new(
                token_actor(HOLDING_ID_2),
                &credit(FUNGIBLE, TRANSFER_AMOUNT)
            )],
            Vec::new()
        )
    );
}

#[test]
fn a_cast_transfer_writes_the_sender_like_a_call_and_sends_one_cast_credit() {
    let sender = ActorState::from(&fungible(INIT_SUPPLY));
    let run = |message: &Message| turn(HOLDING_ID, true, None, &sender, message);

    let cast = run(&cast_transfer(FUNGIBLE, TRANSFER_AMOUNT));

    assert_eq!(
        cast.response.post_state,
        run(&transfer(FUNGIBLE, TRANSFER_AMOUNT))
            .response
            .post_state
    );
    assert_eq!(
        (cast.response.calls, cast.response.casts),
        (
            Vec::new(),
            vec![Cast::new(
                token_actor(HOLDING_ID_2),
                &credit(FUNGIBLE, TRANSFER_AMOUNT)
            )]
        )
    );
}

#[should_panic(expected = "Sender authorization is missing")]
#[test]
fn a_cast_transfer_without_sender_authorization_is_rejected() {
    let _transition = turn(
        HOLDING_ID,
        false,
        None,
        &ActorState::from(&fungible(INIT_SUPPLY)),
        &cast_transfer(FUNGIBLE, TRANSFER_AMOUNT),
    );
}

#[test]
fn expected_sends_for_a_cast_transfer_is_one_cast_credit_to_the_recipient() {
    assert_eq!(
        expected_sends(
            Actor::new(HOLDING_ID, TOKEN_PROGRAM_ID),
            &cast_transfer(FUNGIBLE, TRANSFER_AMOUNT)
        ),
        (
            Vec::new(),
            vec![Cast::new(
                token_actor(HOLDING_ID_2),
                &credit(FUNGIBLE, TRANSFER_AMOUNT)
            )]
        )
    );
}

// --- ensure holding and kind -----------------------------------------------------------------

#[test]
fn ensure_holding_zeroizes_an_empty_or_mismatched_authorized_target() {
    let other_definition = TokenHolding::Fungible {
        definition_id: OTHER_DEFINITION_ID,
        balance: HOLDING_BALANCE,
    };
    let targets = [
        ActorState::empty(),
        ActorState::from(&other_definition),
        ActorState::from(vec![0xFF; 4]),
    ];

    for target in targets {
        assert_eq!(
            holding_at(
                &Message::EnsureHolding {
                    descriptor: FUNGIBLE
                },
                &target
            ),
            fungible(0)
        );
    }
}

#[should_panic(expected = "Only Uninitialized or authorized accounts can be initialized")]
#[test]
fn ensure_holding_rejects_a_mismatched_unauthorized_target() {
    let other_definition = TokenHolding::Fungible {
        definition_id: OTHER_DEFINITION_ID,
        balance: HOLDING_BALANCE,
    };
    let _transition = turn(
        HOLDING_ID,
        false,
        None,
        &ActorState::from(&other_definition),
        &Message::EnsureHolding {
            descriptor: FUNGIBLE,
        },
    );
}

#[test]
fn another_actor_replaces_a_funded_holding_only_with_authorization() {
    let requester = Some(OTHER_DEFINITION_ID);
    let funded = ActorState::from(&TokenHolding::Fungible {
        definition_id: OTHER_DEFINITION_ID,
        balance: HOLDING_BALANCE,
    });
    let request = |is_authorized| {
        turn(
            HOLDING_ID,
            is_authorized,
            requester,
            &funded,
            &Message::EnsureHolding {
                descriptor: FUNGIBLE,
            },
        )
    };

    assert_eq!(
        request(true).response.post_state,
        Some(ActorState::from(&fungible(0)))
    );
    let refusal = std::panic::catch_unwind(|| request(false).response.post_state)
        .expect_err("an unauthorized reset was accepted");
    assert_eq!(
        refusal.downcast_ref::<&str>(),
        Some(&"Only Uninitialized or authorized accounts can be initialized")
    );
}

#[test]
fn ensure_holding_keeps_a_matching_funded_holding() {
    for is_authorized in [false, true] {
        assert_eq!(
            turn(
                HOLDING_ID,
                is_authorized,
                None,
                &ActorState::from(&fungible(HOLDING_BALANCE)),
                &Message::EnsureHolding {
                    descriptor: FUNGIBLE,
                },
            )
            .response
            .post_state,
            None
        );
    }
}

#[test]
fn ensure_holding_keeps_a_funded_master_for_a_printed_copy_descriptor() {
    assert_eq!(
        turn(
            HOLDING_ID,
            false,
            None,
            &ActorState::from(&master(PRINTABLE_COPIES)),
            &Message::EnsureHolding {
                descriptor: PRINTED,
            },
        )
        .response
        .post_state,
        None
    );
}

#[test]
fn assert_kind_keeps_the_definition_it_checked() {
    assert_eq!(
        written(
            &Message::AssertKind {
                kind: TokenKind::Fungible
            },
            &ActorState::from(&fungible_definition(INIT_SUPPLY)),
        ),
        None
    );
    assert_eq!(
        written(
            &Message::AssertKind {
                kind: TokenKind::NftPrintedCopy
            },
            &ActorState::from(&non_fungible_definition(PRINTABLE_COPIES)),
        ),
        None
    );
}

#[test]
fn assert_kind_rejects_a_forged_token_kind() {
    // The kind a holding is ensured with comes from the message, and the holding's own turn
    // never sees the definition. `AssertKind` on the definition is the only thing standing
    // between a claimed kind and a holding that carries it.
    let cases = [
        (
            ActorState::from(&fungible_definition(INIT_SUPPLY)),
            TokenKind::NftMaster,
        ),
        (
            ActorState::from(&fungible_definition(INIT_SUPPLY)),
            TokenKind::NftPrintedCopy,
        ),
        (
            ActorState::from(&non_fungible_definition(PRINTABLE_COPIES)),
            TokenKind::Fungible,
        ),
        (
            ActorState::from(&non_fungible_definition(PRINTABLE_COPIES)),
            TokenKind::NftMaster,
        ),
    ];

    for (definition, claimed) in cases {
        assert!(
            rejection(&Message::AssertKind { kind: claimed }, &definition)
                .contains("Token Definition does not initialize this Token Holding kind"),
            "AssertKind accepted a claimed kind of {claimed:?}"
        );
    }
}

// --- mint ------------------------------------------------------------------------------------

#[should_panic(expected = "Definition authorization is missing")]
#[test]
fn mint_missing_authorization() {
    let _transition = turn(
        DEFINITION_ID,
        false,
        None,
        &ActorState::from(&fungible_definition(INIT_SUPPLY)),
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
        &ActorState::from(&fungible_definition(INIT_SUPPLY)),
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
        &ActorState::from(&fungible(HOLDING_BALANCE)),
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
                ActorState::from(&fungible_definition(INIT_SUPPLY)),
            ),
            (HOLDING_ID, ActorState::from(&fungible(HOLDING_BALANCE))),
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
            ActorState::from(&fungible_definition(INIT_SUPPLY)),
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
        &ActorState::from(&fungible_definition(INIT_SUPPLY)),
    );
}

#[should_panic(expected = "Recipient balance overflow")]
#[test]
fn mint_holding_account_overflow() {
    let _written = written(
        &credit(FUNGIBLE, MINT_OVERFLOW),
        &ActorState::from(&fungible(INIT_SUPPLY)),
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
        &ActorState::from(&non_fungible_definition(PRINTABLE_COPIES)),
    );
}

#[should_panic(expected = "Mismatched Token Definition and Token Holding types")]
#[test]
fn mint_into_a_non_fungible_holding_is_rejected() {
    let _written = written(
        &credit(FUNGIBLE, MINT_SUCCESS),
        &ActorState::from(&master(PRINTABLE_COPIES)),
    );
}

// --- burn ------------------------------------------------------------------------------------

#[should_panic(expected = "Authorization is missing")]
#[test]
fn burn_missing_authorization() {
    let _transition = turn(
        HOLDING_ID,
        false,
        None,
        &ActorState::from(&fungible(HOLDING_BALANCE)),
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
        &ActorState::from(&other_definition),
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
        &ActorState::from(&fungible(HOLDING_BALANCE)),
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
        &ActorState::from(&fungible_definition(INIT_SUPPLY)),
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
                ActorState::from(&fungible_definition(INIT_SUPPLY)),
            ),
            (HOLDING_ID, ActorState::from(&fungible(HOLDING_BALANCE))),
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
            &ActorState::from(&non_fungible_definition(PRINTABLE_COPIES)),
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
            &ActorState::from(&master(PRINTABLE_COPIES)),
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
            &ActorState::from(&non_fungible_definition(PRINTABLE_COPIES)),
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
            &ActorState::from(&printed(true)),
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
        &ActorState::from(&printed(false)),
    );
}

#[test]
fn burn_rejects_a_forged_holding_kind() {
    // The claimed kind picks which of the definition's two supplies is decremented, and the
    // definition's turn never sees the holding. Both turns check the same claim against
    // their own contents.
    let definitions = [
        (
            ActorState::from(&fungible_definition(INIT_SUPPLY)),
            TokenKind::NftMaster,
        ),
        (
            ActorState::from(&fungible_definition(INIT_SUPPLY)),
            TokenKind::NftPrintedCopy,
        ),
        (
            ActorState::from(&non_fungible_definition(PRINTABLE_COPIES)),
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
        (ActorState::from(&fungible(HOLDING_BALANCE)), MASTER),
        (ActorState::from(&master(PRINTABLE_COPIES)), FUNGIBLE),
        (ActorState::from(&printed(true)), MASTER),
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

#[test]
fn a_burn_sends_the_supply_burn_to_the_definition_it_names() {
    let transition = turn(
        HOLDING_ID,
        true,
        None,
        &ActorState::from(&fungible(HOLDING_BALANCE)),
        &Message::Burn {
            descriptor: FUNGIBLE,
            amount: BURN_SUCCESS,
            definition: DEFINITION_ID,
        },
    );

    assert_eq!(
        (transition.response.calls, transition.response.casts),
        (
            vec![Call::new(
                token_actor(DEFINITION_ID),
                &Message::BurnSupply {
                    definition_id: DEFINITION_ID,
                    kind: TokenKind::Fungible,
                    amount: BURN_SUCCESS,
                }
            )],
            Vec::new()
        )
    );
}

#[should_panic(expected = "A supply burn names another definition")]
#[test]
fn a_supply_burn_received_by_another_definition_is_rejected() {
    let _transition = turn(
        OTHER_DEFINITION_ID,
        true,
        TOKEN_ORIGIN,
        &ActorState::from(&fungible_definition(INIT_SUPPLY)),
        &Message::BurnSupply {
            definition_id: DEFINITION_ID,
            kind: TokenKind::Fungible,
            amount: BURN_SUCCESS,
        },
    );
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
        None,
        &ActorState::from(&master(PRINTABLE_COPIES)),
        &print_nft(DEFINITION_ID),
    );
}

#[should_panic(expected = "Invalid Token Holding data")]
#[test]
fn print_nft_master_nft_invalid_token_holding() {
    let _written = written(
        &print_nft(DEFINITION_ID),
        &ActorState::from(&fungible_definition(INIT_SUPPLY)),
    );
}

#[should_panic(expected = "Invalid Token Holding provided as NFT Master Account")]
#[test]
fn print_nft_master_nft_not_nft_master_account() {
    let _written = written(
        &print_nft(DEFINITION_ID),
        &ActorState::from(&fungible(INIT_SUPPLY)),
    );
}

#[should_panic(expected = "Insufficient balance to print another NFT copy")]
#[test]
fn print_nft_master_nft_insufficient_balance() {
    let _written = written(&print_nft(DEFINITION_ID), &ActorState::from(&master(1)));
}

#[should_panic(expected = "Printed copy does not belong to the master's Token Definition")]
#[test]
fn print_nft_rejects_a_forged_definition_id() {
    // The collection the new copy claims is message data, and the printed account's turn
    // never sees the master. Without this check a master of any collection could print a copy
    // of a more valuable one.
    let _written = written(
        &print_nft(OTHER_DEFINITION_ID),
        &ActorState::from(&master(PRINTABLE_COPIES)),
    );
}

#[test]
fn print_nft_success() {
    let state = settle(
        HOLDING_ID,
        &print_nft(DEFINITION_ID),
        &[HOLDING_ID],
        &[(HOLDING_ID, ActorState::from(&master(PRINTABLE_COPIES)))],
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
