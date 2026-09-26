#![cfg(test)]

use std::collections::HashMap;

use lee_core::{
    account::{AccountId, ShardData},
    program::{AccountMeta, Plan, PlanInput},
};
use token_core::{
    Instruction, MetadataStandard, NewTokenDefinition, NewTokenMetadata, TokenDefinition,
    TokenDescriptor, TokenHolding, TokenKind, TokenMetadata,
};

use crate::Effect;

const TOKEN_PROGRAM_ID: AccountId = AccountId::new([5; 32]);
const DEFINITION_ID: AccountId = AccountId::new([15; 32]);
const OTHER_DEFINITION_ID: AccountId = AccountId::new([16; 32]);
const HOLDING_ID: AccountId = AccountId::new([17; 32]);
const HOLDING_ID_2: AccountId = AccountId::new([42; 32]);
const METADATA_ID: AccountId = AccountId::new([43; 32]);

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

fn handle(account_id: AccountId, is_authorized: bool) -> AccountMeta {
    AccountMeta::new(account_id, is_authorized, TOKEN_PROGRAM_ID)
}

fn plan_for(accounts: Vec<AccountMeta>, instruction: Instruction) -> Plan {
    crate::plan(
        &PlanInput {
            self_account_id: TOKEN_PROGRAM_ID,
            caller_account_id: None,
            accounts,
            instruction_data: borsh::to_vec(&instruction).expect("the instruction serializes"),
        },
        instruction,
    )
}

fn rejection(effect: Effect, pre_data: &ShardData) -> String {
    let payload = std::panic::catch_unwind(|| crate::apply(effect, pre_data))
        .expect_err("the effect accepted the proposal");
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

fn holding_at(effect: Effect, pre_data: &ShardData) -> TokenHolding {
    let written = crate::apply(effect, pre_data).expect("the effect writes its shard");
    TokenHolding::try_from(&written).expect("apply wrote a holding")
}

fn definition_at(effect: Effect, pre_data: &ShardData) -> TokenDefinition {
    let written = crate::apply(effect, pre_data).expect("the effect writes its shard");
    TokenDefinition::try_from(&written).expect("apply wrote a definition")
}

fn settle(plan: &Plan, initial: &[(AccountId, ShardData)]) -> HashMap<AccountId, ShardData> {
    let mut state: HashMap<AccountId, ShardData> = initial.iter().cloned().collect();

    for effect in &plan.output().effects {
        let pre_data = state
            .get(&effect.selector.account_id)
            .cloned()
            .unwrap_or_default();
        let post_data = crate::apply(
            borsh::from_slice(&effect.data).expect("the plan wrote a token effect"),
            &pre_data,
        );
        if let Some(post_data) = post_data {
            state.insert(effect.selector.account_id, post_data);
        }
    }

    state
}

fn settled_holding(state: &HashMap<AccountId, ShardData>, account_id: AccountId) -> TokenHolding {
    TokenHolding::try_from(state.get(&account_id).expect("the account was settled"))
        .expect("apply wrote a holding")
}

fn settled_definition(
    state: &HashMap<AccountId, ShardData>,
    account_id: AccountId,
) -> TokenDefinition {
    TokenDefinition::try_from(state.get(&account_id).expect("the account was settled"))
        .expect("apply wrote a definition")
}

// --- new definitions -------------------------------------------------------------------------

#[test]
fn new_definition_with_valid_inputs_succeeds() {
    let plan = plan_for(
        vec![handle(DEFINITION_ID, true), handle(HOLDING_ID, true)],
        Instruction::NewFungibleDefinition {
            name: String::from("test"),
            total_supply: INIT_SUPPLY,
        },
    );
    let state = settle(&plan, &[]);

    let definition = settled_definition(&state, DEFINITION_ID);
    let holding = settled_holding(&state, HOLDING_ID);
    assert_eq!(definition, fungible_definition(INIT_SUPPLY));
    assert_eq!(holding, fungible(INIT_SUPPLY));
}

#[test]
fn new_definition_with_metadata_creates_a_master_copy_for_a_non_fungible() {
    let plan = plan_for(
        vec![
            handle(DEFINITION_ID, true),
            handle(HOLDING_ID, true),
            handle(METADATA_ID, true),
        ],
        Instruction::NewDefinitionWithMetadata {
            new_definition: NewTokenDefinition::NonFungible {
                name: String::from("test"),
                printable_supply: PRINTABLE_COPIES,
            },
            metadata: Box::new(new_metadata()),
        },
    );
    let state = settle(&plan, &[]);

    let definition = settled_definition(&state, DEFINITION_ID);
    let holding = settled_holding(&state, HOLDING_ID);
    assert_eq!(definition, non_fungible_definition(PRINTABLE_COPIES));
    assert_eq!(holding, master(PRINTABLE_COPIES));
    assert_eq!(state.get(&METADATA_ID), Some(&ShardData::from(&metadata())));
}

#[test]
fn every_planned_creation_writes_only_into_an_empty_target() {
    let fungible_with_metadata = NewTokenDefinition::Fungible {
        name: String::from("test"),
        total_supply: INIT_SUPPLY,
    };
    let non_fungible_with_metadata = NewTokenDefinition::NonFungible {
        name: String::from("test"),
        printable_supply: PRINTABLE_COPIES,
    };
    let definition_accounts = || {
        vec![
            handle(DEFINITION_ID, true),
            handle(HOLDING_ID, true),
            handle(METADATA_ID, true),
        ]
    };
    let cases = [
        (
            "NewFungibleDefinition",
            vec![handle(DEFINITION_ID, true), handle(HOLDING_ID, true)],
            Instruction::NewFungibleDefinition {
                name: String::from("test"),
                total_supply: INIT_SUPPLY,
            },
            vec![DEFINITION_ID, HOLDING_ID],
        ),
        (
            "NewDefinitionWithMetadata (fungible)",
            definition_accounts(),
            Instruction::NewDefinitionWithMetadata {
                new_definition: fungible_with_metadata,
                metadata: Box::new(new_metadata()),
            },
            vec![DEFINITION_ID, HOLDING_ID, METADATA_ID],
        ),
        (
            "NewDefinitionWithMetadata (non-fungible)",
            definition_accounts(),
            Instruction::NewDefinitionWithMetadata {
                new_definition: non_fungible_with_metadata,
                metadata: Box::new(new_metadata()),
            },
            vec![DEFINITION_ID, HOLDING_ID, METADATA_ID],
        ),
        (
            "PrintNft",
            vec![handle(HOLDING_ID, true), handle(HOLDING_ID_2, false)],
            Instruction::PrintNft {
                definition_id: DEFINITION_ID,
            },
            vec![HOLDING_ID_2],
        ),
    ];

    for (operation, accounts, instruction, targets) in cases {
        let plan = plan_for(accounts, instruction);
        let creations: Vec<(AccountId, ShardData)> = plan
            .output()
            .effects
            .iter()
            .filter_map(|effect| {
                let Effect::Create(data) =
                    borsh::from_slice(&effect.data).expect("the plan wrote a token effect")
                else {
                    return None;
                };
                Some((effect.selector.account_id, data))
            })
            .collect();
        assert_eq!(
            creations
                .iter()
                .map(|(account_id, _)| *account_id)
                .collect::<Vec<_>>(),
            targets,
            "{operation} creates a different set of accounts"
        );

        for (account_id, data) in creations {
            let create = Effect::Create(data.clone());
            assert_eq!(
                crate::apply(create.clone(), &ShardData::empty()).as_ref(),
                Some(&data),
                "{operation} wrote something other than its plan into {account_id}"
            );
            // Even the very data it would write: a creation never lands twice.
            for occupant in [data, ShardData::from(&fungible(1))] {
                assert!(
                    rejection(create.clone(), &occupant)
                        .contains("Target account must not already hold data"),
                    "{operation} overwrote the occupied account {account_id}"
                );
            }
        }
    }
}

// --- transfer --------------------------------------------------------------------------------

#[should_panic(expected = "Sender authorization is missing")]
#[test]
fn transfer_without_sender_authorization_should_fail() {
    let _plan = plan_for(
        vec![handle(HOLDING_ID, false), handle(HOLDING_ID_2, false)],
        Instruction::Transfer {
            amount_to_transfer: TRANSFER_AMOUNT,
            descriptor: FUNGIBLE,
        },
    );
}

#[should_panic(expected = "Mismatch Token Definition and Token Holding")]
#[test]
fn transfer_with_different_definition_ids_should_fail() {
    let recipient = TokenHolding::Fungible {
        definition_id: OTHER_DEFINITION_ID,
        balance: HOLDING_BALANCE,
    };
    let _written = crate::apply(
        Effect::Deposit {
            descriptor: FUNGIBLE,
            amount: TRANSFER_AMOUNT,
        },
        &ShardData::from(&recipient),
    );
}

#[should_panic(expected = "Mismatched Token Definition and Token Holding types")]
#[test]
fn transfer_with_mismatched_holding_kinds_should_fail() {
    let _written = crate::apply(
        Effect::Withdraw {
            descriptor: FUNGIBLE,
            amount: PRINTABLE_COPIES,
        },
        &ShardData::from(&master(PRINTABLE_COPIES)),
    );
}

#[should_panic(expected = "Insufficient balance")]
#[test]
fn transfer_with_insufficient_balance_should_fail() {
    let _written = crate::apply(
        Effect::Withdraw {
            descriptor: FUNGIBLE,
            amount: BURN_INSUFFICIENT,
        },
        &ShardData::from(&fungible(HOLDING_BALANCE)),
    );
}

#[test]
fn transfer_with_valid_inputs_succeeds() {
    let plan = plan_for(
        vec![handle(HOLDING_ID, true), handle(HOLDING_ID_2, false)],
        Instruction::Transfer {
            amount_to_transfer: TRANSFER_AMOUNT,
            descriptor: FUNGIBLE,
        },
    );
    let state = settle(
        &plan,
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
        holding_at(
            Effect::Deposit {
                descriptor: FUNGIBLE,
                amount: TRANSFER_AMOUNT,
            },
            &ShardData::empty(),
        ),
        fungible(TRANSFER_AMOUNT)
    );
}

#[test]
fn transfer_with_master_nft_invalid_balance() {
    // The whole print balance must move, and the instruction only *claims* how much that is.
    // Every claim other than the master's real print balance is refused by the sender's own
    // effect, so a forged claim cannot mint print capacity into the recipient.
    for claimed in [
        0,
        1,
        PRINTABLE_COPIES_AFTER_PRINT,
        TRANSFER_AMOUNT,
        u128::MAX,
    ] {
        assert!(
            rejection(
                Effect::Withdraw {
                    descriptor: MASTER,
                    amount: claimed,
                },
                &ShardData::from(&master(PRINTABLE_COPIES)),
            )
            .contains("Invalid balance for NFT Master transfer"),
            "Withdraw accepted a claimed print balance of {claimed}"
        );
    }
}

#[should_panic(expected = "Invalid balance in recipient account for NFT transfer")]
#[test]
fn transfer_with_master_nft_invalid_recipient_balance() {
    let _written = crate::apply(
        Effect::Deposit {
            descriptor: MASTER,
            amount: PRINTABLE_COPIES,
        },
        &ShardData::from(&master(PRINTABLE_COPIES)),
    );
}

#[test]
fn transfer_with_master_nft_success() {
    assert_eq!(
        holding_at(
            Effect::Withdraw {
                descriptor: MASTER,
                amount: PRINTABLE_COPIES,
            },
            &ShardData::from(&master(PRINTABLE_COPIES)),
        ),
        master(0)
    );
    assert_eq!(
        holding_at(
            Effect::Deposit {
                descriptor: MASTER,
                amount: PRINTABLE_COPIES,
            },
            &ShardData::empty(),
        ),
        master(PRINTABLE_COPIES)
    );
}

#[test]
fn transfer_of_a_printed_copy_moves_ownership() {
    assert_eq!(
        holding_at(
            Effect::Withdraw {
                descriptor: PRINTED,
                amount: 1,
            },
            &ShardData::from(&printed(true)),
        ),
        printed(false)
    );
    assert_eq!(
        holding_at(
            Effect::Deposit {
                descriptor: PRINTED,
                amount: 1,
            },
            &ShardData::from(&printed(false)),
        ),
        printed(true)
    );
}

#[should_panic(expected = "Sender does not own the NFT Printed Copy")]
#[test]
fn transfer_of_an_unowned_printed_copy_should_fail() {
    let _written = crate::apply(
        Effect::Withdraw {
            descriptor: PRINTED,
            amount: 1,
        },
        &ShardData::from(&printed(false)),
    );
}

// --- initialize ------------------------------------------------------------------------------

#[test]
fn initialize_account_writes_the_zeroized_holding_regardless_of_prior_content() {
    let plan = plan_for(
        vec![handle(DEFINITION_ID, false), handle(HOLDING_ID, true)],
        Instruction::InitializeAccount {
            kind: TokenKind::Fungible,
        },
    );
    let other_definition = TokenHolding::Fungible {
        definition_id: OTHER_DEFINITION_ID,
        balance: HOLDING_BALANCE,
    };
    let targets = [
        ShardData::empty(),
        ShardData::from(&other_definition),
        ShardData::try_from(vec![0xFF; 4]).expect("fits the shard limit"),
    ];

    for target in targets {
        let state = settle(
            &plan,
            &[
                (
                    DEFINITION_ID,
                    ShardData::from(&fungible_definition(INIT_SUPPLY)),
                ),
                (HOLDING_ID, target),
            ],
        );
        assert_eq!(settled_holding(&state, HOLDING_ID), fungible(0));
    }
}

#[should_panic(expected = "Only Uninitialized or authorized accounts can be initialized")]
#[test]
fn initialize_account_rejects_occupied_unauthorized_target() {
    let _written = crate::apply(
        Effect::InitializeHolding {
            descriptor: FUNGIBLE,
            is_authorized: false,
        },
        &ShardData::from(&fungible(HOLDING_BALANCE)),
    );
}

#[test]
fn initialize_account_keeps_the_definition_it_checked() {
    assert_eq!(
        crate::apply(
            Effect::CheckHoldingKind(TokenKind::Fungible),
            &ShardData::from(&fungible_definition(INIT_SUPPLY)),
        ),
        None
    );
    assert_eq!(
        crate::apply(
            Effect::CheckHoldingKind(TokenKind::NftPrintedCopy),
            &ShardData::from(&non_fungible_definition(PRINTABLE_COPIES)),
        ),
        None
    );
}

#[test]
fn initialize_account_rejects_a_forged_token_kind() {
    // The kind the holding is created with comes from the instruction, and the holding's own
    // `apply` never sees the definition. `CheckHoldingKind` on the definition is the only
    // thing standing between a claimed kind and a holding that carries it.
    let cases = [
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
        (
            ShardData::from(&non_fungible_definition(PRINTABLE_COPIES)),
            TokenKind::NftMaster,
        ),
    ];

    for (definition, claimed) in cases {
        assert!(
            rejection(Effect::CheckHoldingKind(claimed), &definition)
                .contains("Token Definition does not initialize this Token Holding kind"),
            "CheckHoldingKind accepted a claimed kind of {claimed:?}"
        );
    }
}

// --- mint ------------------------------------------------------------------------------------

#[should_panic(expected = "Definition authorization is missing")]
#[test]
fn mint_missing_authorization() {
    let _plan = plan_for(
        vec![handle(DEFINITION_ID, false), handle(HOLDING_ID, false)],
        Instruction::Mint {
            amount_to_mint: MINT_SUCCESS,
        },
    );
}

#[should_panic(expected = "Invalid recipient data")]
#[test]
fn mint_not_valid_holding_account() {
    let _written = crate::apply(
        Effect::Deposit {
            descriptor: FUNGIBLE,
            amount: MINT_SUCCESS,
        },
        &ShardData::from(&fungible_definition(INIT_SUPPLY)),
    );
}

#[should_panic(expected = "Definition account must be valid")]
#[test]
fn mint_not_valid_definition_account() {
    let _written = crate::apply(
        Effect::MintSupply {
            amount: MINT_SUCCESS,
        },
        &ShardData::from(&fungible(HOLDING_BALANCE)),
    );
}

#[test]
fn mint_success() {
    let plan = plan_for(
        vec![handle(DEFINITION_ID, true), handle(HOLDING_ID, false)],
        Instruction::Mint {
            amount_to_mint: MINT_SUCCESS,
        },
    );
    let state = settle(
        &plan,
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
    let plan = plan_for(
        vec![handle(DEFINITION_ID, true), handle(HOLDING_ID, false)],
        Instruction::Mint {
            amount_to_mint: MINT_SUCCESS,
        },
    );
    let state = settle(
        &plan,
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
    let _written = crate::apply(
        Effect::MintSupply {
            amount: MINT_OVERFLOW,
        },
        &ShardData::from(&fungible_definition(INIT_SUPPLY)),
    );
}

#[should_panic(expected = "Recipient balance overflow")]
#[test]
fn mint_holding_account_overflow() {
    let _written = crate::apply(
        Effect::Deposit {
            descriptor: FUNGIBLE,
            amount: MINT_OVERFLOW,
        },
        &ShardData::from(&fungible(INIT_SUPPLY)),
    );
}

#[should_panic(expected = "Cannot mint additional supply for Non-Fungible Tokens")]
#[test]
fn mint_cannot_mint_unmintable_tokens() {
    let _written = crate::apply(
        Effect::MintSupply {
            amount: MINT_SUCCESS,
        },
        &ShardData::from(&non_fungible_definition(PRINTABLE_COPIES)),
    );
}

#[should_panic(expected = "Mismatched Token Definition and Token Holding types")]
#[test]
fn mint_into_a_non_fungible_holding_is_rejected() {
    let _written = crate::apply(
        Effect::Deposit {
            descriptor: FUNGIBLE,
            amount: MINT_SUCCESS,
        },
        &ShardData::from(&master(PRINTABLE_COPIES)),
    );
}

// --- burn ------------------------------------------------------------------------------------

#[should_panic(expected = "Authorization is missing")]
#[test]
fn burn_missing_authorization() {
    let _plan = plan_for(
        vec![handle(DEFINITION_ID, true), handle(HOLDING_ID, false)],
        Instruction::Burn {
            amount_to_burn: BURN_SUCCESS,
            kind: TokenKind::Fungible,
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
    let _written = crate::apply(
        Effect::BurnHolding {
            descriptor: FUNGIBLE,
            amount: BURN_SUCCESS,
        },
        &ShardData::from(&other_definition),
    );
}

#[should_panic(expected = "Insufficient balance to burn")]
#[test]
fn burn_insufficient_balance() {
    let _written = crate::apply(
        Effect::BurnHolding {
            descriptor: FUNGIBLE,
            amount: BURN_INSUFFICIENT,
        },
        &ShardData::from(&fungible(HOLDING_BALANCE)),
    );
}

#[should_panic(expected = "Total supply underflow")]
#[test]
fn burn_total_supply_underflow() {
    let _written = crate::apply(
        Effect::BurnSupply {
            kind: TokenKind::Fungible,
            amount: MINT_OVERFLOW,
        },
        &ShardData::from(&fungible_definition(INIT_SUPPLY)),
    );
}

#[test]
fn burn_success() {
    let plan = plan_for(
        vec![handle(DEFINITION_ID, false), handle(HOLDING_ID, true)],
        Instruction::Burn {
            amount_to_burn: BURN_SUCCESS,
            kind: TokenKind::Fungible,
        },
    );
    let state = settle(
        &plan,
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
            Effect::BurnSupply {
                kind: TokenKind::NftMaster,
                amount: 1,
            },
            &ShardData::from(&non_fungible_definition(PRINTABLE_COPIES)),
        ),
        non_fungible_definition(PRINTABLE_COPIES_AFTER_PRINT)
    );
    assert_eq!(
        holding_at(
            Effect::BurnHolding {
                descriptor: MASTER,
                amount: 1,
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
            Effect::BurnSupply {
                kind: TokenKind::NftPrintedCopy,
                amount: 1,
            },
            &ShardData::from(&non_fungible_definition(PRINTABLE_COPIES)),
        ),
        non_fungible_definition(PRINTABLE_COPIES_AFTER_PRINT)
    );
    assert_eq!(
        holding_at(
            Effect::BurnHolding {
                descriptor: PRINTED,
                amount: 1,
            },
            &ShardData::from(&printed(true)),
        ),
        printed(false)
    );
}

#[should_panic(expected = "Cannot burn unowned NFT Printed Copy")]
#[test]
fn burn_of_an_unowned_printed_copy_is_rejected() {
    let _written = crate::apply(
        Effect::BurnHolding {
            descriptor: PRINTED,
            amount: 1,
        },
        &ShardData::from(&printed(false)),
    );
}

#[test]
fn burn_rejects_a_forged_holding_kind() {
    // The claimed kind picks which of the definition's two supplies is decremented, and the
    // definition's `apply` never sees the holding. Both effects check the same claim against
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
                Effect::BurnSupply {
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
                Effect::BurnHolding {
                    descriptor: claimed,
                    amount: 1,
                },
                &holding,
            )
            .contains("Mismatched Token Definition and Token Holding types"),
            "BurnHolding accepted a claimed kind of {:?}",
            claimed.kind
        );
    }
}

// --- print nft -------------------------------------------------------------------------------

#[should_panic(expected = "Master NFT Account must be authorized")]
#[test]
fn print_nft_master_account_must_be_authorized() {
    let _plan = plan_for(
        vec![handle(HOLDING_ID, false), handle(HOLDING_ID_2, false)],
        Instruction::PrintNft {
            definition_id: DEFINITION_ID,
        },
    );
}

#[should_panic(expected = "Invalid Token Holding data")]
#[test]
fn print_nft_master_nft_invalid_token_holding() {
    let _written = crate::apply(
        Effect::PrintCopy {
            definition_id: DEFINITION_ID,
        },
        &ShardData::from(&fungible_definition(INIT_SUPPLY)),
    );
}

#[should_panic(expected = "Invalid Token Holding provided as NFT Master Account")]
#[test]
fn print_nft_master_nft_not_nft_master_account() {
    let _written = crate::apply(
        Effect::PrintCopy {
            definition_id: DEFINITION_ID,
        },
        &ShardData::from(&fungible(INIT_SUPPLY)),
    );
}

#[should_panic(expected = "Insufficient balance to print another NFT copy")]
#[test]
fn print_nft_master_nft_insufficient_balance() {
    let _written = crate::apply(
        Effect::PrintCopy {
            definition_id: DEFINITION_ID,
        },
        &ShardData::from(&master(1)),
    );
}

#[should_panic(expected = "Printed copy does not belong to the master's Token Definition")]
#[test]
fn print_nft_rejects_a_forged_definition_id() {
    // The collection the new copy claims is instruction data, and the printed account's
    // `apply` never sees the master. Without this check a master of any collection could
    // print a copy of a more valuable one.
    let _written = crate::apply(
        Effect::PrintCopy {
            definition_id: OTHER_DEFINITION_ID,
        },
        &ShardData::from(&master(PRINTABLE_COPIES)),
    );
}

#[test]
fn print_nft_success() {
    let plan = plan_for(
        vec![handle(HOLDING_ID, true), handle(HOLDING_ID_2, false)],
        Instruction::PrintNft {
            definition_id: DEFINITION_ID,
        },
    );
    let state = settle(
        &plan,
        &[(HOLDING_ID, ShardData::from(&master(PRINTABLE_COPIES)))],
    );

    let master_holding = settled_holding(&state, HOLDING_ID);
    let copy = settled_holding(&state, HOLDING_ID_2);
    assert_eq!(master_holding, master(PRINTABLE_COPIES_AFTER_PRINT));
    assert_eq!(copy, printed(true));
    assert_eq!(
        master_holding.definition_id(),
        copy.definition_id(),
        "the plan printed a copy of a collection the master does not hold"
    );
}

// --- dispatch --------------------------------------------------------------------------------

#[should_panic(expected = "names the shard of")]
#[test]
fn a_handle_selecting_another_programs_shard_is_rejected() {
    let foreign = AccountMeta::native_balance(HOLDING_ID_2, false);
    let _plan = plan_for(
        vec![handle(HOLDING_ID, true), foreign],
        Instruction::Transfer {
            amount_to_transfer: TRANSFER_AMOUNT,
            descriptor: FUNGIBLE,
        },
    );
}

#[should_panic(expected = "Transfer instruction requires exactly two accounts")]
#[test]
fn a_transfer_with_a_third_account_is_rejected() {
    let _plan = plan_for(
        vec![
            handle(HOLDING_ID, true),
            handle(HOLDING_ID_2, false),
            handle(DEFINITION_ID, false),
        ],
        Instruction::Transfer {
            amount_to_transfer: TRANSFER_AMOUNT,
            descriptor: FUNGIBLE,
        },
    );
}
