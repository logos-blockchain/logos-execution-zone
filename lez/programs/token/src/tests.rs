#![cfg(test)]
#![expect(
    clippy::shadow_unrelated,
    clippy::arithmetic_side_effects,
    reason = "We don't care about it in tests"
)]

use lee_core::{
    account::{AccountId, AccountIdData, BalanceDiff, ShardData},
    program::{AccountInput, AccountStateDiff},
};
use token_core::{
    HoldingKind, HoldingTarget, MetadataStandard, NewTokenDefinition, NewTokenMetadata,
    TokenDefinition, TokenHolding,
};

use crate::{
    burn::burn,
    initialize::initialize_account,
    mint::mint,
    new_definition::{new_definition_with_metadata, new_fungible_definition},
    print_nft::print_nft,
    transfer::transfer,
};

// TODO: Move tests to a proper modules like burn, mint, transfer, etc, so that they are more
// unit-test.

const TOKEN_PROGRAM_ID: AccountId = AccountId::new([5; 32]);

struct BalanceForTests;
struct IdForTests;
struct HolderForTests;

struct AccountForTests;

impl AccountForTests {
    fn at(
        holder: &HoldingTarget,
        definition_id: AccountId,
        kind: HoldingKind,
        data: ShardData,
    ) -> AccountInput {
        AccountInput::with_shard(
            token_core::holding_id(holder, TOKEN_PROGRAM_ID, definition_id, kind),
            false,
            0,
            TOKEN_PROGRAM_ID,
            data,
        )
    }

    fn holding(holder: &HoldingTarget, holding: &TokenHolding) -> AccountInput {
        Self::at(
            holder,
            holding.definition_id(),
            holding.kind(),
            ShardData::from(holding),
        )
    }

    fn fungible_holding(holder: &HoldingTarget, balance: u128) -> AccountInput {
        Self::holding(
            holder,
            &TokenHolding::Fungible {
                definition_id: IdForTests::pool_definition_id(),
                balance,
            },
        )
    }

    fn master_nft_holding(holder: &HoldingTarget, print_balance: u128) -> AccountInput {
        Self::holding(
            holder,
            &TokenHolding::NftMaster {
                definition_id: IdForTests::pool_definition_id(),
                print_balance,
            },
        )
    }

    fn owner_row(holder: &HoldingTarget, is_authorized: bool) -> AccountInput {
        AccountInput::balance(holder.owner_id, is_authorized, 0)
    }

    fn definition(
        account_id: AccountId,
        is_authorized: bool,
        definition: &TokenDefinition,
    ) -> AccountInput {
        AccountInput::with_shard(
            account_id,
            is_authorized,
            0,
            TOKEN_PROGRAM_ID,
            ShardData::from(definition),
        )
    }

    fn definition_account_auth() -> AccountInput {
        Self::definition(
            IdForTests::pool_definition_id(),
            true,
            &TokenDefinition::Fungible {
                name: String::from("test"),
                total_supply: BalanceForTests::init_supply(),
                metadata_id: None,
            },
        )
    }

    fn definition_account_without_auth() -> AccountInput {
        Self::definition(
            IdForTests::pool_definition_id(),
            false,
            &TokenDefinition::Fungible {
                name: String::from("test"),
                total_supply: BalanceForTests::init_supply(),
                metadata_id: None,
            },
        )
    }

    fn definition_account_with_holding_data() -> AccountInput {
        AccountInput::with_shard(
            IdForTests::pool_definition_id(),
            true,
            0,
            TOKEN_PROGRAM_ID,
            ShardData::from(&TokenHolding::Fungible {
                definition_id: IdForTests::pool_definition_id(),
                balance: BalanceForTests::holding_balance(),
            }),
        )
    }

    fn holding_account_with_definition_data(
        holder: &HoldingTarget,
        kind: HoldingKind,
    ) -> AccountInput {
        Self::at(
            holder,
            IdForTests::pool_definition_id(),
            kind,
            ShardData::from(&TokenDefinition::Fungible {
                name: String::from("test"),
                total_supply: BalanceForTests::init_supply(),
                metadata_id: None,
            }),
        )
    }

    fn holding_different_definition(
        holder: &HoldingTarget,
        address_definition_id: AccountId,
    ) -> AccountInput {
        Self::at(
            holder,
            address_definition_id,
            HoldingKind::Fungible,
            ShardData::from(&TokenHolding::Fungible {
                definition_id: IdForTests::pool_definition_id_diff(),
                balance: BalanceForTests::holding_balance(),
            }),
        )
    }

    fn holding_same_definition() -> AccountInput {
        Self::fungible_holding(&HolderForTests::owner(), BalanceForTests::holding_balance())
    }

    fn holding_same_definition_large_balance() -> AccountInput {
        Self::fungible_holding(&HolderForTests::owner(), BalanceForTests::mint_overflow())
    }

    fn definition_account_post_burn() -> AccountInput {
        Self::definition(
            IdForTests::pool_definition_id(),
            true,
            &TokenDefinition::Fungible {
                name: String::from("test"),
                total_supply: BalanceForTests::init_supply_burned(),
                metadata_id: None,
            },
        )
    }

    fn holding_account_post_burn() -> AccountInput {
        Self::fungible_holding(
            &HolderForTests::owner(),
            BalanceForTests::holding_balance_burned(),
        )
    }

    fn holding_account_uninit(holder: &HoldingTarget, kind: HoldingKind) -> AccountInput {
        Self::at(
            holder,
            IdForTests::pool_definition_id(),
            kind,
            ShardData::empty(),
        )
    }

    fn init_mint() -> AccountInput {
        Self::fungible_holding(&HolderForTests::owner(), BalanceForTests::mint_success())
    }

    fn holding_account_same_definition_mint() -> AccountInput {
        Self::fungible_holding(
            &HolderForTests::owner(),
            BalanceForTests::holding_balance_mint(),
        )
    }

    fn definition_account_mint() -> AccountInput {
        Self::definition(
            IdForTests::pool_definition_id(),
            true,
            &TokenDefinition::Fungible {
                name: String::from("test"),
                total_supply: BalanceForTests::init_supply_mint(),
                metadata_id: None,
            },
        )
    }

    fn definition_account_with_authorization_nonfungible() -> AccountInput {
        Self::definition(
            IdForTests::pool_definition_id(),
            true,
            &TokenDefinition::NonFungible {
                name: String::from("test"),
                printable_supply: BalanceForTests::printable_copies(),
                metadata_id: AccountId::new([0; 32]),
            },
        )
    }

    fn definition_account_uninit() -> AccountInput {
        AccountInput::with_shard(
            IdForTests::pool_definition_id(),
            true,
            0,
            TOKEN_PROGRAM_ID,
            ShardData::empty(),
        )
    }

    fn metadata_account_uninit() -> AccountInput {
        AccountInput::with_shard(
            IdForTests::metadata_id(),
            true,
            0,
            TOKEN_PROGRAM_ID,
            ShardData::empty(),
        )
    }

    fn metadata_account_init() -> AccountInput {
        AccountInput {
            account_id: IdForTests::metadata_id(),
            ..Self::definition_account_auth()
        }
    }

    fn holding_account_init() -> AccountInput {
        Self::fungible_holding(&HolderForTests::owner(), BalanceForTests::init_supply())
    }

    fn holding_account2_init() -> AccountInput {
        Self::fungible_holding(&HolderForTests::owner_2(), BalanceForTests::init_supply())
    }

    fn holding_account2_init_post_transfer() -> AccountInput {
        Self::fungible_holding(
            &HolderForTests::owner_2(),
            BalanceForTests::recipient_post_transfer(),
        )
    }

    fn holding_account_init_post_transfer() -> AccountInput {
        Self::fungible_holding(
            &HolderForTests::owner(),
            BalanceForTests::sender_post_transfer(),
        )
    }

    fn holding_account_master_nft() -> AccountInput {
        Self::master_nft_holding(
            &HolderForTests::owner(),
            BalanceForTests::printable_copies(),
        )
    }

    fn holding_account_master_nft_at_fungible_address() -> AccountInput {
        AccountInput {
            account_id: token_core::holding_id(
                &HolderForTests::owner(),
                TOKEN_PROGRAM_ID,
                IdForTests::pool_definition_id(),
                HoldingKind::Fungible,
            ),
            ..Self::holding_account_master_nft()
        }
    }

    fn holding_account_master_nft_insufficient_balance() -> AccountInput {
        Self::master_nft_holding(&HolderForTests::owner(), 1)
    }

    fn holding_account_master_nft_after_print() -> AccountInput {
        Self::master_nft_holding(
            &HolderForTests::owner(),
            BalanceForTests::printable_copies() - 1,
        )
    }

    fn holding_account_printed_nft() -> AccountInput {
        Self::holding(
            &HolderForTests::owner_2(),
            &TokenHolding::NftPrintedCopy {
                definition_id: IdForTests::pool_definition_id(),
                owned: true,
            },
        )
    }

    fn holding_account_with_master_nft_transferred_to() -> AccountInput {
        Self::master_nft_holding(
            &HolderForTests::owner_2(),
            BalanceForTests::printable_copies(),
        )
    }

    fn holding_account_master_nft_post_transfer() -> AccountInput {
        Self::master_nft_holding(&HolderForTests::owner(), 0)
    }
}

impl BalanceForTests {
    fn init_supply() -> u128 {
        100_000
    }

    fn holding_balance() -> u128 {
        1_000
    }

    fn init_supply_burned() -> u128 {
        99_500
    }

    fn holding_balance_burned() -> u128 {
        500
    }

    fn burn_success() -> u128 {
        500
    }

    fn burn_insufficient() -> u128 {
        1_500
    }

    fn mint_success() -> u128 {
        50_000
    }

    fn holding_balance_mint() -> u128 {
        51_000
    }

    fn mint_overflow() -> u128 {
        u128::MAX - 40_000
    }

    fn init_supply_mint() -> u128 {
        150_000
    }

    fn sender_post_transfer() -> u128 {
        95_000
    }

    fn recipient_post_transfer() -> u128 {
        105_000
    }

    fn transfer_amount() -> u128 {
        5_000
    }

    fn printable_copies() -> u128 {
        10
    }
}

impl IdForTests {
    fn pool_definition_id() -> AccountId {
        AccountId::new([15; 32])
    }

    fn pool_definition_id_diff() -> AccountId {
        AccountId::new([16; 32])
    }

    fn metadata_id() -> AccountId {
        AccountId::new([2; 32])
    }

    fn owner_id() -> AccountId {
        AccountId::new([17; 32])
    }

    fn owner_id_2() -> AccountId {
        AccountId::new([42; 32])
    }
}

impl HolderForTests {
    fn owner() -> HoldingTarget {
        HoldingTarget {
            owner_id: IdForTests::owner_id(),
            account_id_data: AccountIdData::public(),
        }
    }

    fn owner_2() -> HoldingTarget {
        HoldingTarget {
            owner_id: IdForTests::owner_id_2(),
            account_id_data: AccountIdData::public(),
        }
    }
}

/// Asserts the diff leaves the native balance untouched and sets data to exactly `expected`'s.
fn assert_data_diff(diff_output: &AccountStateDiff, expected: &AccountInput) {
    assert_eq!(diff_output.post_balance_diff, BalanceDiff::Add(0));
    let effective_data = diff_output
        .post_data
        .clone()
        .unwrap_or_else(|| diff_output.pre_state.shard_of(TOKEN_PROGRAM_ID).clone());
    assert_eq!(&effective_data, expected.shard_of(TOKEN_PROGRAM_ID));
}

#[should_panic(expected = "Definition target account must not already hold data")]
#[test]
fn new_definition_data_bearing_first_account_should_fail() {
    let holder = HolderForTests::owner();
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::holding_account_uninit(&holder, HoldingKind::Fungible);
    let _post_diffs = new_fungible_definition(
        &definition_account,
        &holding_account,
        &holder,
        TOKEN_PROGRAM_ID,
        String::from("test"),
        10,
    );
}

#[should_panic(expected = "Holding target account must not already hold data")]
#[test]
fn new_definition_data_bearing_second_account_should_fail() {
    let definition_account = AccountForTests::definition_account_uninit();
    let holding_account = AccountForTests::holding_account_init();
    let _post_diffs = new_fungible_definition(
        &definition_account,
        &holding_account,
        &HolderForTests::owner(),
        TOKEN_PROGRAM_ID,
        String::from("test"),
        10,
    );
}

/// A definition address is derivable, and anyone may credit an unowned account.
/// Creation must therefore turn on whether the address already holds data, not on
/// whether it is pristine — otherwise one unit of balance bricks the address for ever.
#[test]
fn new_definition_succeeds_on_an_address_someone_credited() {
    let holder = HolderForTests::owner();
    let mut definition_account = AccountForTests::definition_account_uninit();
    definition_account.balance = 1;
    let holding_account = AccountForTests::holding_account_uninit(&holder, HoldingKind::Fungible);

    let post_diffs = new_fungible_definition(
        &definition_account,
        &holding_account,
        &holder,
        TOKEN_PROGRAM_ID,
        String::from("test"),
        BalanceForTests::init_supply(),
    );

    let [definition_post, _holding_post] = post_diffs.try_into().unwrap();
    assert_eq!(
        definition_post.post_balance_diff,
        BalanceDiff::Add(0),
        "the credit is left alone"
    );
    assert!(
        definition_post
            .post_data
            .is_some_and(|data| !data.is_empty()),
        "the definition is written"
    );
}

#[test]
fn new_definition_with_valid_inputs_succeeds() {
    let holder = HolderForTests::owner();
    let definition_account = AccountForTests::definition_account_uninit();
    let holding_account = AccountForTests::holding_account_uninit(&holder, HoldingKind::Fungible);

    let post_diffs = new_fungible_definition(
        &definition_account,
        &holding_account,
        &holder,
        TOKEN_PROGRAM_ID,
        String::from("test"),
        BalanceForTests::init_supply(),
    );

    let [definition_account, holding_account] = post_diffs.try_into().unwrap();
    assert_data_diff(
        &definition_account,
        &AccountForTests::definition_account_auth(),
    );
    assert_data_diff(&holding_account, &AccountForTests::holding_account_init());
}

#[should_panic(expected = "Sender and recipient definition id mismatch")]
#[test]
fn transfer_with_different_definition_ids_should_fail() {
    let sender_holder = HolderForTests::owner();
    let recipient_holder = HolderForTests::owner_2();
    let sender = AccountForTests::holding_same_definition();
    let recipient = AccountForTests::holding_different_definition(
        &recipient_holder,
        IdForTests::pool_definition_id(),
    );
    let _post_diffs = transfer(
        vec![
            sender,
            recipient,
            AccountForTests::owner_row(&sender_holder, true),
        ],
        &sender_holder,
        &recipient_holder,
        TOKEN_PROGRAM_ID,
        10,
    );
}

#[should_panic(expected = "Insufficient balance")]
#[test]
fn transfer_with_insufficient_balance_should_fail() {
    let sender_holder = HolderForTests::owner();
    let recipient_holder = HolderForTests::owner_2();
    let sender = AccountForTests::holding_same_definition();
    let recipient = AccountForTests::holding_account2_init();
    // Attempt to transfer more than balance
    let _post_diffs = transfer(
        vec![
            sender,
            recipient,
            AccountForTests::owner_row(&sender_holder, true),
        ],
        &sender_holder,
        &recipient_holder,
        TOKEN_PROGRAM_ID,
        BalanceForTests::burn_insufficient(),
    );
}

#[should_panic(expected = "Owner authorization is missing")]
#[test]
fn transfer_without_sender_authorization_should_fail() {
    let sender_holder = HolderForTests::owner();
    let recipient_holder = HolderForTests::owner_2();
    let sender = AccountForTests::holding_same_definition();
    let recipient =
        AccountForTests::holding_account_uninit(&recipient_holder, HoldingKind::Fungible);
    let _post_diffs = transfer(
        vec![
            sender,
            recipient,
            AccountForTests::owner_row(&sender_holder, false),
        ],
        &sender_holder,
        &recipient_holder,
        TOKEN_PROGRAM_ID,
        37,
    );
}

#[test]
fn transfer_with_valid_inputs_succeeds() {
    let sender_holder = HolderForTests::owner();
    let recipient_holder = HolderForTests::owner_2();
    let sender = AccountForTests::holding_account_init();
    let recipient = AccountForTests::holding_account2_init();
    let post_diffs = transfer(
        vec![
            sender,
            recipient,
            AccountForTests::owner_row(&sender_holder, true),
        ],
        &sender_holder,
        &recipient_holder,
        TOKEN_PROGRAM_ID,
        BalanceForTests::transfer_amount(),
    );
    let [sender_post, recipient_post, owner_post] = post_diffs.try_into().unwrap();

    assert_data_diff(
        &sender_post,
        &AccountForTests::holding_account_init_post_transfer(),
    );
    assert_data_diff(
        &recipient_post,
        &AccountForTests::holding_account2_init_post_transfer(),
    );
    assert_eq!(owner_post.post_data, None);
}

#[should_panic(expected = "Invalid balance for NFT Master transfer")]
#[test]
fn transfer_with_master_nft_invalid_balance() {
    let sender_holder = HolderForTests::owner();
    let recipient_holder = HolderForTests::owner_2();
    let sender = AccountForTests::holding_account_master_nft();
    let recipient =
        AccountForTests::holding_account_uninit(&recipient_holder, HoldingKind::NftMaster);
    let _post_diffs = transfer(
        vec![
            sender,
            recipient,
            AccountForTests::owner_row(&sender_holder, true),
        ],
        &sender_holder,
        &recipient_holder,
        TOKEN_PROGRAM_ID,
        BalanceForTests::transfer_amount(),
    );
}

#[should_panic(expected = "Invalid balance in recipient account for NFT transfer")]
#[test]
fn transfer_with_master_nft_invalid_recipient_balance() {
    let sender_holder = HolderForTests::owner();
    let recipient_holder = HolderForTests::owner_2();
    let sender = AccountForTests::holding_account_master_nft();
    let recipient = AccountForTests::holding_account_with_master_nft_transferred_to();
    let _post_diffs = transfer(
        vec![
            sender,
            recipient,
            AccountForTests::owner_row(&sender_holder, true),
        ],
        &sender_holder,
        &recipient_holder,
        TOKEN_PROGRAM_ID,
        BalanceForTests::printable_copies(),
    );
}

#[test]
fn transfer_with_master_nft_success() {
    let sender_holder = HolderForTests::owner();
    let recipient_holder = HolderForTests::owner_2();
    let sender = AccountForTests::holding_account_master_nft();
    let recipient =
        AccountForTests::holding_account_uninit(&recipient_holder, HoldingKind::NftMaster);
    let post_diffs = transfer(
        vec![
            sender,
            recipient,
            AccountForTests::owner_row(&sender_holder, true),
        ],
        &sender_holder,
        &recipient_holder,
        TOKEN_PROGRAM_ID,
        BalanceForTests::printable_copies(),
    );
    let [sender_post, recipient_post, owner_post] = post_diffs.try_into().unwrap();

    assert_data_diff(
        &sender_post,
        &AccountForTests::holding_account_master_nft_post_transfer(),
    );
    assert_data_diff(
        &recipient_post,
        &AccountForTests::holding_account_with_master_nft_transferred_to(),
    );
    assert_eq!(owner_post.post_data, None);
}

#[test]
fn token_initialize_account_succeeds() {
    let sender_holder = HolderForTests::owner();
    let recipient_holder = HolderForTests::owner_2();
    let sender = AccountForTests::holding_account_init();
    let recipient = AccountForTests::holding_account2_init();
    let post_diffs = transfer(
        vec![
            sender,
            recipient,
            AccountForTests::owner_row(&sender_holder, true),
        ],
        &sender_holder,
        &recipient_holder,
        TOKEN_PROGRAM_ID,
        BalanceForTests::transfer_amount(),
    );
    let [sender_post, recipient_post, owner_post] = post_diffs.try_into().unwrap();

    assert_data_diff(
        &sender_post,
        &AccountForTests::holding_account_init_post_transfer(),
    );
    assert_data_diff(
        &recipient_post,
        &AccountForTests::holding_account2_init_post_transfer(),
    );
    assert_eq!(owner_post.post_data, None);
}

#[test]
#[should_panic(expected = "Mismatch Token Definition and Token Holding")]
fn burn_mismatch_def() {
    let holder = HolderForTests::owner();
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::holding_different_definition(
        &holder,
        IdForTests::pool_definition_id_diff(),
    );
    let _post_diffs = burn(
        vec![
            definition_account,
            holding_account,
            AccountForTests::owner_row(&holder, true),
        ],
        &holder,
        TOKEN_PROGRAM_ID,
        BalanceForTests::burn_success(),
    );
}

#[test]
#[should_panic(expected = "Owner authorization is missing")]
fn burn_missing_authorization() {
    let holder = HolderForTests::owner();
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::holding_same_definition();
    let _post_diffs = burn(
        vec![
            definition_account,
            holding_account,
            AccountForTests::owner_row(&holder, false),
        ],
        &holder,
        TOKEN_PROGRAM_ID,
        BalanceForTests::burn_success(),
    );
}

#[test]
#[should_panic(expected = "Insufficient balance to burn")]
fn burn_insufficient_balance() {
    let holder = HolderForTests::owner();
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::holding_same_definition();
    let _post_diffs = burn(
        vec![
            definition_account,
            holding_account,
            AccountForTests::owner_row(&holder, true),
        ],
        &holder,
        TOKEN_PROGRAM_ID,
        BalanceForTests::burn_insufficient(),
    );
}

#[test]
#[should_panic(expected = "Total supply underflow")]
fn burn_total_supply_underflow() {
    let holder = HolderForTests::owner();
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::holding_same_definition_large_balance();
    let _post_diffs = burn(
        vec![
            definition_account,
            holding_account,
            AccountForTests::owner_row(&holder, true),
        ],
        &holder,
        TOKEN_PROGRAM_ID,
        BalanceForTests::mint_overflow(),
    );
}

#[test]
fn burn_success() {
    let holder = HolderForTests::owner();
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::holding_same_definition();
    let post_diffs = burn(
        vec![
            definition_account,
            holding_account,
            AccountForTests::owner_row(&holder, true),
        ],
        &holder,
        TOKEN_PROGRAM_ID,
        BalanceForTests::burn_success(),
    );

    let [def_post, holding_post, owner_post] = post_diffs.try_into().unwrap();

    assert_data_diff(&def_post, &AccountForTests::definition_account_post_burn());
    assert_data_diff(&holding_post, &AccountForTests::holding_account_post_burn());
    assert_eq!(owner_post.post_data, None);
}

#[test]
#[should_panic(expected = "Holding account must be valid")]
fn mint_not_valid_holding_account() {
    let holder = HolderForTests::owner();
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account =
        AccountForTests::holding_account_with_definition_data(&holder, HoldingKind::Fungible);
    let _post_diffs = mint(
        &definition_account,
        &holding_account,
        &holder,
        TOKEN_PROGRAM_ID,
        BalanceForTests::mint_success(),
    );
}

#[test]
#[should_panic(expected = "Definition account must be valid")]
fn mint_not_valid_definition_account() {
    let holder = HolderForTests::owner();
    let definition_account = AccountForTests::definition_account_with_holding_data();
    let holding_account = AccountForTests::holding_account_uninit(&holder, HoldingKind::Fungible);
    let _post_diffs = mint(
        &definition_account,
        &holding_account,
        &holder,
        TOKEN_PROGRAM_ID,
        BalanceForTests::mint_success(),
    );
}

#[test]
#[should_panic(expected = "Definition authorization is missing")]
fn mint_missing_authorization() {
    let definition_account = AccountForTests::definition_account_without_auth();
    let holding_account = AccountForTests::holding_same_definition();
    let _post_diffs = mint(
        &definition_account,
        &holding_account,
        &HolderForTests::owner(),
        TOKEN_PROGRAM_ID,
        BalanceForTests::mint_success(),
    );
}

#[test]
#[should_panic(expected = "Mismatch Token Definition and Token Holding")]
fn mint_mismatched_token_definition() {
    let holder = HolderForTests::owner();
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account =
        AccountForTests::holding_different_definition(&holder, IdForTests::pool_definition_id());
    let _post_diffs = mint(
        &definition_account,
        &holding_account,
        &holder,
        TOKEN_PROGRAM_ID,
        BalanceForTests::mint_success(),
    );
}

#[test]
fn mint_success() {
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::holding_same_definition();
    let post_diffs = mint(
        &definition_account,
        &holding_account,
        &HolderForTests::owner(),
        TOKEN_PROGRAM_ID,
        BalanceForTests::mint_success(),
    );

    let [def_post, holding_post] = post_diffs.try_into().unwrap();

    assert_data_diff(&def_post, &AccountForTests::definition_account_mint());
    assert_data_diff(
        &holding_post,
        &AccountForTests::holding_account_same_definition_mint(),
    );
}

#[test]
fn mint_uninit_holding_success() {
    let holder = HolderForTests::owner();
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::holding_account_uninit(&holder, HoldingKind::Fungible);
    let post_diffs = mint(
        &definition_account,
        &holding_account,
        &holder,
        TOKEN_PROGRAM_ID,
        BalanceForTests::mint_success(),
    );

    let [def_post, holding_post] = post_diffs.try_into().unwrap();

    assert_data_diff(&def_post, &AccountForTests::definition_account_mint());
    assert_data_diff(&holding_post, &AccountForTests::init_mint());
}

#[test]
#[should_panic(expected = "Total supply overflow")]
fn mint_total_supply_overflow() {
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::holding_same_definition();
    let _post_diffs = mint(
        &definition_account,
        &holding_account,
        &HolderForTests::owner(),
        TOKEN_PROGRAM_ID,
        BalanceForTests::mint_overflow(),
    );
}

#[test]
#[should_panic(expected = "Balance overflow on minting")]
fn mint_holding_account_overflow() {
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::holding_account_init();
    let _post_diffs = mint(
        &definition_account,
        &holding_account,
        &HolderForTests::owner(),
        TOKEN_PROGRAM_ID,
        BalanceForTests::mint_overflow(),
    );
}

#[test]
#[should_panic(expected = "Cannot mint additional supply for Non-Fungible Tokens")]
fn mint_cannot_mint_unmintable_tokens() {
    let holder = HolderForTests::owner();
    let definition_account = AccountForTests::definition_account_with_authorization_nonfungible();
    let holding_account = AccountForTests::holding_account_master_nft_at_fungible_address();
    let _post_diffs = mint(
        &definition_account,
        &holding_account,
        &holder,
        TOKEN_PROGRAM_ID,
        BalanceForTests::mint_success(),
    );
}

#[should_panic(expected = "Definition target account must not already hold data")]
#[test]
fn call_new_definition_metadata_with_init_definition() {
    let holder = HolderForTests::owner();
    let definition_account = AccountForTests::definition_account_auth();
    let metadata_account = AccountForTests::metadata_account_uninit();
    let holding_account = AccountForTests::holding_account_uninit(&holder, HoldingKind::Fungible);
    let new_definition = NewTokenDefinition::Fungible {
        name: String::from("test"),
        total_supply: 15_u128,
    };
    let metadata = NewTokenMetadata {
        standard: MetadataStandard::Simple,
        uri: "test_uri".to_owned(),
        creators: "test_creators".to_owned(),
    };
    let _post_diffs = new_definition_with_metadata(
        &definition_account,
        &holding_account,
        &metadata_account,
        &holder,
        TOKEN_PROGRAM_ID,
        new_definition,
        metadata,
    );
}

#[should_panic(expected = "Metadata target account must not already hold data")]
#[test]
fn call_new_definition_metadata_with_init_metadata() {
    let holder = HolderForTests::owner();
    let definition_account = AccountForTests::definition_account_uninit();
    let holding_account = AccountForTests::holding_account_uninit(&holder, HoldingKind::Fungible);
    let metadata_account = AccountForTests::metadata_account_init();
    let new_definition = NewTokenDefinition::Fungible {
        name: String::from("test"),
        total_supply: 15_u128,
    };
    let metadata = NewTokenMetadata {
        standard: MetadataStandard::Simple,
        uri: "test_uri".to_owned(),
        creators: "test_creators".to_owned(),
    };
    let _post_diffs = new_definition_with_metadata(
        &definition_account,
        &holding_account,
        &metadata_account,
        &holder,
        TOKEN_PROGRAM_ID,
        new_definition,
        metadata,
    );
}

#[should_panic(expected = "Holding target account must not already hold data")]
#[test]
fn call_new_definition_metadata_with_init_holding() {
    let definition_account = AccountForTests::definition_account_uninit();
    let metadata_account = AccountForTests::metadata_account_uninit();
    let holding_account = AccountForTests::holding_account_same_definition_mint();
    let new_definition = NewTokenDefinition::Fungible {
        name: String::from("test"),
        total_supply: 15_u128,
    };
    let metadata = NewTokenMetadata {
        standard: MetadataStandard::Simple,
        uri: "test_uri".to_owned(),
        creators: "test_creators".to_owned(),
    };
    let _post_diffs = new_definition_with_metadata(
        &definition_account,
        &holding_account,
        &metadata_account,
        &HolderForTests::owner(),
        TOKEN_PROGRAM_ID,
        new_definition,
        metadata,
    );
}

#[should_panic(expected = "Owner authorization is missing")]
#[test]
fn print_nft_master_account_must_be_authorized() {
    let master_holder = HolderForTests::owner();
    let copy_holder = HolderForTests::owner_2();
    let master_account =
        AccountForTests::holding_account_uninit(&master_holder, HoldingKind::NftMaster);
    let printed_account =
        AccountForTests::holding_account_uninit(&copy_holder, HoldingKind::NftPrintedCopy);
    let _post_diffs = print_nft(
        vec![
            master_account,
            printed_account,
            AccountForTests::owner_row(&master_holder, false),
        ],
        &master_holder,
        &copy_holder,
        TOKEN_PROGRAM_ID,
    );
}

#[should_panic(expected = "Printed Account already holds a copy")]
#[test]
fn print_nft_print_account_initialized() {
    let master_holder = HolderForTests::owner();
    let copy_holder = HolderForTests::owner_2();
    let master_account = AccountForTests::holding_account_master_nft();
    let printed_account = AccountForTests::holding_account_printed_nft();
    let _post_diffs = print_nft(
        vec![
            master_account,
            printed_account,
            AccountForTests::owner_row(&master_holder, true),
        ],
        &master_holder,
        &copy_holder,
        TOKEN_PROGRAM_ID,
    );
}

#[should_panic(expected = "Invalid Token Holding data")]
#[test]
fn print_nft_master_nft_invalid_token_holding() {
    let master_holder = HolderForTests::owner();
    let copy_holder = HolderForTests::owner_2();
    let master_account = AccountForTests::holding_account_with_definition_data(
        &master_holder,
        HoldingKind::NftMaster,
    );
    let printed_account =
        AccountForTests::holding_account_uninit(&copy_holder, HoldingKind::NftPrintedCopy);
    let _post_diffs = print_nft(
        vec![
            master_account,
            printed_account,
            AccountForTests::owner_row(&master_holder, true),
        ],
        &master_holder,
        &copy_holder,
        TOKEN_PROGRAM_ID,
    );
}

#[should_panic(expected = "Invalid Token Holding provided as NFT Master Account")]
#[test]
fn print_nft_master_nft_not_nft_master_account() {
    let master_holder = HolderForTests::owner();
    let copy_holder = HolderForTests::owner_2();
    let master_account = AccountForTests::holding_account_init();
    let printed_account =
        AccountForTests::holding_account_uninit(&copy_holder, HoldingKind::NftPrintedCopy);
    let _post_diffs = print_nft(
        vec![
            master_account,
            printed_account,
            AccountForTests::owner_row(&master_holder, true),
        ],
        &master_holder,
        &copy_holder,
        TOKEN_PROGRAM_ID,
    );
}

#[should_panic(expected = "Insufficient balance to print another NFT copy")]
#[test]
fn print_nft_master_nft_insufficient_balance() {
    let master_holder = HolderForTests::owner();
    let copy_holder = HolderForTests::owner_2();
    let master_account = AccountForTests::holding_account_master_nft_insufficient_balance();
    let printed_account =
        AccountForTests::holding_account_uninit(&copy_holder, HoldingKind::NftPrintedCopy);
    let _post_diffs = print_nft(
        vec![
            master_account,
            printed_account,
            AccountForTests::owner_row(&master_holder, true),
        ],
        &master_holder,
        &copy_holder,
        TOKEN_PROGRAM_ID,
    );
}

#[test]
fn print_nft_success() {
    let master_holder = HolderForTests::owner();
    let copy_holder = HolderForTests::owner_2();
    let master_account = AccountForTests::holding_account_master_nft();
    let printed_account =
        AccountForTests::holding_account_uninit(&copy_holder, HoldingKind::NftPrintedCopy);
    let post_diffs = print_nft(
        vec![
            master_account,
            printed_account,
            AccountForTests::owner_row(&master_holder, true),
        ],
        &master_holder,
        &copy_holder,
        TOKEN_PROGRAM_ID,
    );

    let [post_master_nft, post_printed, owner_post] = post_diffs.try_into().unwrap();

    assert_data_diff(
        &post_master_nft,
        &AccountForTests::holding_account_master_nft_after_print(),
    );
    assert_data_diff(
        &post_printed,
        &AccountForTests::holding_account_printed_nft(),
    );
    assert_eq!(owner_post.post_data, None);
}

#[test]
fn initialize_account_writes_a_fresh_holding_without_authorization() {
    let holder = HolderForTests::owner();
    let target = AccountForTests::holding_account_uninit(&holder, HoldingKind::Fungible);
    assert!(!target.is_authorized);

    let post_diffs = initialize_account(
        &AccountForTests::definition_account_auth(),
        &target,
        &holder,
        TOKEN_PROGRAM_ID,
    );
    let [_, holding_post] = post_diffs.try_into().unwrap();

    assert_data_diff(
        &holding_post,
        &AccountForTests::fungible_holding(&holder, 0),
    );
}

#[test]
fn initialize_account_preserves_a_matching_funded_holding() {
    let holder = HolderForTests::owner();
    let funded = AccountForTests::fungible_holding(&holder, BalanceForTests::holding_balance());

    let post_diffs = initialize_account(
        &AccountForTests::definition_account_auth(),
        &funded,
        &holder,
        TOKEN_PROGRAM_ID,
    );
    let [_, holding_post] = post_diffs.try_into().unwrap();

    assert_eq!(holding_post.post_data, None);
    assert_eq!(holding_post.post_balance_diff, BalanceDiff::Add(0));
    assert_data_diff(&holding_post, &funded);
}

#[should_panic(expected = "Initialized holding does not match the definition")]
#[test]
fn initialize_account_rejects_a_holding_of_another_definition() {
    let holder = HolderForTests::owner();
    let target =
        AccountForTests::holding_different_definition(&holder, IdForTests::pool_definition_id());

    let _post_diffs = initialize_account(
        &AccountForTests::definition_account_auth(),
        &target,
        &holder,
        TOKEN_PROGRAM_ID,
    );
}

#[should_panic(expected = "Holding account ID does not match its derivation")]
#[test]
fn initialize_account_rejects_a_target_that_is_not_the_derived_holding() {
    let stranger =
        AccountForTests::holding_account_uninit(&HolderForTests::owner_2(), HoldingKind::Fungible);

    let _post_diffs = initialize_account(
        &AccountForTests::definition_account_auth(),
        &stranger,
        &HolderForTests::owner(),
        TOKEN_PROGRAM_ID,
    );
}
