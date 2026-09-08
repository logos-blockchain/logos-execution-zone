#![cfg(test)]
#![expect(
    clippy::shadow_unrelated,
    clippy::arithmetic_side_effects,
    reason = "We don't care about it in tests"
)]

use lee_core::{
    account::{AccountId, AccountInput, BalanceDiff, Data},
    program::AccountStateDiff,
};
use token_core::{
    MetadataStandard, NewTokenDefinition, NewTokenMetadata, TokenDefinition, TokenHolding,
};

use crate::{
    burn::burn,
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

struct AccountForTests;

impl AccountForTests {
    fn holding(account_id: AccountId, is_authorized: bool, holding: &TokenHolding) -> AccountInput {
        AccountInput::with_shard(
            account_id,
            is_authorized,
            0,
            TOKEN_PROGRAM_ID,
            Data::from(holding),
        )
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
            Data::from(definition),
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

    fn holding_different_definition() -> AccountInput {
        Self::holding(
            IdForTests::holding_id(),
            true,
            &TokenHolding::Fungible {
                definition_id: IdForTests::pool_definition_id_diff(),
                balance: BalanceForTests::holding_balance(),
            },
        )
    }

    fn holding_same_definition_with_authorization() -> AccountInput {
        Self::holding(
            IdForTests::holding_id(),
            true,
            &TokenHolding::Fungible {
                definition_id: IdForTests::pool_definition_id(),
                balance: BalanceForTests::holding_balance(),
            },
        )
    }

    fn holding_same_definition_without_authorization() -> AccountInput {
        Self::holding(
            IdForTests::holding_id(),
            false,
            &TokenHolding::Fungible {
                definition_id: IdForTests::pool_definition_id(),
                balance: BalanceForTests::holding_balance(),
            },
        )
    }

    fn holding_same_definition_without_authorization_overflow() -> AccountInput {
        Self::holding(
            IdForTests::holding_id(),
            false,
            &TokenHolding::Fungible {
                definition_id: IdForTests::pool_definition_id(),
                balance: BalanceForTests::init_supply(),
            },
        )
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
        Self::holding(
            IdForTests::holding_id(),
            false,
            &TokenHolding::Fungible {
                definition_id: IdForTests::pool_definition_id(),
                balance: BalanceForTests::holding_balance_burned(),
            },
        )
    }

    fn holding_account_uninit() -> AccountInput {
        AccountInput::with_shard(
            IdForTests::holding_id_2(),
            false,
            0,
            TOKEN_PROGRAM_ID,
            Data::empty(),
        )
    }

    fn init_mint() -> AccountInput {
        Self::holding(
            IdForTests::holding_id(),
            false,
            &TokenHolding::Fungible {
                definition_id: IdForTests::pool_definition_id(),
                balance: BalanceForTests::mint_success(),
            },
        )
    }

    fn holding_account_same_definition_mint() -> AccountInput {
        Self::holding(
            IdForTests::pool_definition_id(),
            true,
            &TokenHolding::Fungible {
                definition_id: IdForTests::pool_definition_id(),
                balance: BalanceForTests::holding_balance_mint(),
            },
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

    fn holding_same_definition_with_authorization_and_large_balance() -> AccountInput {
        Self::holding(
            IdForTests::pool_definition_id(),
            true,
            &TokenHolding::Fungible {
                definition_id: IdForTests::pool_definition_id(),
                balance: BalanceForTests::mint_overflow(),
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
            false,
            0,
            TOKEN_PROGRAM_ID,
            Data::empty(),
        )
    }

    fn holding_account_init() -> AccountInput {
        Self::holding(
            IdForTests::holding_id(),
            true,
            &TokenHolding::Fungible {
                definition_id: IdForTests::pool_definition_id(),
                balance: BalanceForTests::init_supply(),
            },
        )
    }

    fn holding_account2_init() -> AccountInput {
        Self::holding(
            IdForTests::holding_id_2(),
            true,
            &TokenHolding::Fungible {
                definition_id: IdForTests::pool_definition_id(),
                balance: BalanceForTests::init_supply(),
            },
        )
    }

    fn holding_account2_init_post_transfer() -> AccountInput {
        Self::holding(
            IdForTests::holding_id_2(),
            true,
            &TokenHolding::Fungible {
                definition_id: IdForTests::pool_definition_id(),
                balance: BalanceForTests::recipient_post_transfer(),
            },
        )
    }

    fn holding_account_init_post_transfer() -> AccountInput {
        Self::holding(
            IdForTests::holding_id(),
            true,
            &TokenHolding::Fungible {
                definition_id: IdForTests::pool_definition_id(),
                balance: BalanceForTests::sender_post_transfer(),
            },
        )
    }

    fn holding_account_master_nft() -> AccountInput {
        Self::holding(
            IdForTests::holding_id(),
            true,
            &TokenHolding::NftMaster {
                definition_id: IdForTests::pool_definition_id(),
                print_balance: BalanceForTests::printable_copies(),
            },
        )
    }

    fn holding_account_master_nft_insufficient_balance() -> AccountInput {
        Self::holding(
            IdForTests::holding_id(),
            true,
            &TokenHolding::NftMaster {
                definition_id: IdForTests::pool_definition_id(),
                print_balance: 1,
            },
        )
    }

    fn holding_account_master_nft_after_print() -> AccountInput {
        Self::holding(
            IdForTests::holding_id(),
            true,
            &TokenHolding::NftMaster {
                definition_id: IdForTests::pool_definition_id(),
                print_balance: BalanceForTests::printable_copies() - 1,
            },
        )
    }

    fn holding_account_printed_nft() -> AccountInput {
        Self::holding(
            IdForTests::holding_id(),
            false,
            &TokenHolding::NftPrintedCopy {
                definition_id: IdForTests::pool_definition_id(),
                owned: true,
            },
        )
    }

    fn holding_account_with_master_nft_transferred_to() -> AccountInput {
        Self::holding(
            IdForTests::holding_id_2(),
            true,
            &TokenHolding::NftMaster {
                definition_id: IdForTests::pool_definition_id(),
                print_balance: BalanceForTests::printable_copies(),
            },
        )
    }

    fn holding_account_master_nft_post_transfer() -> AccountInput {
        Self::holding(
            IdForTests::holding_id(),
            true,
            &TokenHolding::NftMaster {
                definition_id: IdForTests::pool_definition_id(),
                print_balance: 0,
            },
        )
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

    fn holding_id() -> AccountId {
        AccountId::new([17; 32])
    }

    fn holding_id_2() -> AccountId {
        AccountId::new([42; 32])
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
    let definition_account = AccountInput::with_shard(
        AccountId::new([1; 32]),
        true,
        0,
        TOKEN_PROGRAM_ID,
        Data::from(&TokenDefinition::Fungible {
            name: String::from("taken"),
            total_supply: 1,
            metadata_id: None,
        }),
    );
    let holding_account = AccountInput::with_shard(
        AccountId::new([2; 32]),
        true,
        0,
        TOKEN_PROGRAM_ID,
        Data::empty(),
    );
    let _post_diffs = new_fungible_definition(
        &definition_account,
        &holding_account,
        TOKEN_PROGRAM_ID,
        String::from("test"),
        10,
    );
}

#[should_panic(expected = "Holding target account must not already hold data")]
#[test]
fn new_definition_data_bearing_second_account_should_fail() {
    let definition_account = AccountInput::with_shard(
        AccountId::new([1; 32]),
        true,
        0,
        TOKEN_PROGRAM_ID,
        Data::empty(),
    );
    let holding_account = AccountInput::with_shard(
        AccountId::new([2; 32]),
        true,
        0,
        TOKEN_PROGRAM_ID,
        Data::from(&TokenHolding::Fungible {
            definition_id: AccountId::new([1; 32]),
            balance: 1,
        }),
    );
    let _post_diffs = new_fungible_definition(
        &definition_account,
        &holding_account,
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
    let mut definition_account = AccountForTests::definition_account_uninit();
    definition_account.balance = 1;
    let holding_account = AccountForTests::holding_account_uninit();

    let post_diffs = new_fungible_definition(
        &definition_account,
        &holding_account,
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
    let definition_account = AccountForTests::definition_account_uninit();
    let holding_account = AccountForTests::holding_account_uninit();

    let post_diffs = new_fungible_definition(
        &definition_account,
        &holding_account,
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
    let sender = AccountForTests::holding_same_definition_with_authorization();
    let recipient = AccountForTests::holding_different_definition();
    let _post_diffs = transfer(&sender, &recipient, TOKEN_PROGRAM_ID, 10);
}

#[should_panic(expected = "Insufficient balance")]
#[test]
fn transfer_with_insufficient_balance_should_fail() {
    let sender = AccountForTests::holding_same_definition_with_authorization();
    let recipient = AccountForTests::holding_account_same_definition_mint();
    // Attempt to transfer more than balance
    let _post_diffs = transfer(
        &sender,
        &recipient,
        TOKEN_PROGRAM_ID,
        BalanceForTests::burn_insufficient(),
    );
}

#[should_panic(expected = "Sender authorization is missing")]
#[test]
fn transfer_without_sender_authorization_should_fail() {
    let sender = AccountForTests::holding_same_definition_without_authorization();
    let recipient = AccountForTests::holding_account_uninit();
    let _post_diffs = transfer(&sender, &recipient, TOKEN_PROGRAM_ID, 37);
}

#[test]
fn transfer_with_valid_inputs_succeeds() {
    let sender = AccountForTests::holding_account_init();
    let recipient = AccountForTests::holding_account2_init();
    let post_diffs = transfer(
        &sender,
        &recipient,
        TOKEN_PROGRAM_ID,
        BalanceForTests::transfer_amount(),
    );
    let [sender_post, recipient_post] = post_diffs.try_into().unwrap();

    assert_data_diff(
        &sender_post,
        &AccountForTests::holding_account_init_post_transfer(),
    );
    assert_data_diff(
        &recipient_post,
        &AccountForTests::holding_account2_init_post_transfer(),
    );
}

#[should_panic(expected = "Invalid balance for NFT Master transfer")]
#[test]
fn transfer_with_master_nft_invalid_balance() {
    let sender = AccountForTests::holding_account_master_nft();
    let recipient = AccountForTests::holding_account_uninit();
    let _post_diffs = transfer(
        &sender,
        &recipient,
        TOKEN_PROGRAM_ID,
        BalanceForTests::transfer_amount(),
    );
}

#[should_panic(expected = "Invalid balance in recipient account for NFT transfer")]
#[test]
fn transfer_with_master_nft_invalid_recipient_balance() {
    let sender = AccountForTests::holding_account_master_nft();
    let recipient = AccountForTests::holding_account_with_master_nft_transferred_to();
    let _post_diffs = transfer(
        &sender,
        &recipient,
        TOKEN_PROGRAM_ID,
        BalanceForTests::printable_copies(),
    );
}

#[test]
fn transfer_with_master_nft_success() {
    let sender = AccountForTests::holding_account_master_nft();
    let recipient = AccountForTests::holding_account_uninit();
    let post_diffs = transfer(
        &sender,
        &recipient,
        TOKEN_PROGRAM_ID,
        BalanceForTests::printable_copies(),
    );
    let [sender_post, recipient_post] = post_diffs.try_into().unwrap();

    assert_data_diff(
        &sender_post,
        &AccountForTests::holding_account_master_nft_post_transfer(),
    );
    assert_data_diff(
        &recipient_post,
        &AccountForTests::holding_account_with_master_nft_transferred_to(),
    );
}

#[test]
fn token_initialize_account_succeeds() {
    let sender = AccountForTests::holding_account_init();
    let recipient = AccountForTests::holding_account2_init();
    let post_diffs = transfer(
        &sender,
        &recipient,
        TOKEN_PROGRAM_ID,
        BalanceForTests::transfer_amount(),
    );
    let [sender_post, recipient_post] = post_diffs.try_into().unwrap();

    assert_data_diff(
        &sender_post,
        &AccountForTests::holding_account_init_post_transfer(),
    );
    assert_data_diff(
        &recipient_post,
        &AccountForTests::holding_account2_init_post_transfer(),
    );
}

#[test]
#[should_panic(expected = "Mismatch Token Definition and Token Holding")]
fn burn_mismatch_def() {
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::holding_different_definition();
    let _post_diffs = burn(
        &definition_account,
        &holding_account,
        TOKEN_PROGRAM_ID,
        BalanceForTests::burn_success(),
    );
}

#[test]
#[should_panic(expected = "Authorization is missing")]
fn burn_missing_authorization() {
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::holding_same_definition_without_authorization();
    let _post_diffs = burn(
        &definition_account,
        &holding_account,
        TOKEN_PROGRAM_ID,
        BalanceForTests::burn_success(),
    );
}

#[test]
#[should_panic(expected = "Insufficient balance to burn")]
fn burn_insufficient_balance() {
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::holding_same_definition_with_authorization();
    let _post_diffs = burn(
        &definition_account,
        &holding_account,
        TOKEN_PROGRAM_ID,
        BalanceForTests::burn_insufficient(),
    );
}

#[test]
#[should_panic(expected = "Total supply underflow")]
fn burn_total_supply_underflow() {
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account =
        AccountForTests::holding_same_definition_with_authorization_and_large_balance();
    let _post_diffs = burn(
        &definition_account,
        &holding_account,
        TOKEN_PROGRAM_ID,
        BalanceForTests::mint_overflow(),
    );
}

#[test]
fn burn_success() {
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::holding_same_definition_with_authorization();
    let post_diffs = burn(
        &definition_account,
        &holding_account,
        TOKEN_PROGRAM_ID,
        BalanceForTests::burn_success(),
    );

    let [def_post, holding_post] = post_diffs.try_into().unwrap();

    assert_data_diff(&def_post, &AccountForTests::definition_account_post_burn());
    assert_data_diff(&holding_post, &AccountForTests::holding_account_post_burn());
}

#[test]
#[should_panic(expected = "Holding account must be valid")]
fn mint_not_valid_holding_account() {
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::definition_account_without_auth();
    let _post_diffs = mint(
        &definition_account,
        &holding_account,
        TOKEN_PROGRAM_ID,
        BalanceForTests::mint_success(),
    );
}

#[test]
#[should_panic(expected = "Definition account must be valid")]
fn mint_not_valid_definition_account() {
    let definition_account = AccountForTests::holding_same_definition_with_authorization();
    let holding_account = AccountForTests::holding_same_definition_without_authorization();
    let _post_diffs = mint(
        &definition_account,
        &holding_account,
        TOKEN_PROGRAM_ID,
        BalanceForTests::mint_success(),
    );
}

#[test]
#[should_panic(expected = "Definition authorization is missing")]
fn mint_missing_authorization() {
    let definition_account = AccountForTests::definition_account_without_auth();
    let holding_account = AccountForTests::holding_same_definition_without_authorization();
    let _post_diffs = mint(
        &definition_account,
        &holding_account,
        TOKEN_PROGRAM_ID,
        BalanceForTests::mint_success(),
    );
}

#[test]
#[should_panic(expected = "Mismatch Token Definition and Token Holding")]
fn mint_mismatched_token_definition() {
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::holding_different_definition();
    let _post_diffs = mint(
        &definition_account,
        &holding_account,
        TOKEN_PROGRAM_ID,
        BalanceForTests::mint_success(),
    );
}

#[test]
fn mint_success() {
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::holding_same_definition_without_authorization();
    let post_diffs = mint(
        &definition_account,
        &holding_account,
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
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::holding_account_uninit();
    let post_diffs = mint(
        &definition_account,
        &holding_account,
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
    let holding_account = AccountForTests::holding_same_definition_without_authorization();
    let _post_diffs = mint(
        &definition_account,
        &holding_account,
        TOKEN_PROGRAM_ID,
        BalanceForTests::mint_overflow(),
    );
}

#[test]
#[should_panic(expected = "Balance overflow on minting")]
fn mint_holding_account_overflow() {
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::holding_same_definition_without_authorization_overflow();
    let _post_diffs = mint(
        &definition_account,
        &holding_account,
        TOKEN_PROGRAM_ID,
        BalanceForTests::mint_overflow(),
    );
}

#[test]
#[should_panic(expected = "Cannot mint additional supply for Non-Fungible Tokens")]
fn mint_cannot_mint_unmintable_tokens() {
    let definition_account = AccountForTests::definition_account_with_authorization_nonfungible();
    let holding_account = AccountForTests::holding_account_master_nft();
    let _post_diffs = mint(
        &definition_account,
        &holding_account,
        TOKEN_PROGRAM_ID,
        BalanceForTests::mint_success(),
    );
}

#[should_panic(expected = "Definition target account must not already hold data")]
#[test]
fn call_new_definition_metadata_with_init_definition() {
    let definition_account = AccountForTests::definition_account_auth();
    let metadata_account = AccountInput::with_shard(
        AccountId::new([2; 32]),
        true,
        0,
        TOKEN_PROGRAM_ID,
        Data::empty(),
    );
    let holding_account = AccountInput::with_shard(
        AccountId::new([3; 32]),
        true,
        0,
        TOKEN_PROGRAM_ID,
        Data::empty(),
    );
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
        &metadata_account,
        &holding_account,
        TOKEN_PROGRAM_ID,
        new_definition,
        metadata,
    );
}

#[should_panic(expected = "Metadata target account must not already hold data")]
#[test]
fn call_new_definition_metadata_with_init_metadata() {
    let definition_account = AccountInput::with_shard(
        AccountId::new([1; 32]),
        true,
        0,
        TOKEN_PROGRAM_ID,
        Data::empty(),
    );
    let holding_account = AccountInput::with_shard(
        AccountId::new([3; 32]),
        true,
        0,
        TOKEN_PROGRAM_ID,
        Data::empty(),
    );
    let metadata_account = AccountForTests::holding_account_same_definition_mint();
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
        TOKEN_PROGRAM_ID,
        new_definition,
        metadata,
    );
}

#[should_panic(expected = "Holding target account must not already hold data")]
#[test]
fn call_new_definition_metadata_with_init_holding() {
    let definition_account = AccountInput::with_shard(
        AccountId::new([1; 32]),
        true,
        0,
        TOKEN_PROGRAM_ID,
        Data::empty(),
    );
    let metadata_account = AccountInput::with_shard(
        AccountId::new([2; 32]),
        true,
        0,
        TOKEN_PROGRAM_ID,
        Data::empty(),
    );
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
        TOKEN_PROGRAM_ID,
        new_definition,
        metadata,
    );
}

#[should_panic(expected = "Master NFT Account must be authorized")]
#[test]
fn print_nft_master_account_must_be_authorized() {
    let master_account = AccountForTests::holding_account_uninit();
    let printed_account = AccountForTests::holding_account_uninit();
    let _post_diffs = print_nft(&master_account, &printed_account, TOKEN_PROGRAM_ID);
}

#[should_panic(expected = "Printed Account must not already hold data")]
#[test]
fn print_nft_print_account_initialized() {
    let master_account = AccountForTests::holding_account_master_nft();
    let printed_account = AccountForTests::holding_account_init();
    let _post_diffs = print_nft(&master_account, &printed_account, TOKEN_PROGRAM_ID);
}

#[should_panic(expected = "Invalid Token Holding data")]
#[test]
fn print_nft_master_nft_invalid_token_holding() {
    let master_account = AccountForTests::definition_account_auth();
    let printed_account = AccountForTests::holding_account_uninit();
    let _post_diffs = print_nft(&master_account, &printed_account, TOKEN_PROGRAM_ID);
}

#[should_panic(expected = "Invalid Token Holding provided as NFT Master Account")]
#[test]
fn print_nft_master_nft_not_nft_master_account() {
    let master_account = AccountForTests::holding_account_init();
    let printed_account = AccountForTests::holding_account_uninit();
    let _post_diffs = print_nft(&master_account, &printed_account, TOKEN_PROGRAM_ID);
}

#[should_panic(expected = "Insufficient balance to print another NFT copy")]
#[test]
fn print_nft_master_nft_insufficient_balance() {
    let master_account = AccountForTests::holding_account_master_nft_insufficient_balance();
    let printed_account = AccountForTests::holding_account_uninit();
    let _post_diffs = print_nft(&master_account, &printed_account, TOKEN_PROGRAM_ID);
}

#[test]
fn print_nft_success() {
    let master_account = AccountForTests::holding_account_master_nft();
    let printed_account = AccountForTests::holding_account_uninit();
    let post_diffs = print_nft(&master_account, &printed_account, TOKEN_PROGRAM_ID);

    let [post_master_nft, post_printed] = post_diffs.try_into().unwrap();

    assert_data_diff(
        &post_master_nft,
        &AccountForTests::holding_account_master_nft_after_print(),
    );
    assert_data_diff(
        &post_printed,
        &AccountForTests::holding_account_printed_nft(),
    );
}
