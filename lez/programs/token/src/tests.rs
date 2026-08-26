#![cfg(test)]
#![expect(
    clippy::shadow_unrelated,
    clippy::arithmetic_side_effects,
    reason = "We don't care about it in tests"
)]

use lee_core::{
    account::{AccountId, Data, Input, Slot},
    program::ProgramId,
};
use token_core::{
    MetadataStandard, NewTokenDefinition, NewTokenMetadata, TokenDefinition, TokenHolding,
};

use crate::{
    burn::burn,
    close::close_holding,
    initialize::initialize_account,
    mint::mint,
    new_definition::{new_definition_with_metadata, new_fungible_definition},
    print_nft::print_nft,
    transfer::transfer,
};

// TODO: Move tests to a proper modules like burn, mint, transfer, etc, so that they are more
// unit-test.

const TOKEN_PROGRAM_ID: ProgramId = [5; 8];

struct BalanceForTests;
struct IdForTests;

struct AccountForTests;

impl AccountForTests {
    fn definition_account_auth() -> Input {
        Input {
            slot: named(token_account(Data::from(&TokenDefinition::Fungible {
                name: String::from("test"),
                total_supply: BalanceForTests::init_supply(),
                metadata_id: None,
            }))),
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn definition_account_without_auth() -> Input {
        Input {
            slot: named(token_account(Data::from(&TokenDefinition::Fungible {
                name: String::from("test"),
                total_supply: BalanceForTests::init_supply(),
                metadata_id: None,
            }))),
            is_authorized: false,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn holding_different_definition() -> Input {
        Input {
            slot: named(token_account(Data::from(&TokenHolding::Fungible {
                definition_id: IdForTests::pool_definition_id_diff(),
                balance: BalanceForTests::holding_balance(),
            }))),
            is_authorized: true,
            account_id: IdForTests::holding_id_2(),
        }
    }

    fn holding_same_definition_with_authorization() -> Input {
        Input {
            slot: named(token_account(Data::from(&TokenHolding::Fungible {
                definition_id: IdForTests::pool_definition_id(),
                balance: BalanceForTests::holding_balance(),
            }))),
            is_authorized: true,
            account_id: IdForTests::holding_id(),
        }
    }

    fn holding_same_definition_without_authorization() -> Input {
        Input {
            slot: named(token_account(Data::from(&TokenHolding::Fungible {
                definition_id: IdForTests::pool_definition_id(),
                balance: BalanceForTests::holding_balance(),
            }))),
            is_authorized: false,
            account_id: IdForTests::holding_id(),
        }
    }

    fn holding_same_definition_without_authorization_overflow() -> Input {
        Input {
            slot: named(token_account(Data::from(&TokenHolding::Fungible {
                definition_id: IdForTests::pool_definition_id(),
                balance: BalanceForTests::init_supply(),
            }))),
            is_authorized: false,
            account_id: IdForTests::holding_id(),
        }
    }

    fn definition_account_post_burn() -> Slot {
        token_account(Data::from(&TokenDefinition::Fungible {
            name: String::from("test"),
            total_supply: BalanceForTests::init_supply_burned(),
            metadata_id: None,
        }))
    }

    fn holding_account_post_burn() -> Slot {
        token_account(Data::from(&TokenHolding::Fungible {
            definition_id: IdForTests::pool_definition_id(),
            balance: BalanceForTests::holding_balance_burned(),
        }))
    }

    fn holding_account_uninit() -> Input {
        Input {
            slot: named(Slot::default()),
            is_authorized: false,
            account_id: IdForTests::holding_id_2(),
        }
    }

    fn init_mint() -> Slot {
        token_account(Data::from(&TokenHolding::Fungible {
            definition_id: IdForTests::pool_definition_id(),
            balance: BalanceForTests::mint_success(),
        }))
    }

    fn holding_account_same_definition_mint() -> Input {
        Input {
            slot: named(token_account(Data::from(&TokenHolding::Fungible {
                definition_id: IdForTests::pool_definition_id(),
                balance: BalanceForTests::holding_balance_mint(),
            }))),
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn definition_account_mint() -> Slot {
        token_account(Data::from(&TokenDefinition::Fungible {
            name: String::from("test"),
            total_supply: BalanceForTests::init_supply_mint(),
            metadata_id: None,
        }))
    }

    fn holding_same_definition_with_authorization_and_large_balance() -> Input {
        Input {
            slot: named(token_account(Data::from(&TokenHolding::Fungible {
                definition_id: IdForTests::pool_definition_id(),
                balance: BalanceForTests::mint_overflow(),
            }))),
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn definition_account_with_authorization_nonfungible() -> Input {
        Input {
            slot: named(token_account(Data::from(&TokenDefinition::NonFungible {
                name: String::from("test"),
                printable_supply: BalanceForTests::printable_copies(),
                metadata_id: AccountId::new([0; 32]),
            }))),
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn definition_account_uninit() -> Input {
        Input {
            slot: named(Slot::default()),
            is_authorized: false,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn holding_account_init() -> Input {
        Input {
            slot: named(token_account(Data::from(&TokenHolding::Fungible {
                definition_id: IdForTests::pool_definition_id(),
                balance: BalanceForTests::init_supply(),
            }))),
            is_authorized: true,
            account_id: IdForTests::holding_id(),
        }
    }

    fn definition_account_new() -> Slot {
        token_account(Data::from(&TokenDefinition::Fungible {
            name: String::from("test"),
            total_supply: BalanceForTests::init_supply(),
            metadata_id: None,
        }))
    }

    fn holding_account_new() -> Slot {
        token_account(Data::from(&TokenHolding::Fungible {
            definition_id: IdForTests::pool_definition_id(),
            balance: BalanceForTests::init_supply(),
        }))
    }

    fn holding_account_zeroized() -> Slot {
        token_account(Data::from(&TokenHolding::Fungible {
            definition_id: IdForTests::pool_definition_id(),
            balance: 0,
        }))
    }

    fn holding_account2_init() -> Input {
        Input {
            slot: named(token_account(Data::from(&TokenHolding::Fungible {
                definition_id: IdForTests::pool_definition_id(),
                balance: BalanceForTests::init_supply(),
            }))),
            is_authorized: true,
            account_id: IdForTests::holding_id_2(),
        }
    }

    fn holding_account2_init_post_transfer() -> Slot {
        token_account(Data::from(&TokenHolding::Fungible {
            definition_id: IdForTests::pool_definition_id(),
            balance: BalanceForTests::recipient_post_transfer(),
        }))
    }

    fn holding_account_init_post_transfer() -> Slot {
        token_account(Data::from(&TokenHolding::Fungible {
            definition_id: IdForTests::pool_definition_id(),
            balance: BalanceForTests::sender_post_transfer(),
        }))
    }

    fn holding_account_master_nft() -> Input {
        Input {
            slot: named(token_account(Data::from(&TokenHolding::NftMaster {
                definition_id: IdForTests::pool_definition_id(),
                print_balance: BalanceForTests::printable_copies(),
            }))),
            is_authorized: true,
            account_id: IdForTests::holding_id(),
        }
    }

    fn holding_account_master_nft_insufficient_balance() -> Input {
        Input {
            slot: named(token_account(Data::from(&TokenHolding::NftMaster {
                definition_id: IdForTests::pool_definition_id(),
                print_balance: 1,
            }))),
            is_authorized: true,
            account_id: IdForTests::holding_id(),
        }
    }

    fn holding_account_master_nft_after_print() -> Slot {
        token_account(Data::from(&TokenHolding::NftMaster {
            definition_id: IdForTests::pool_definition_id(),
            print_balance: BalanceForTests::printable_copies() - 1,
        }))
    }

    fn holding_account_printed_nft() -> Slot {
        token_account(Data::from(&TokenHolding::NftPrintedCopy {
            definition_id: IdForTests::pool_definition_id(),
            owned: true,
        }))
    }

    fn holding_account_with_master_nft_transferred_to() -> Input {
        Input {
            slot: named(token_account(Data::from(&TokenHolding::NftMaster {
                definition_id: IdForTests::pool_definition_id(),
                print_balance: BalanceForTests::printable_copies(),
            }))),
            is_authorized: true,
            account_id: IdForTests::holding_id_2(),
        }
    }

    fn holding_account_master_nft_post_transfer() -> Slot {
        token_account(Data::from(&TokenHolding::NftMaster {
            definition_id: IdForTests::pool_definition_id(),
            print_balance: 0,
        }))
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

fn token_account(data: Data) -> Slot {
    Slot { balance: 0, data }
}

/// The slot fixture, named as this program's namespace, for an `Input` position.
#[expect(
    clippy::unnecessary_wraps,
    reason = "the wrap is the point: this fills `Input::slot`"
)]
fn named(slot: Slot) -> Option<(AccountId, Slot)> {
    Some((TOKEN_PROGRAM_ID.into(), slot))
}

#[should_panic(expected = "Definition target account must be uninitialized")]
#[test]
fn new_definition_initialized_first_account_should_fail() {
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = Input {
        slot: named(Slot::default()),
        is_authorized: true,
        account_id: AccountId::new([2; 32]),
    };
    let _post_states = new_fungible_definition(
        definition_account,
        holding_account,
        String::from("test"),
        10,
        TOKEN_PROGRAM_ID,
    );
}

#[should_panic(expected = "Holding target account must be uninitialized")]
#[test]
fn new_definition_initialized_second_account_should_fail() {
    let definition_account = Input {
        slot: named(Slot::default()),
        is_authorized: true,
        account_id: AccountId::new([1; 32]),
    };
    let holding_account = AccountForTests::holding_account_init();
    let _post_states = new_fungible_definition(
        definition_account,
        holding_account,
        String::from("test"),
        10,
        TOKEN_PROGRAM_ID,
    );
}

#[test]
fn new_definition_with_valid_inputs_succeeds() {
    let definition_account = AccountForTests::definition_account_uninit();
    let holding_account = AccountForTests::holding_account_uninit();

    let post_states = new_fungible_definition(
        definition_account,
        holding_account,
        String::from("test"),
        BalanceForTests::init_supply(),
        TOKEN_PROGRAM_ID,
    );

    let [definition_account, holding_account] = <[_; 2]>::try_from(post_states).unwrap();
    assert_eq!(
        definition_account,
        Some(AccountForTests::definition_account_new())
    );
    assert_eq!(
        holding_account,
        Some(AccountForTests::holding_account_new())
    );
}

#[should_panic(expected = "Sender and recipient definition id mismatch")]
#[test]
fn transfer_with_different_definition_ids_should_fail() {
    let sender = AccountForTests::holding_same_definition_with_authorization();
    let recipient = AccountForTests::holding_different_definition();
    let _post_states = transfer(sender, recipient, 10, TOKEN_PROGRAM_ID);
}

#[should_panic(expected = "Sender authorization is missing")]
#[test]
fn transfer_without_sender_authorization_should_fail() {
    let sender = AccountForTests::holding_same_definition_without_authorization();
    let recipient = AccountForTests::holding_account_uninit();
    let _post_states = transfer(sender, recipient, 37, TOKEN_PROGRAM_ID);
}

#[should_panic(expected = "Insufficient balance")]
#[test]
fn transfer_with_insufficient_balance_should_fail() {
    let sender = AccountForTests::holding_same_definition_with_authorization();
    let recipient = AccountForTests::holding_account_same_definition_mint();
    // Attempt to transfer more than balance
    let _post_states = transfer(
        sender,
        recipient,
        BalanceForTests::burn_insufficient(),
        TOKEN_PROGRAM_ID,
    );
}

#[test]
fn transfer_with_valid_inputs_succeeds() {
    let sender = AccountForTests::holding_account_init();
    let recipient = AccountForTests::holding_account2_init();
    let post_states = transfer(
        sender,
        recipient,
        BalanceForTests::transfer_amount(),
        TOKEN_PROGRAM_ID,
    );
    let [sender_post, recipient_post] = <[_; 2]>::try_from(post_states).unwrap();

    assert_eq!(
        sender_post,
        Some(AccountForTests::holding_account_init_post_transfer())
    );
    assert_eq!(
        recipient_post,
        Some(AccountForTests::holding_account2_init_post_transfer())
    );
}

#[should_panic(expected = "Insufficient balance")]
#[test]
fn transfer_to_self_beyond_balance_should_fail() {
    let sender = AccountForTests::holding_same_definition_with_authorization();
    let recipient = AccountForTests::holding_same_definition_with_authorization();
    let _post_states = transfer(
        sender,
        recipient,
        BalanceForTests::burn_insufficient(),
        TOKEN_PROGRAM_ID,
    );
}

#[should_panic(expected = "Invalid balance for NFT Master transfer")]
#[test]
fn transfer_with_master_nft_invalid_balance() {
    let sender = AccountForTests::holding_account_master_nft();
    let recipient = AccountForTests::holding_account_uninit();
    let _post_states = transfer(
        sender,
        recipient,
        BalanceForTests::transfer_amount(),
        TOKEN_PROGRAM_ID,
    );
}

#[should_panic(expected = "Invalid balance in recipient account for NFT transfer")]
#[test]
fn transfer_with_master_nft_invalid_recipient_balance() {
    let sender = AccountForTests::holding_account_master_nft();
    let recipient = AccountForTests::holding_account_with_master_nft_transferred_to();
    let _post_states = transfer(
        sender,
        recipient,
        BalanceForTests::printable_copies(),
        TOKEN_PROGRAM_ID,
    );
}

#[should_panic(expected = "Mismatched token holding types for transfer")]
#[test]
fn transfer_between_mismatched_holding_types_should_fail() {
    let sender = AccountForTests::holding_account_master_nft();
    let recipient = Input {
        slot: named(token_account(Data::from(&TokenHolding::NftPrintedCopy {
            definition_id: IdForTests::pool_definition_id(),
            owned: false,
        }))),
        is_authorized: true,
        account_id: IdForTests::holding_id_2(),
    };
    let _post_states = transfer(
        sender,
        recipient,
        BalanceForTests::printable_copies(),
        TOKEN_PROGRAM_ID,
    );
}

#[test]
fn transfer_with_master_nft_success() {
    let sender = AccountForTests::holding_account_master_nft();
    let recipient = AccountForTests::holding_account_uninit();
    let post_states = transfer(
        sender,
        recipient,
        BalanceForTests::printable_copies(),
        TOKEN_PROGRAM_ID,
    );
    let [sender_post, recipient_post] = <[_; 2]>::try_from(post_states).unwrap();

    assert_eq!(
        sender_post,
        Some(AccountForTests::holding_account_master_nft_post_transfer())
    );
    assert_eq!(
        recipient_post,
        AccountForTests::holding_account_with_master_nft_transferred_to().unchanged()
    );
}

#[test]
fn token_initialize_account_succeeds() {
    let definition_account = AccountForTests::definition_account_auth();
    let account_to_initialize = AccountForTests::holding_account_uninit();
    let post_states =
        initialize_account(&definition_account, account_to_initialize, TOKEN_PROGRAM_ID);
    let [definition_post, initialized_post] = <[_; 2]>::try_from(post_states).unwrap();

    assert_eq!(
        definition_post,
        AccountForTests::definition_account_auth().unchanged()
    );
    assert_eq!(
        initialized_post,
        Some(AccountForTests::holding_account_zeroized())
    );
}

#[should_panic(expected = "Only Uninitialized accounts can be initialized")]
#[test]
fn token_initialize_initialized_account_should_fail() {
    let definition_account = AccountForTests::definition_account_auth();
    let account_to_initialize = AccountForTests::holding_account_init();
    let _post_states =
        initialize_account(&definition_account, account_to_initialize, TOKEN_PROGRAM_ID);
}

#[test]
#[should_panic(expected = "Mismatch Token Definition and Token Holding")]
fn burn_mismatch_def() {
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::holding_different_definition();
    let _post_states = burn(
        definition_account,
        holding_account,
        BalanceForTests::burn_success(),
        TOKEN_PROGRAM_ID,
    );
}

#[test]
#[should_panic(expected = "Authorization is missing")]
fn burn_missing_authorization() {
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::holding_same_definition_without_authorization();
    let _post_states = burn(
        definition_account,
        holding_account,
        BalanceForTests::burn_success(),
        TOKEN_PROGRAM_ID,
    );
}

#[test]
#[should_panic(expected = "Insufficient balance to burn")]
fn burn_insufficient_balance() {
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::holding_same_definition_with_authorization();
    let _post_states = burn(
        definition_account,
        holding_account,
        BalanceForTests::burn_insufficient(),
        TOKEN_PROGRAM_ID,
    );
}

#[test]
#[should_panic(expected = "Total supply underflow")]
fn burn_total_supply_underflow() {
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account =
        AccountForTests::holding_same_definition_with_authorization_and_large_balance();
    let _post_states = burn(
        definition_account,
        holding_account,
        BalanceForTests::mint_overflow(),
        TOKEN_PROGRAM_ID,
    );
}

#[test]
fn burn_success() {
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::holding_same_definition_with_authorization();
    let post_states = burn(
        definition_account,
        holding_account,
        BalanceForTests::burn_success(),
        TOKEN_PROGRAM_ID,
    );

    let [def_post, holding_post] = <[_; 2]>::try_from(post_states).unwrap();

    assert_eq!(
        def_post,
        Some(AccountForTests::definition_account_post_burn())
    );
    assert_eq!(
        holding_post,
        Some(AccountForTests::holding_account_post_burn())
    );
}

#[test]
#[should_panic(expected = "Holding account must be valid")]
fn mint_not_valid_holding_account() {
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::definition_account_without_auth();
    let _post_states = mint(
        definition_account,
        holding_account,
        BalanceForTests::mint_success(),
        TOKEN_PROGRAM_ID,
    );
}

#[test]
#[should_panic(expected = "Definition account must be valid")]
fn mint_not_valid_definition_account() {
    let definition_account = AccountForTests::holding_same_definition_with_authorization();
    let holding_account = AccountForTests::holding_same_definition_without_authorization();
    let _post_states = mint(
        definition_account,
        holding_account,
        BalanceForTests::mint_success(),
        TOKEN_PROGRAM_ID,
    );
}

#[test]
#[should_panic(expected = "Definition authorization is missing")]
fn mint_missing_authorization() {
    let definition_account = AccountForTests::definition_account_without_auth();
    let holding_account = AccountForTests::holding_same_definition_without_authorization();
    let _post_states = mint(
        definition_account,
        holding_account,
        BalanceForTests::mint_success(),
        TOKEN_PROGRAM_ID,
    );
}

#[test]
#[should_panic(expected = "Mismatch Token Definition and Token Holding")]
fn mint_mismatched_token_definition() {
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::holding_different_definition();
    let _post_states = mint(
        definition_account,
        holding_account,
        BalanceForTests::mint_success(),
        TOKEN_PROGRAM_ID,
    );
}

#[test]
fn mint_success() {
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::holding_same_definition_without_authorization();
    let post_states = mint(
        definition_account,
        holding_account,
        BalanceForTests::mint_success(),
        TOKEN_PROGRAM_ID,
    );

    let [def_post, holding_post] = <[_; 2]>::try_from(post_states).unwrap();

    assert_eq!(def_post, Some(AccountForTests::definition_account_mint()));
    assert_eq!(
        holding_post,
        AccountForTests::holding_account_same_definition_mint().unchanged()
    );
}

#[test]
fn mint_uninit_holding_success() {
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::holding_account_uninit();
    let post_states = mint(
        definition_account,
        holding_account,
        BalanceForTests::mint_success(),
        TOKEN_PROGRAM_ID,
    );

    let [def_post, holding_post] = <[_; 2]>::try_from(post_states).unwrap();

    assert_eq!(def_post, Some(AccountForTests::definition_account_mint()));
    assert_eq!(holding_post, Some(AccountForTests::init_mint()));
}

#[test]
#[should_panic(expected = "Total supply overflow")]
fn mint_total_supply_overflow() {
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::holding_same_definition_without_authorization();
    let _post_states = mint(
        definition_account,
        holding_account,
        BalanceForTests::mint_overflow(),
        TOKEN_PROGRAM_ID,
    );
}

#[test]
#[should_panic(expected = "Balance overflow on minting")]
fn mint_holding_account_overflow() {
    let definition_account = AccountForTests::definition_account_auth();
    let holding_account = AccountForTests::holding_same_definition_without_authorization_overflow();
    let _post_states = mint(
        definition_account,
        holding_account,
        BalanceForTests::mint_overflow(),
        TOKEN_PROGRAM_ID,
    );
}

#[test]
#[should_panic(expected = "Cannot mint additional supply for Non-Fungible Tokens")]
fn mint_cannot_mint_unmintable_tokens() {
    let definition_account = AccountForTests::definition_account_with_authorization_nonfungible();
    let holding_account = AccountForTests::holding_account_master_nft();
    let _post_states = mint(
        definition_account,
        holding_account,
        BalanceForTests::mint_success(),
        TOKEN_PROGRAM_ID,
    );
}

#[should_panic(expected = "Definition target account must be uninitialized")]
#[test]
fn call_new_definition_metadata_with_init_definition() {
    let definition_account = AccountForTests::definition_account_auth();
    let metadata_account = Input {
        slot: named(Slot::default()),
        is_authorized: true,
        account_id: AccountId::new([2; 32]),
    };
    let holding_account = Input {
        slot: named(Slot::default()),
        is_authorized: true,
        account_id: AccountId::new([3; 32]),
    };
    let new_definition = NewTokenDefinition::Fungible {
        name: String::from("test"),
        total_supply: 15_u128,
    };
    let metadata = NewTokenMetadata {
        standard: MetadataStandard::Simple,
        uri: "test_uri".to_owned(),
        creators: "test_creators".to_owned(),
    };
    let _post_states = new_definition_with_metadata(
        definition_account,
        metadata_account,
        holding_account,
        new_definition,
        metadata,
        TOKEN_PROGRAM_ID,
    );
}

#[should_panic(expected = "Metadata target account must be uninitialized")]
#[test]
fn call_new_definition_metadata_with_init_metadata() {
    let definition_account = Input {
        slot: named(Slot::default()),
        is_authorized: true,
        account_id: AccountId::new([1; 32]),
    };
    let holding_account = Input {
        slot: named(Slot::default()),
        is_authorized: true,
        account_id: AccountId::new([3; 32]),
    };
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
    let _post_states = new_definition_with_metadata(
        definition_account,
        holding_account,
        metadata_account,
        new_definition,
        metadata,
        TOKEN_PROGRAM_ID,
    );
}

#[should_panic(expected = "Holding target account must be uninitialized")]
#[test]
fn call_new_definition_metadata_with_init_holding() {
    let definition_account = Input {
        slot: named(Slot::default()),
        is_authorized: true,
        account_id: AccountId::new([1; 32]),
    };
    let metadata_account = Input {
        slot: named(Slot::default()),
        is_authorized: true,
        account_id: AccountId::new([2; 32]),
    };
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
    let _post_states = new_definition_with_metadata(
        definition_account,
        holding_account,
        metadata_account,
        new_definition,
        metadata,
        TOKEN_PROGRAM_ID,
    );
}

#[should_panic(expected = "Master NFT Account must be authorized")]
#[test]
fn print_nft_master_account_must_be_authorized() {
    let master_account = AccountForTests::holding_account_uninit();
    let printed_account = AccountForTests::holding_account_uninit();
    let _post_states = print_nft(master_account, printed_account, TOKEN_PROGRAM_ID);
}

#[should_panic(expected = "Printed Account must be uninitialized")]
#[test]
fn print_nft_print_account_initialized() {
    let master_account = AccountForTests::holding_account_master_nft();
    let printed_account = AccountForTests::holding_account_init();
    let _post_states = print_nft(master_account, printed_account, TOKEN_PROGRAM_ID);
}

#[should_panic(expected = "Invalid Token Holding data")]
#[test]
fn print_nft_master_nft_invalid_token_holding() {
    let master_account = AccountForTests::definition_account_auth();
    let printed_account = AccountForTests::holding_account_uninit();
    let _post_states = print_nft(master_account, printed_account, TOKEN_PROGRAM_ID);
}

#[should_panic(expected = "Invalid Token Holding provided as NFT Master Account")]
#[test]
fn print_nft_master_nft_not_nft_master_account() {
    let master_account = AccountForTests::holding_account_init();
    let printed_account = AccountForTests::holding_account_uninit();
    let _post_states = print_nft(master_account, printed_account, TOKEN_PROGRAM_ID);
}

#[should_panic(expected = "Insufficient balance to print another NFT copy")]
#[test]
fn print_nft_master_nft_insufficient_balance() {
    let master_account = AccountForTests::holding_account_master_nft_insufficient_balance();
    let printed_account = AccountForTests::holding_account_uninit();
    let _post_states = print_nft(master_account, printed_account, TOKEN_PROGRAM_ID);
}

#[test]
fn print_nft_success() {
    let master_account = AccountForTests::holding_account_master_nft();
    let printed_account = AccountForTests::holding_account_uninit();
    let post_states = print_nft(master_account, printed_account, TOKEN_PROGRAM_ID);

    let [post_master_nft, post_printed] = <[_; 2]>::try_from(post_states).unwrap();

    assert_eq!(
        post_master_nft,
        Some(AccountForTests::holding_account_master_nft_after_print())
    );
    assert_eq!(
        post_printed,
        Some(AccountForTests::holding_account_printed_nft())
    );
}

/// An empty holding is closeable by its holder, and the slot goes with it so the
/// address reads as untouched again.
#[test]
fn close_holding_success() {
    let holding = Input {
        slot: named(token_account(Data::from(&TokenHolding::Fungible {
            definition_id: IdForTests::pool_definition_id(),
            balance: 0,
        }))),
        is_authorized: true,
        account_id: IdForTests::holding_id_2(),
    };

    let [post] = <[_; 1]>::try_from(close_holding(holding, TOKEN_PROGRAM_ID)).unwrap();

    assert_eq!(post, Some(Slot::default()));
}

/// The squat this exists for: an address a stranger pinned to another definition is
/// cleared, then initializes against the definition its holder wanted.
#[test]
fn a_holding_pinned_to_a_foreign_definition_can_be_cleared_and_reused() {
    let squatted = Input {
        slot: named(token_account(Data::from(&TokenHolding::Fungible {
            definition_id: AccountId::new([99; 32]),
            balance: 0,
        }))),
        is_authorized: true,
        account_id: IdForTests::holding_id_2(),
    };

    let [cleared] = <[_; 1]>::try_from(close_holding(squatted, TOKEN_PROGRAM_ID)).unwrap();
    let cleared = cleared.expect("close writes the slot back");
    assert!(cleared.data.is_empty(), "closing clears the holding");

    let reused = Input {
        slot: named(cleared),
        is_authorized: false,
        account_id: IdForTests::holding_id_2(),
    };
    let post_states = initialize_account(
        &AccountForTests::definition_account_auth(),
        reused,
        TOKEN_PROGRAM_ID,
    );
    let [_, post_holding] = <[_; 2]>::try_from(post_states).unwrap();

    assert_eq!(
        TokenHolding::try_from(&post_holding.as_ref().unwrap().data)
            .unwrap()
            .definition_id(),
        AccountForTests::definition_account_auth().account_id
    );
}

#[should_panic(expected = "Holding authorization is missing")]
#[test]
fn close_holding_without_authorization_should_fail() {
    let holding = Input {
        slot: named(token_account(Data::from(&TokenHolding::Fungible {
            definition_id: IdForTests::pool_definition_id(),
            balance: 0,
        }))),
        is_authorized: false,
        account_id: IdForTests::holding_id_2(),
    };

    let _post_states = close_holding(holding, TOKEN_PROGRAM_ID);
}

#[should_panic(expected = "Only an empty holding can be closed")]
#[test]
fn close_holding_holding_value_should_fail() {
    let holding = Input {
        slot: named(token_account(Data::from(&TokenHolding::Fungible {
            definition_id: IdForTests::pool_definition_id(),
            balance: 1,
        }))),
        is_authorized: true,
        account_id: IdForTests::holding_id_2(),
    };

    let _post_states = close_holding(holding, TOKEN_PROGRAM_ID);
}

/// Anyone may credit a foreign slot into existence, which leaves this program's slot
/// present but empty. That is not a holding, and must not be read as one.
#[test]
fn a_bare_credit_does_not_look_like_a_holding() {
    let squatted = Slot {
        balance: 1,
        data: Data::empty(),
    };

    let recipient = Input {
        slot: named(squatted.clone()),
        is_authorized: false,
        account_id: IdForTests::holding_id_2(),
    };
    let post_states = transfer(
        AccountForTests::holding_account_init(),
        recipient,
        BalanceForTests::transfer_amount(),
        TOKEN_PROGRAM_ID,
    );
    let [_, post_recipient] = <[_; 2]>::try_from(post_states).unwrap();
    assert_eq!(
        TokenHolding::try_from(&post_recipient.as_ref().unwrap().data).unwrap(),
        TokenHolding::Fungible {
            definition_id: IdForTests::pool_definition_id(),
            balance: BalanceForTests::transfer_amount(),
        }
    );

    // The credited balance is untouched: it was never this program's to spend.
    assert_eq!(post_recipient.as_ref().unwrap().balance, 1);

    // And initializing over it still works.
    let fresh = Input {
        slot: named(squatted),
        is_authorized: false,
        account_id: IdForTests::holding_id_2(),
    };
    let post_states = initialize_account(
        &AccountForTests::definition_account_auth(),
        fresh,
        TOKEN_PROGRAM_ID,
    );
    assert_eq!(post_states.len(), 2);
}
