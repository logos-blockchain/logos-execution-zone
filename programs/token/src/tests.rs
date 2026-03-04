#![cfg(test)]
#![expect(
    clippy::shadow_unrelated,
    clippy::arithmetic_side_effects,
    reason = "We don't care about it in tests"
)]

use nssa_core::account::{Account, AccountId, AccountWithMetadata, Data};
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

struct BalanceForTests;
struct IdForTests;

struct AccountForTests;

impl AccountForTests {
    fn definition_account_auth() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: [5_u32; 8],
                balance: 0_u128,
                data: Data::from(&TokenDefinition::Fungible {
                    name: String::from("test"),
                    total_supply: BalanceForTests::init_supply(),
                    metadata_id: None,
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn definition_account_without_auth() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: [5_u32; 8],
                balance: 0_u128,
                data: Data::from(&TokenDefinition::Fungible {
                    name: String::from("test"),
                    total_supply: BalanceForTests::init_supply(),
                    metadata_id: None,
                }),
                nonce: 0,
            },
            is_authorized: false,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn holding_different_definition() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: [5_u32; 8],
                balance: 0_u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::pool_definition_id_diff(),
                    balance: BalanceForTests::holding_balance(),
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::holding_id(),
        }
    }

    fn holding_same_definition_with_authorization() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: [5_u32; 8],
                balance: 0_u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::pool_definition_id(),
                    balance: BalanceForTests::holding_balance(),
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::holding_id(),
        }
    }

    fn holding_same_definition_without_authorization() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: [5_u32; 8],
                balance: 0_u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::pool_definition_id(),
                    balance: BalanceForTests::holding_balance(),
                }),
                nonce: 0,
            },
            is_authorized: false,
            account_id: IdForTests::holding_id(),
        }
    }

    fn holding_same_definition_without_authorization_overflow() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: [5_u32; 8],
                balance: 0_u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::pool_definition_id(),
                    balance: BalanceForTests::init_supply(),
                }),
                nonce: 0,
            },
            is_authorized: false,
            account_id: IdForTests::holding_id(),
        }
    }

    fn definition_account_post_burn() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: [5_u32; 8],
                balance: 0_u128,
                data: Data::from(&TokenDefinition::Fungible {
                    name: String::from("test"),
                    total_supply: BalanceForTests::init_supply_burned(),
                    metadata_id: None,
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn holding_account_post_burn() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: [5_u32; 8],
                balance: 0_u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::pool_definition_id(),
                    balance: BalanceForTests::holding_balance_burned(),
                }),
                nonce: 0,
            },
            is_authorized: false,
            account_id: IdForTests::holding_id(),
        }
    }

    fn holding_account_uninit() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account::default(),
            is_authorized: false,
            account_id: IdForTests::holding_id_2(),
        }
    }

    fn init_mint() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: [0_u32; 8],
                balance: 0_u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::pool_definition_id(),
                    balance: BalanceForTests::mint_success(),
                }),
                nonce: 0,
            },
            is_authorized: false,
            account_id: IdForTests::holding_id(),
        }
    }

    fn holding_account_same_definition_mint() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: [5_u32; 8],
                balance: 0_u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::pool_definition_id(),
                    balance: BalanceForTests::holding_balance_mint(),
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn definition_account_mint() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: [5_u32; 8],
                balance: 0_u128,
                data: Data::from(&TokenDefinition::Fungible {
                    name: String::from("test"),
                    total_supply: BalanceForTests::init_supply_mint(),
                    metadata_id: None,
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn holding_same_definition_with_authorization_and_large_balance() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: [5_u32; 8],
                balance: 0_u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::pool_definition_id(),
                    balance: BalanceForTests::mint_overflow(),
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn definition_account_with_authorization_nonfungible() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: [5_u32; 8],
                balance: 0_u128,
                data: Data::from(&TokenDefinition::NonFungible {
                    name: String::from("test"),
                    printable_supply: BalanceForTests::printable_copies(),
                    metadata_id: AccountId::new([0; 32]),
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn definition_account_uninit() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account::default(),
            is_authorized: false,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn holding_account_init() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: [5_u32; 8],
                balance: 0_u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::pool_definition_id(),
                    balance: BalanceForTests::init_supply(),
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::holding_id(),
        }
    }

    fn definition_account_unclaimed() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: [0_u32; 8],
                balance: 0_u128,
                data: Data::from(&TokenDefinition::Fungible {
                    name: String::from("test"),
                    total_supply: BalanceForTests::init_supply(),
                    metadata_id: None,
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn holding_account_unclaimed() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: [0_u32; 8],
                balance: 0_u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::pool_definition_id(),
                    balance: BalanceForTests::init_supply(),
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::holding_id(),
        }
    }

    fn holding_account2_init() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: [5_u32; 8],
                balance: 0_u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::pool_definition_id(),
                    balance: BalanceForTests::init_supply(),
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::holding_id_2(),
        }
    }

    fn holding_account2_init_post_transfer() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: [5_u32; 8],
                balance: 0_u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::pool_definition_id(),
                    balance: BalanceForTests::recipient_post_transfer(),
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::holding_id_2(),
        }
    }

    fn holding_account_init_post_transfer() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: [5_u32; 8],
                balance: 0_u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::pool_definition_id(),
                    balance: BalanceForTests::sender_post_transfer(),
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::holding_id(),
        }
    }

    fn holding_account_master_nft() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: [5_u32; 8],
                balance: 0_u128,
                data: Data::from(&TokenHolding::NftMaster {
                    definition_id: IdForTests::pool_definition_id(),
                    print_balance: BalanceForTests::printable_copies(),
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::holding_id(),
        }
    }

    fn holding_account_master_nft_insufficient_balance() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: [5_u32; 8],
                balance: 0_u128,
                data: Data::from(&TokenHolding::NftMaster {
                    definition_id: IdForTests::pool_definition_id(),
                    print_balance: 1,
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::holding_id(),
        }
    }

    fn holding_account_master_nft_after_print() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: [5_u32; 8],
                balance: 0_u128,
                data: Data::from(&TokenHolding::NftMaster {
                    definition_id: IdForTests::pool_definition_id(),
                    print_balance: BalanceForTests::printable_copies() - 1,
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::holding_id(),
        }
    }

    fn holding_account_printed_nft() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: [0_u32; 8],
                balance: 0_u128,
                data: Data::from(&TokenHolding::NftPrintedCopy {
                    definition_id: IdForTests::pool_definition_id(),
                    owned: true,
                }),
                nonce: 0,
            },
            is_authorized: false,
            account_id: IdForTests::holding_id(),
        }
    }

    fn holding_account_with_master_nft_transferred_to() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: [0_u32; 8],
                balance: 0_u128,
                data: Data::from(&TokenHolding::NftMaster {
                    definition_id: IdForTests::pool_definition_id(),
                    print_balance: BalanceForTests::printable_copies(),
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::holding_id_2(),
        }
    }

    fn holding_account_master_nft_post_transfer() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: [5_u32; 8],
                balance: 0_u128,
                data: Data::from(&TokenHolding::NftMaster {
                    definition_id: IdForTests::pool_definition_id(),
                    print_balance: 0,
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::holding_id(),
        }
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

#[should_panic(expected = "Definition target account must have default values")]
#[test]
fn new_definition_non_default_first_account_should_fail() {
    let definition_account = AccountWithMetadata {
        account: Account {
            program_owner: [1, 2, 3, 4, 5, 6, 7, 8],
            ..Account::default()
        },
        is_authorized: true,
        account_id: AccountId::new([1; 32]),
    };
    let holding_account = AccountWithMetadata {
        account: Account::default(),
        is_authorized: true,
        account_id: AccountId::new([2; 32]),
    };
    let _post_states = new_fungible_definition(
        definition_account,
        holding_account,
        String::from("test"),
        10,
    );
}

#[should_panic(expected = "Holding target account must have default values")]
#[test]
fn new_definition_non_default_second_account_should_fail() {
    let definition_account = AccountWithMetadata {
        account: Account::default(),
        is_authorized: true,
        account_id: AccountId::new([1; 32]),
    };
    let holding_account = AccountWithMetadata {
        account: Account {
            program_owner: [1, 2, 3, 4, 5, 6, 7, 8],
            ..Account::default()
        },
        is_authorized: true,
        account_id: AccountId::new([2; 32]),
    };
    let _post_states = new_fungible_definition(
        definition_account,
        holding_account,
        String::from("test"),
        10,
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
    );

    let [definition_account, holding_account] = post_states.try_into().unwrap();
    assert_eq!(
        *definition_account.account(),
        AccountForTests::definition_account_unclaimed().account
    );

    assert_eq!(
        *holding_account.account(),
        AccountForTests::holding_account_unclaimed().account
    );
}

#[should_panic(expected = "Sender and recipient definition id mismatch")]
#[test]
fn transfer_with_different_definition_ids_should_fail() {
    let sender = AccountForTests::holding_same_definition_with_authorization();
    let recipient = AccountForTests::holding_different_definition();
    let _post_states = transfer(sender, recipient, 10);
}

#[should_panic(expected = "Insufficient balance")]
#[test]
fn transfer_with_insufficient_balance_should_fail() {
    let sender = AccountForTests::holding_same_definition_with_authorization();
    let recipient = AccountForTests::holding_account_same_definition_mint();
    // Attempt to transfer more than balance
    let _post_states = transfer(sender, recipient, BalanceForTests::burn_insufficient());
}

#[should_panic(expected = "Sender authorization is missing")]
#[test]
fn transfer_without_sender_authorization_should_fail() {
    let sender = AccountForTests::holding_same_definition_without_authorization();
    let recipient = AccountForTests::holding_account_uninit();
    let _post_states = transfer(sender, recipient, 37);
}

#[test]
fn transfer_with_valid_inputs_succeeds() {
    let sender = AccountForTests::holding_account_init();
    let recipient = AccountForTests::holding_account2_init();
    let post_states = transfer(sender, recipient, BalanceForTests::transfer_amount());
    let [sender_post, recipient_post] = post_states.try_into().unwrap();

    assert_eq!(
        *sender_post.account(),
        AccountForTests::holding_account_init_post_transfer().account
    );
    assert_eq!(
        *recipient_post.account(),
        AccountForTests::holding_account2_init_post_transfer().account
    );
}

#[should_panic(expected = "Invalid balance for NFT Master transfer")]
#[test]
fn transfer_with_master_nft_invalid_balance() {
    let sender = AccountForTests::holding_account_master_nft();
    let recipient = AccountForTests::holding_account_uninit();
    let _post_states = transfer(sender, recipient, BalanceForTests::transfer_amount());
}

#[should_panic(expected = "Invalid balance in recipient account for NFT transfer")]
#[test]
fn transfer_with_master_nft_invalid_recipient_balance() {
    let sender = AccountForTests::holding_account_master_nft();
    let recipient = AccountForTests::holding_account_with_master_nft_transferred_to();
    let _post_states = transfer(sender, recipient, BalanceForTests::printable_copies());
}

#[test]
fn transfer_with_master_nft_success() {
    let sender = AccountForTests::holding_account_master_nft();
    let recipient = AccountForTests::holding_account_uninit();
    let post_states = transfer(sender, recipient, BalanceForTests::printable_copies());
    let [sender_post, recipient_post] = post_states.try_into().unwrap();

    assert_eq!(
        *sender_post.account(),
        AccountForTests::holding_account_master_nft_post_transfer().account
    );
    assert_eq!(
        *recipient_post.account(),
        AccountForTests::holding_account_with_master_nft_transferred_to().account
    );
}

#[test]
fn token_initialize_account_succeeds() {
    let sender = AccountForTests::holding_account_init();
    let recipient = AccountForTests::holding_account2_init();
    let post_states = transfer(sender, recipient, BalanceForTests::transfer_amount());
    let [sender_post, recipient_post] = post_states.try_into().unwrap();

    assert_eq!(
        *sender_post.account(),
        AccountForTests::holding_account_init_post_transfer().account
    );
    assert_eq!(
        *recipient_post.account(),
        AccountForTests::holding_account2_init_post_transfer().account
    );
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
    );

    let [def_post, holding_post] = post_states.try_into().unwrap();

    assert_eq!(
        *def_post.account(),
        AccountForTests::definition_account_post_burn().account
    );
    assert_eq!(
        *holding_post.account(),
        AccountForTests::holding_account_post_burn().account
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
    );

    let [def_post, holding_post] = post_states.try_into().unwrap();

    assert_eq!(
        *def_post.account(),
        AccountForTests::definition_account_mint().account
    );
    assert_eq!(
        *holding_post.account(),
        AccountForTests::holding_account_same_definition_mint().account
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
    );

    let [def_post, holding_post] = post_states.try_into().unwrap();

    assert_eq!(
        *def_post.account(),
        AccountForTests::definition_account_mint().account
    );
    assert_eq!(
        *holding_post.account(),
        AccountForTests::init_mint().account
    );
    assert!(holding_post.requires_claim());
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
    );
}

#[should_panic(expected = "Definition target account must have default values")]
#[test]
fn call_new_definition_metadata_with_init_definition() {
    let definition_account = AccountForTests::definition_account_auth();
    let metadata_account = AccountWithMetadata {
        account: Account::default(),
        is_authorized: true,
        account_id: AccountId::new([2; 32]),
    };
    let holding_account = AccountWithMetadata {
        account: Account::default(),
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
    );
}

#[should_panic(expected = "Metadata target account must have default values")]
#[test]
fn call_new_definition_metadata_with_init_metadata() {
    let definition_account = AccountWithMetadata {
        account: Account::default(),
        is_authorized: true,
        account_id: AccountId::new([1; 32]),
    };
    let holding_account = AccountWithMetadata {
        account: Account::default(),
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
    );
}

#[should_panic(expected = "Holding target account must have default values")]
#[test]
fn call_new_definition_metadata_with_init_holding() {
    let definition_account = AccountWithMetadata {
        account: Account::default(),
        is_authorized: true,
        account_id: AccountId::new([1; 32]),
    };
    let metadata_account = AccountWithMetadata {
        account: Account::default(),
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
    );
}

#[should_panic(expected = "Master NFT Account must be authorized")]
#[test]
fn print_nft_master_account_must_be_authorized() {
    let master_account = AccountForTests::holding_account_uninit();
    let printed_account = AccountForTests::holding_account_uninit();
    let _post_states = print_nft(master_account, printed_account);
}

#[should_panic(expected = "Printed Account must be uninitialized")]
#[test]
fn print_nft_print_account_initialized() {
    let master_account = AccountForTests::holding_account_master_nft();
    let printed_account = AccountForTests::holding_account_init();
    let _post_states = print_nft(master_account, printed_account);
}

#[should_panic(expected = "Invalid Token Holding data")]
#[test]
fn print_nft_master_nft_invalid_token_holding() {
    let master_account = AccountForTests::definition_account_auth();
    let printed_account = AccountForTests::holding_account_uninit();
    let _post_states = print_nft(master_account, printed_account);
}

#[should_panic(expected = "Invalid Token Holding provided as NFT Master Account")]
#[test]
fn print_nft_master_nft_not_nft_master_account() {
    let master_account = AccountForTests::holding_account_init();
    let printed_account = AccountForTests::holding_account_uninit();
    let _post_states = print_nft(master_account, printed_account);
}

#[should_panic(expected = "Insufficient balance to print another NFT copy")]
#[test]
fn print_nft_master_nft_insufficient_balance() {
    let master_account = AccountForTests::holding_account_master_nft_insufficient_balance();
    let printed_account = AccountForTests::holding_account_uninit();
    let _post_states = print_nft(master_account, printed_account);
}

#[test]
fn print_nft_success() {
    let master_account = AccountForTests::holding_account_master_nft();
    let printed_account = AccountForTests::holding_account_uninit();
    let post_states = print_nft(master_account, printed_account);

    let [post_master_nft, post_printed] = post_states.try_into().unwrap();

    assert_eq!(
        *post_master_nft.account(),
        AccountForTests::holding_account_master_nft_after_print().account
    );
    assert_eq!(
        *post_printed.account(),
        AccountForTests::holding_account_printed_nft().account
    );
}
