use std::num::NonZero;

use amm_core::{
    PoolDefinition, compute_liquidity_token_pda, compute_liquidity_token_pda_seed,
    compute_pool_pda, compute_vault_pda, compute_vault_pda_seed,
};
use nssa::{
    PrivateKey, PublicKey, PublicTransaction, V02State, program::Program, public_transaction,
};
use nssa_core::{
    account::{Account, AccountId, AccountWithMetadata, Data},
    program::{ChainedCall, ProgramId},
};
use token_core::{TokenDefinition, TokenHolding};

use crate::{
    add::add_liquidity, new_definition::new_definition, remove::remove_liquidity, swap::swap,
};

const TOKEN_PROGRAM_ID: ProgramId = [15; 8];
const AMM_PROGRAM_ID: ProgramId = [42; 8];

struct BalanceForTests;
struct ChainedCallForTests;
struct IdForTests;
struct AccountWithMetadataForTests;

struct PrivateKeysForTests;

struct IdForExeTests;

struct BalanceForExeTests;

struct AccountsForExeTests;

impl PrivateKeysForTests {
    fn user_token_a_key() -> PrivateKey {
        PrivateKey::try_new([31; 32]).expect("Keys constructor expects valid private key")
    }

    fn user_token_b_key() -> PrivateKey {
        PrivateKey::try_new([32; 32]).expect("Keys constructor expects valid private key")
    }

    fn user_token_lp_key() -> PrivateKey {
        PrivateKey::try_new([33; 32]).expect("Keys constructor expects valid private key")
    }
}

impl BalanceForTests {
    fn vault_a_reserve_init() -> u128 {
        1_000
    }

    fn vault_b_reserve_init() -> u128 {
        500
    }

    fn vault_a_reserve_low() -> u128 {
        10
    }

    fn vault_b_reserve_low() -> u128 {
        10
    }

    fn vault_a_reserve_high() -> u128 {
        500_000
    }

    fn vault_b_reserve_high() -> u128 {
        500_000
    }

    fn user_token_a_balance() -> u128 {
        1_000
    }

    fn user_token_b_balance() -> u128 {
        500
    }

    fn user_token_lp_balance() -> u128 {
        100
    }

    fn remove_min_amount_a() -> u128 {
        50
    }

    fn remove_min_amount_b() -> u128 {
        100
    }

    fn remove_actual_a_successful() -> u128 {
        141
    }

    fn remove_min_amount_b_low() -> u128 {
        50
    }

    fn remove_amount_lp() -> u128 {
        100
    }

    fn remove_amount_lp_1() -> u128 {
        30
    }

    fn add_max_amount_a() -> u128 {
        500
    }

    fn add_max_amount_b() -> u128 {
        200
    }

    fn add_max_amount_a_low() -> u128 {
        10
    }

    fn add_max_amount_b_low() -> u128 {
        10
    }

    fn add_min_amount_lp() -> u128 {
        20
    }

    fn lp_supply_init() -> u128 {
        // sqrt(vault_a_reserve_init * vault_b_reserve_init) = sqrt(1000 * 500) = 707
        (Self::vault_a_reserve_init() * Self::vault_b_reserve_init()).isqrt()
    }

    fn vault_a_swap_test_1() -> u128 {
        1_500
    }

    fn vault_a_swap_test_2() -> u128 {
        715
    }

    fn vault_b_swap_test_1() -> u128 {
        334
    }

    fn vault_b_swap_test_2() -> u128 {
        700
    }

    fn min_amount_out() -> u128 {
        200
    }

    fn vault_a_add_successful() -> u128 {
        1_400
    }

    fn vault_b_add_successful() -> u128 {
        700
    }

    fn add_successful_amount_a() -> u128 {
        400
    }

    fn add_successful_amount_b() -> u128 {
        200
    }

    fn vault_a_remove_successful() -> u128 {
        859
    }

    fn vault_b_remove_successful() -> u128 {
        430
    }
}

impl ChainedCallForTests {
    fn cc_swap_token_a_test_1() -> ChainedCall {
        ChainedCall::new(
            TOKEN_PROGRAM_ID,
            vec![
                AccountWithMetadataForTests::user_holding_a(),
                AccountWithMetadataForTests::vault_a_init(),
            ],
            &token_core::Instruction::Transfer {
                amount_to_transfer: BalanceForTests::add_max_amount_a(),
            },
        )
    }

    fn cc_swap_token_b_test_1() -> ChainedCall {
        let swap_amount: u128 = 166;

        let mut vault_b_auth = AccountWithMetadataForTests::vault_b_init();
        vault_b_auth.is_authorized = true;

        ChainedCall::new(
            TOKEN_PROGRAM_ID,
            vec![vault_b_auth, AccountWithMetadataForTests::user_holding_b()],
            &token_core::Instruction::Transfer {
                amount_to_transfer: swap_amount,
            },
        )
        .with_pda_seeds(vec![compute_vault_pda_seed(
            IdForTests::pool_definition_id(),
            IdForTests::token_b_definition_id(),
        )])
    }

    fn cc_swap_token_a_test_2() -> ChainedCall {
        let swap_amount: u128 = 285;

        let mut vault_a_auth = AccountWithMetadataForTests::vault_a_init();
        vault_a_auth.is_authorized = true;

        ChainedCall::new(
            TOKEN_PROGRAM_ID,
            vec![vault_a_auth, AccountWithMetadataForTests::user_holding_a()],
            &token_core::Instruction::Transfer {
                amount_to_transfer: swap_amount,
            },
        )
        .with_pda_seeds(vec![compute_vault_pda_seed(
            IdForTests::pool_definition_id(),
            IdForTests::token_a_definition_id(),
        )])
    }

    fn cc_swap_token_b_test_2() -> ChainedCall {
        ChainedCall::new(
            TOKEN_PROGRAM_ID,
            vec![
                AccountWithMetadataForTests::user_holding_b(),
                AccountWithMetadataForTests::vault_b_init(),
            ],
            &token_core::Instruction::Transfer {
                amount_to_transfer: BalanceForTests::add_max_amount_b(),
            },
        )
    }

    fn cc_add_token_a() -> ChainedCall {
        ChainedCall::new(
            TOKEN_PROGRAM_ID,
            vec![
                AccountWithMetadataForTests::user_holding_a(),
                AccountWithMetadataForTests::vault_a_init(),
            ],
            &token_core::Instruction::Transfer {
                amount_to_transfer: BalanceForTests::add_successful_amount_a(),
            },
        )
    }

    fn cc_add_token_b() -> ChainedCall {
        ChainedCall::new(
            TOKEN_PROGRAM_ID,
            vec![
                AccountWithMetadataForTests::user_holding_b(),
                AccountWithMetadataForTests::vault_b_init(),
            ],
            &token_core::Instruction::Transfer {
                amount_to_transfer: BalanceForTests::add_successful_amount_b(),
            },
        )
    }

    fn cc_add_pool_lp() -> ChainedCall {
        let mut pool_lp_auth = AccountWithMetadataForTests::pool_lp_init();
        pool_lp_auth.is_authorized = true;

        ChainedCall::new(
            TOKEN_PROGRAM_ID,
            vec![
                pool_lp_auth,
                AccountWithMetadataForTests::user_holding_lp_init(),
            ],
            &token_core::Instruction::Mint {
                amount_to_mint: 282,
            },
        )
        .with_pda_seeds(vec![compute_liquidity_token_pda_seed(
            IdForTests::pool_definition_id(),
        )])
    }

    fn cc_remove_token_a() -> ChainedCall {
        let mut vault_a_auth = AccountWithMetadataForTests::vault_a_init();
        vault_a_auth.is_authorized = true;

        ChainedCall::new(
            TOKEN_PROGRAM_ID,
            vec![vault_a_auth, AccountWithMetadataForTests::user_holding_a()],
            &token_core::Instruction::Transfer {
                amount_to_transfer: BalanceForTests::remove_actual_a_successful(),
            },
        )
        .with_pda_seeds(vec![compute_vault_pda_seed(
            IdForTests::pool_definition_id(),
            IdForTests::token_a_definition_id(),
        )])
    }

    fn cc_remove_token_b() -> ChainedCall {
        let mut vault_b_auth = AccountWithMetadataForTests::vault_b_init();
        vault_b_auth.is_authorized = true;

        ChainedCall::new(
            TOKEN_PROGRAM_ID,
            vec![vault_b_auth, AccountWithMetadataForTests::user_holding_b()],
            &token_core::Instruction::Transfer {
                amount_to_transfer: 70,
            },
        )
        .with_pda_seeds(vec![compute_vault_pda_seed(
            IdForTests::pool_definition_id(),
            IdForTests::token_b_definition_id(),
        )])
    }

    fn cc_remove_pool_lp() -> ChainedCall {
        let mut pool_lp_auth = AccountWithMetadataForTests::pool_lp_init();
        pool_lp_auth.is_authorized = true;

        ChainedCall::new(
            TOKEN_PROGRAM_ID,
            vec![
                pool_lp_auth,
                AccountWithMetadataForTests::user_holding_lp_init(),
            ],
            &token_core::Instruction::Burn {
                amount_to_burn: BalanceForTests::remove_amount_lp(),
            },
        )
        .with_pda_seeds(vec![compute_liquidity_token_pda_seed(
            IdForTests::pool_definition_id(),
        )])
    }

    fn cc_new_definition_token_a() -> ChainedCall {
        ChainedCall::new(
            TOKEN_PROGRAM_ID,
            vec![
                AccountWithMetadataForTests::user_holding_a(),
                AccountWithMetadataForTests::vault_a_init(),
            ],
            &token_core::Instruction::Transfer {
                amount_to_transfer: BalanceForTests::add_successful_amount_a(),
            },
        )
    }

    fn cc_new_definition_token_b() -> ChainedCall {
        ChainedCall::new(
            TOKEN_PROGRAM_ID,
            vec![
                AccountWithMetadataForTests::user_holding_b(),
                AccountWithMetadataForTests::vault_b_init(),
            ],
            &token_core::Instruction::Transfer {
                amount_to_transfer: BalanceForTests::add_successful_amount_b(),
            },
        )
    }

    fn cc_new_definition_token_lp() -> ChainedCall {
        ChainedCall::new(
            TOKEN_PROGRAM_ID,
            vec![
                AccountWithMetadataForTests::pool_lp_init(),
                AccountWithMetadataForTests::user_holding_lp_uninit(),
            ],
            &token_core::Instruction::Mint {
                amount_to_mint: BalanceForTests::lp_supply_init(),
            },
        )
        .with_pda_seeds(vec![compute_liquidity_token_pda_seed(
            IdForTests::pool_definition_id(),
        )])
    }
}

impl IdForTests {
    fn token_a_definition_id() -> AccountId {
        AccountId::new([42; 32])
    }

    fn token_b_definition_id() -> AccountId {
        AccountId::new([43; 32])
    }

    fn token_lp_definition_id() -> AccountId {
        compute_liquidity_token_pda(AMM_PROGRAM_ID, Self::pool_definition_id())
    }

    fn user_token_a_id() -> AccountId {
        AccountId::new([45; 32])
    }

    fn user_token_b_id() -> AccountId {
        AccountId::new([46; 32])
    }

    fn user_token_lp_id() -> AccountId {
        AccountId::new([47; 32])
    }

    fn pool_definition_id() -> AccountId {
        compute_pool_pda(
            AMM_PROGRAM_ID,
            Self::token_a_definition_id(),
            Self::token_b_definition_id(),
        )
    }

    fn vault_a_id() -> AccountId {
        compute_vault_pda(
            AMM_PROGRAM_ID,
            Self::pool_definition_id(),
            Self::token_a_definition_id(),
        )
    }

    fn vault_b_id() -> AccountId {
        compute_vault_pda(
            AMM_PROGRAM_ID,
            Self::pool_definition_id(),
            Self::token_b_definition_id(),
        )
    }
}

impl AccountWithMetadataForTests {
    fn user_holding_a() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0_u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_a_definition_id(),
                    balance: BalanceForTests::user_token_a_balance(),
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: IdForTests::user_token_a_id(),
        }
    }

    fn user_holding_b() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0_u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_b_definition_id(),
                    balance: BalanceForTests::user_token_b_balance(),
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: IdForTests::user_token_b_id(),
        }
    }

    fn vault_a_init() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0_u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_a_definition_id(),
                    balance: BalanceForTests::vault_a_reserve_init(),
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: IdForTests::vault_a_id(),
        }
    }

    fn vault_b_init() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0_u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_b_definition_id(),
                    balance: BalanceForTests::vault_b_reserve_init(),
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: IdForTests::vault_b_id(),
        }
    }

    fn vault_a_init_high() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0_u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_a_definition_id(),
                    balance: BalanceForTests::vault_a_reserve_high(),
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: IdForTests::vault_a_id(),
        }
    }

    fn vault_b_init_high() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0_u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_b_definition_id(),
                    balance: BalanceForTests::vault_b_reserve_high(),
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: IdForTests::vault_b_id(),
        }
    }

    fn vault_a_init_low() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0_u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_a_definition_id(),
                    balance: BalanceForTests::vault_a_reserve_low(),
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: IdForTests::vault_a_id(),
        }
    }

    fn vault_b_init_low() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0_u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_b_definition_id(),
                    balance: BalanceForTests::vault_b_reserve_low(),
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: IdForTests::vault_b_id(),
        }
    }

    fn vault_a_init_zero() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0_u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_a_definition_id(),
                    balance: 0,
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: IdForTests::vault_a_id(),
        }
    }

    fn vault_b_init_zero() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0_u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_b_definition_id(),
                    balance: 0,
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: IdForTests::vault_b_id(),
        }
    }

    fn pool_lp_init() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0_u128,
                data: Data::from(&TokenDefinition::Fungible {
                    name: String::from("test"),
                    total_supply: BalanceForTests::lp_supply_init(),
                    metadata_id: None,
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: IdForTests::token_lp_definition_id(),
        }
    }

    fn pool_lp_with_wrong_id() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0_u128,
                data: Data::from(&TokenDefinition::Fungible {
                    name: String::from("test"),
                    total_supply: BalanceForTests::lp_supply_init(),
                    metadata_id: None,
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: IdForTests::vault_a_id(),
        }
    }

    fn user_holding_lp_uninit() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0_u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_lp_definition_id(),
                    balance: 0,
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: IdForTests::user_token_lp_id(),
        }
    }

    fn user_holding_lp_init() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0_u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_lp_definition_id(),
                    balance: BalanceForTests::user_token_lp_balance(),
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: IdForTests::user_token_lp_id(),
        }
    }

    fn pool_definition_init() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: ProgramId::default(),
                balance: 0_u128,
                data: Data::from(&PoolDefinition {
                    definition_token_a_id: IdForTests::token_a_definition_id(),
                    definition_token_b_id: IdForTests::token_b_definition_id(),
                    vault_a_id: IdForTests::vault_a_id(),
                    vault_b_id: IdForTests::vault_b_id(),
                    liquidity_pool_id: IdForTests::token_lp_definition_id(),
                    liquidity_pool_supply: BalanceForTests::lp_supply_init(),
                    reserve_a: BalanceForTests::vault_a_reserve_init(),
                    reserve_b: BalanceForTests::vault_b_reserve_init(),
                    fees: 0_u128,
                    active: true,
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn pool_definition_init_reserve_a_zero() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: ProgramId::default(),
                balance: 0_u128,
                data: Data::from(&PoolDefinition {
                    definition_token_a_id: IdForTests::token_a_definition_id(),
                    definition_token_b_id: IdForTests::token_b_definition_id(),
                    vault_a_id: IdForTests::vault_a_id(),
                    vault_b_id: IdForTests::vault_b_id(),
                    liquidity_pool_id: IdForTests::token_lp_definition_id(),
                    liquidity_pool_supply: BalanceForTests::lp_supply_init(),
                    reserve_a: 0,
                    reserve_b: BalanceForTests::vault_b_reserve_init(),
                    fees: 0_u128,
                    active: true,
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn pool_definition_init_reserve_b_zero() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: ProgramId::default(),
                balance: 0_u128,
                data: Data::from(&PoolDefinition {
                    definition_token_a_id: IdForTests::token_a_definition_id(),
                    definition_token_b_id: IdForTests::token_b_definition_id(),
                    vault_a_id: IdForTests::vault_a_id(),
                    vault_b_id: IdForTests::vault_b_id(),
                    liquidity_pool_id: IdForTests::token_lp_definition_id(),
                    liquidity_pool_supply: BalanceForTests::lp_supply_init(),
                    reserve_a: BalanceForTests::vault_a_reserve_init(),
                    reserve_b: 0,
                    fees: 0_u128,
                    active: true,
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn pool_definition_init_reserve_a_low() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: ProgramId::default(),
                balance: 0_u128,
                data: Data::from(&PoolDefinition {
                    definition_token_a_id: IdForTests::token_a_definition_id(),
                    definition_token_b_id: IdForTests::token_b_definition_id(),
                    vault_a_id: IdForTests::vault_a_id(),
                    vault_b_id: IdForTests::vault_b_id(),
                    liquidity_pool_id: IdForTests::token_lp_definition_id(),
                    liquidity_pool_supply: BalanceForTests::vault_a_reserve_low(),
                    reserve_a: BalanceForTests::vault_a_reserve_low(),
                    reserve_b: BalanceForTests::vault_b_reserve_high(),
                    fees: 0_u128,
                    active: true,
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn pool_definition_init_reserve_b_low() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: ProgramId::default(),
                balance: 0_u128,
                data: Data::from(&PoolDefinition {
                    definition_token_a_id: IdForTests::token_a_definition_id(),
                    definition_token_b_id: IdForTests::token_b_definition_id(),
                    vault_a_id: IdForTests::vault_a_id(),
                    vault_b_id: IdForTests::vault_b_id(),
                    liquidity_pool_id: IdForTests::token_lp_definition_id(),
                    liquidity_pool_supply: BalanceForTests::vault_a_reserve_high(),
                    reserve_a: BalanceForTests::vault_a_reserve_high(),
                    reserve_b: BalanceForTests::vault_b_reserve_low(),
                    fees: 0_u128,
                    active: true,
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn pool_definition_swap_test_1() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: ProgramId::default(),
                balance: 0_u128,
                data: Data::from(&PoolDefinition {
                    definition_token_a_id: IdForTests::token_a_definition_id(),
                    definition_token_b_id: IdForTests::token_b_definition_id(),
                    vault_a_id: IdForTests::vault_a_id(),
                    vault_b_id: IdForTests::vault_b_id(),
                    liquidity_pool_id: IdForTests::token_lp_definition_id(),
                    liquidity_pool_supply: BalanceForTests::lp_supply_init(),
                    reserve_a: BalanceForTests::vault_a_swap_test_1(),
                    reserve_b: BalanceForTests::vault_b_swap_test_1(),
                    fees: 0_u128,
                    active: true,
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn pool_definition_swap_test_2() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: ProgramId::default(),
                balance: 0_u128,
                data: Data::from(&PoolDefinition {
                    definition_token_a_id: IdForTests::token_a_definition_id(),
                    definition_token_b_id: IdForTests::token_b_definition_id(),
                    vault_a_id: IdForTests::vault_a_id(),
                    vault_b_id: IdForTests::vault_b_id(),
                    liquidity_pool_id: IdForTests::token_lp_definition_id(),
                    liquidity_pool_supply: BalanceForTests::lp_supply_init(),
                    reserve_a: BalanceForTests::vault_a_swap_test_2(),
                    reserve_b: BalanceForTests::vault_b_swap_test_2(),
                    fees: 0_u128,
                    active: true,
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn pool_definition_add_zero_lp() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: ProgramId::default(),
                balance: 0_u128,
                data: Data::from(&PoolDefinition {
                    definition_token_a_id: IdForTests::token_a_definition_id(),
                    definition_token_b_id: IdForTests::token_b_definition_id(),
                    vault_a_id: IdForTests::vault_a_id(),
                    vault_b_id: IdForTests::vault_b_id(),
                    liquidity_pool_id: IdForTests::token_lp_definition_id(),
                    liquidity_pool_supply: BalanceForTests::vault_a_reserve_low(),
                    reserve_a: BalanceForTests::vault_a_reserve_init(),
                    reserve_b: BalanceForTests::vault_b_reserve_init(),
                    fees: 0_u128,
                    active: true,
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn pool_definition_add_successful() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: ProgramId::default(),
                balance: 0_u128,
                data: Data::from(&PoolDefinition {
                    definition_token_a_id: IdForTests::token_a_definition_id(),
                    definition_token_b_id: IdForTests::token_b_definition_id(),
                    vault_a_id: IdForTests::vault_a_id(),
                    vault_b_id: IdForTests::vault_b_id(),
                    liquidity_pool_id: IdForTests::token_lp_definition_id(),
                    liquidity_pool_supply: 989,
                    reserve_a: BalanceForTests::vault_a_add_successful(),
                    reserve_b: BalanceForTests::vault_b_add_successful(),
                    fees: 0_u128,
                    active: true,
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn pool_definition_remove_successful() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: ProgramId::default(),
                balance: 0_u128,
                data: Data::from(&PoolDefinition {
                    definition_token_a_id: IdForTests::token_a_definition_id(),
                    definition_token_b_id: IdForTests::token_b_definition_id(),
                    vault_a_id: IdForTests::vault_a_id(),
                    vault_b_id: IdForTests::vault_b_id(),
                    liquidity_pool_id: IdForTests::token_lp_definition_id(),
                    liquidity_pool_supply: 607,
                    reserve_a: BalanceForTests::vault_a_remove_successful(),
                    reserve_b: BalanceForTests::vault_b_remove_successful(),
                    fees: 0_u128,
                    active: true,
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn pool_definition_inactive() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: ProgramId::default(),
                balance: 0_u128,
                data: Data::from(&PoolDefinition {
                    definition_token_a_id: IdForTests::token_a_definition_id(),
                    definition_token_b_id: IdForTests::token_b_definition_id(),
                    vault_a_id: IdForTests::vault_a_id(),
                    vault_b_id: IdForTests::vault_b_id(),
                    liquidity_pool_id: IdForTests::token_lp_definition_id(),
                    liquidity_pool_supply: BalanceForTests::lp_supply_init(),
                    reserve_a: BalanceForTests::vault_a_reserve_init(),
                    reserve_b: BalanceForTests::vault_b_reserve_init(),
                    fees: 0_u128,
                    active: false,
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn pool_definition_with_wrong_id() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: ProgramId::default(),
                balance: 0_u128,
                data: Data::from(&PoolDefinition {
                    definition_token_a_id: IdForTests::token_a_definition_id(),
                    definition_token_b_id: IdForTests::token_b_definition_id(),
                    vault_a_id: IdForTests::vault_a_id(),
                    vault_b_id: IdForTests::vault_b_id(),
                    liquidity_pool_id: IdForTests::token_lp_definition_id(),
                    liquidity_pool_supply: BalanceForTests::lp_supply_init(),
                    reserve_a: BalanceForTests::vault_a_reserve_init(),
                    reserve_b: BalanceForTests::vault_b_reserve_init(),
                    fees: 0_u128,
                    active: false,
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: AccountId::new([4; 32]),
        }
    }

    fn vault_a_with_wrong_id() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0_u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_a_definition_id(),
                    balance: BalanceForTests::vault_a_reserve_init(),
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: AccountId::new([4; 32]),
        }
    }

    fn vault_b_with_wrong_id() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0_u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_b_definition_id(),
                    balance: BalanceForTests::vault_b_reserve_init(),
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: AccountId::new([4; 32]),
        }
    }

    fn pool_definition_active() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: ProgramId::default(),
                balance: 0_u128,
                data: Data::from(&PoolDefinition {
                    definition_token_a_id: IdForTests::token_a_definition_id(),
                    definition_token_b_id: IdForTests::token_b_definition_id(),
                    vault_a_id: IdForTests::vault_a_id(),
                    vault_b_id: IdForTests::vault_b_id(),
                    liquidity_pool_id: IdForTests::token_lp_definition_id(),
                    liquidity_pool_supply: BalanceForTests::lp_supply_init(),
                    reserve_a: BalanceForTests::vault_a_reserve_init(),
                    reserve_b: BalanceForTests::vault_b_reserve_init(),
                    fees: 0_u128,
                    active: true,
                }),
                nonce: 0_u128.into(),
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }
}

impl BalanceForExeTests {
    fn user_token_a_holding_init() -> u128 {
        10_000
    }

    fn user_token_b_holding_init() -> u128 {
        10_000
    }

    fn user_token_lp_holding_init() -> u128 {
        2_000
    }

    fn vault_a_balance_init() -> u128 {
        5_000
    }

    fn vault_b_balance_init() -> u128 {
        2_500
    }

    fn pool_lp_supply_init() -> u128 {
        5_000
    }

    fn token_a_supply() -> u128 {
        100_000
    }

    fn token_b_supply() -> u128 {
        100_000
    }

    fn token_lp_supply() -> u128 {
        5_000
    }

    fn remove_lp() -> u128 {
        1_000
    }

    fn remove_min_amount_a() -> u128 {
        500
    }

    fn remove_min_amount_b() -> u128 {
        500
    }

    fn add_min_amount_lp() -> u128 {
        1_000
    }

    fn add_max_amount_a() -> u128 {
        2_000
    }

    fn add_max_amount_b() -> u128 {
        1_000
    }

    fn swap_amount_in() -> u128 {
        1_000
    }

    fn swap_min_amount_out() -> u128 {
        200
    }

    fn vault_a_balance_swap_1() -> u128 {
        3_572
    }

    fn vault_b_balance_swap_1() -> u128 {
        3_500
    }

    fn user_token_a_holding_swap_1() -> u128 {
        11_428
    }

    fn user_token_b_holding_swap_1() -> u128 {
        9_000
    }

    fn vault_a_balance_swap_2() -> u128 {
        6_000
    }

    fn vault_b_balance_swap_2() -> u128 {
        2_084
    }

    fn user_token_a_holding_swap_2() -> u128 {
        9_000
    }

    fn user_token_b_holding_swap_2() -> u128 {
        10_416
    }

    fn vault_a_balance_add() -> u128 {
        7_000
    }

    fn vault_b_balance_add() -> u128 {
        3_500
    }

    fn user_token_a_holding_add() -> u128 {
        8_000
    }

    fn user_token_b_holding_add() -> u128 {
        9_000
    }

    fn user_token_lp_holding_add() -> u128 {
        4_000
    }

    fn token_lp_supply_add() -> u128 {
        7_000
    }

    fn vault_a_balance_remove() -> u128 {
        4_000
    }

    fn vault_b_balance_remove() -> u128 {
        2_000
    }

    fn user_token_a_holding_remove() -> u128 {
        11_000
    }

    fn user_token_b_holding_remove() -> u128 {
        10_500
    }

    fn user_token_lp_holding_remove() -> u128 {
        1_000
    }

    fn token_lp_supply_remove() -> u128 {
        4_000
    }

    fn user_token_a_holding_new_definition() -> u128 {
        5_000
    }

    fn user_token_b_holding_new_definition() -> u128 {
        7_500
    }

    fn lp_supply_init() -> u128 {
        // isqrt(vault_a_balance_init * vault_b_balance_init) = isqrt(5_000 * 2_500) = 3535
        (Self::vault_a_balance_init() * Self::vault_b_balance_init()).isqrt()
    }
}

impl IdForExeTests {
    fn pool_definition_id() -> AccountId {
        amm_core::compute_pool_pda(
            Program::amm().id(),
            Self::token_a_definition_id(),
            Self::token_b_definition_id(),
        )
    }

    fn token_lp_definition_id() -> AccountId {
        amm_core::compute_liquidity_token_pda(Program::amm().id(), Self::pool_definition_id())
    }

    fn token_a_definition_id() -> AccountId {
        AccountId::new([3; 32])
    }

    fn token_b_definition_id() -> AccountId {
        AccountId::new([4; 32])
    }

    fn user_token_a_id() -> AccountId {
        AccountId::from(&PublicKey::new_from_private_key(
            &PrivateKeysForTests::user_token_a_key(),
        ))
    }

    fn user_token_b_id() -> AccountId {
        AccountId::from(&PublicKey::new_from_private_key(
            &PrivateKeysForTests::user_token_b_key(),
        ))
    }

    fn user_token_lp_id() -> AccountId {
        AccountId::from(&PublicKey::new_from_private_key(
            &PrivateKeysForTests::user_token_lp_key(),
        ))
    }

    fn vault_a_id() -> AccountId {
        amm_core::compute_vault_pda(
            Program::amm().id(),
            Self::pool_definition_id(),
            Self::token_a_definition_id(),
        )
    }

    fn vault_b_id() -> AccountId {
        amm_core::compute_vault_pda(
            Program::amm().id(),
            Self::pool_definition_id(),
            Self::token_b_definition_id(),
        )
    }
}

impl AccountsForExeTests {
    fn user_token_a_holding() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_a_definition_id(),
                balance: BalanceForExeTests::user_token_a_holding_init(),
            }),
            nonce: 0_u128.into(),
        }
    }

    fn user_token_b_holding() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_b_definition_id(),
                balance: BalanceForExeTests::user_token_b_holding_init(),
            }),
            nonce: 0_u128.into(),
        }
    }

    fn pool_definition_init() -> Account {
        Account {
            program_owner: Program::amm().id(),
            balance: 0_u128,
            data: Data::from(&PoolDefinition {
                definition_token_a_id: IdForExeTests::token_a_definition_id(),
                definition_token_b_id: IdForExeTests::token_b_definition_id(),
                vault_a_id: IdForExeTests::vault_a_id(),
                vault_b_id: IdForExeTests::vault_b_id(),
                liquidity_pool_id: IdForExeTests::token_lp_definition_id(),
                liquidity_pool_supply: BalanceForExeTests::pool_lp_supply_init(),
                reserve_a: BalanceForExeTests::vault_a_balance_init(),
                reserve_b: BalanceForExeTests::vault_b_balance_init(),
                fees: 0_u128,
                active: true,
            }),
            nonce: 0_u128.into(),
        }
    }

    fn token_a_definition_account() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenDefinition::Fungible {
                name: String::from("test"),
                total_supply: BalanceForExeTests::token_a_supply(),
                metadata_id: None,
            }),
            nonce: 0_u128.into(),
        }
    }

    fn token_b_definition_acc() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenDefinition::Fungible {
                name: String::from("test"),
                total_supply: BalanceForExeTests::token_b_supply(),
                metadata_id: None,
            }),
            nonce: 0_u128.into(),
        }
    }

    fn token_lp_definition_acc() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenDefinition::Fungible {
                name: String::from("LP Token"),
                total_supply: BalanceForExeTests::token_lp_supply(),
                metadata_id: None,
            }),
            nonce: 0_u128.into(),
        }
    }

    fn vault_a_init() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_a_definition_id(),
                balance: BalanceForExeTests::vault_a_balance_init(),
            }),
            nonce: 0_u128.into(),
        }
    }

    fn vault_b_init() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_b_definition_id(),
                balance: BalanceForExeTests::vault_b_balance_init(),
            }),
            nonce: 0_u128.into(),
        }
    }

    fn user_token_lp_holding() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_lp_definition_id(),
                balance: BalanceForExeTests::user_token_lp_holding_init(),
            }),
            nonce: 0_u128.into(),
        }
    }

    fn vault_a_swap_1() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_a_definition_id(),
                balance: BalanceForExeTests::vault_a_balance_swap_1(),
            }),
            nonce: 0_u128.into(),
        }
    }

    fn vault_b_swap_1() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_b_definition_id(),
                balance: BalanceForExeTests::vault_b_balance_swap_1(),
            }),
            nonce: 0_u128.into(),
        }
    }

    fn pool_definition_swap_1() -> Account {
        Account {
            program_owner: Program::amm().id(),
            balance: 0_u128,
            data: Data::from(&PoolDefinition {
                definition_token_a_id: IdForExeTests::token_a_definition_id(),
                definition_token_b_id: IdForExeTests::token_b_definition_id(),
                vault_a_id: IdForExeTests::vault_a_id(),
                vault_b_id: IdForExeTests::vault_b_id(),
                liquidity_pool_id: IdForExeTests::token_lp_definition_id(),
                liquidity_pool_supply: BalanceForExeTests::pool_lp_supply_init(),
                reserve_a: BalanceForExeTests::vault_a_balance_swap_1(),
                reserve_b: BalanceForExeTests::vault_b_balance_swap_1(),
                fees: 0_u128,
                active: true,
            }),
            nonce: 0_u128.into(),
        }
    }

    fn user_token_a_holding_swap_1() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_a_definition_id(),
                balance: BalanceForExeTests::user_token_a_holding_swap_1(),
            }),
            nonce: 0_u128.into(),
        }
    }

    fn user_token_b_holding_swap_1() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_b_definition_id(),
                balance: BalanceForExeTests::user_token_b_holding_swap_1(),
            }),
            nonce: 1_u128.into(),
        }
    }

    fn vault_a_swap_2() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_a_definition_id(),
                balance: BalanceForExeTests::vault_a_balance_swap_2(),
            }),
            nonce: 0_u128.into(),
        }
    }

    fn vault_b_swap_2() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_b_definition_id(),
                balance: BalanceForExeTests::vault_b_balance_swap_2(),
            }),
            nonce: 0_u128.into(),
        }
    }

    fn pool_definition_swap_2() -> Account {
        Account {
            program_owner: Program::amm().id(),
            balance: 0_u128,
            data: Data::from(&PoolDefinition {
                definition_token_a_id: IdForExeTests::token_a_definition_id(),
                definition_token_b_id: IdForExeTests::token_b_definition_id(),
                vault_a_id: IdForExeTests::vault_a_id(),
                vault_b_id: IdForExeTests::vault_b_id(),
                liquidity_pool_id: IdForExeTests::token_lp_definition_id(),
                liquidity_pool_supply: BalanceForExeTests::pool_lp_supply_init(),
                reserve_a: BalanceForExeTests::vault_a_balance_swap_2(),
                reserve_b: BalanceForExeTests::vault_b_balance_swap_2(),
                fees: 0_u128,
                active: true,
            }),
            nonce: 0_u128.into(),
        }
    }

    fn user_token_a_holding_swap_2() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_a_definition_id(),
                balance: BalanceForExeTests::user_token_a_holding_swap_2(),
            }),
            nonce: 1_u128.into(),
        }
    }

    fn user_token_b_holding_swap_2() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_b_definition_id(),
                balance: BalanceForExeTests::user_token_b_holding_swap_2(),
            }),
            nonce: 0_u128.into(),
        }
    }

    fn vault_a_add() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_a_definition_id(),
                balance: BalanceForExeTests::vault_a_balance_add(),
            }),
            nonce: 0_u128.into(),
        }
    }

    fn vault_b_add() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_b_definition_id(),
                balance: BalanceForExeTests::vault_b_balance_add(),
            }),
            nonce: 0_u128.into(),
        }
    }

    fn pool_definition_add() -> Account {
        Account {
            program_owner: Program::amm().id(),
            balance: 0_u128,
            data: Data::from(&PoolDefinition {
                definition_token_a_id: IdForExeTests::token_a_definition_id(),
                definition_token_b_id: IdForExeTests::token_b_definition_id(),
                vault_a_id: IdForExeTests::vault_a_id(),
                vault_b_id: IdForExeTests::vault_b_id(),
                liquidity_pool_id: IdForExeTests::token_lp_definition_id(),
                liquidity_pool_supply: BalanceForExeTests::token_lp_supply_add(),
                reserve_a: BalanceForExeTests::vault_a_balance_add(),
                reserve_b: BalanceForExeTests::vault_b_balance_add(),
                fees: 0_u128,
                active: true,
            }),
            nonce: 0_u128.into(),
        }
    }

    fn user_token_a_holding_add() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_a_definition_id(),
                balance: BalanceForExeTests::user_token_a_holding_add(),
            }),
            nonce: 1_u128.into(),
        }
    }

    fn user_token_b_holding_add() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_b_definition_id(),
                balance: BalanceForExeTests::user_token_b_holding_add(),
            }),
            nonce: 1_u128.into(),
        }
    }

    fn user_token_lp_holding_add() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_lp_definition_id(),
                balance: BalanceForExeTests::user_token_lp_holding_add(),
            }),
            nonce: 0_u128.into(),
        }
    }

    fn token_lp_definition_add() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenDefinition::Fungible {
                name: String::from("LP Token"),
                total_supply: BalanceForExeTests::token_lp_supply_add(),
                metadata_id: None,
            }),
            nonce: 0_u128.into(),
        }
    }

    fn vault_a_remove() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_a_definition_id(),
                balance: BalanceForExeTests::vault_a_balance_remove(),
            }),
            nonce: 0_u128.into(),
        }
    }

    fn vault_b_remove() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_b_definition_id(),
                balance: BalanceForExeTests::vault_b_balance_remove(),
            }),
            nonce: 0_u128.into(),
        }
    }

    fn pool_definition_remove() -> Account {
        Account {
            program_owner: Program::amm().id(),
            balance: 0_u128,
            data: Data::from(&PoolDefinition {
                definition_token_a_id: IdForExeTests::token_a_definition_id(),
                definition_token_b_id: IdForExeTests::token_b_definition_id(),
                vault_a_id: IdForExeTests::vault_a_id(),
                vault_b_id: IdForExeTests::vault_b_id(),
                liquidity_pool_id: IdForExeTests::token_lp_definition_id(),
                liquidity_pool_supply: BalanceForExeTests::token_lp_supply_remove(),
                reserve_a: BalanceForExeTests::vault_a_balance_remove(),
                reserve_b: BalanceForExeTests::vault_b_balance_remove(),
                fees: 0_u128,
                active: true,
            }),
            nonce: 0_u128.into(),
        }
    }

    fn user_token_a_holding_remove() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_a_definition_id(),
                balance: BalanceForExeTests::user_token_a_holding_remove(),
            }),
            nonce: 0_u128.into(),
        }
    }

    fn user_token_b_holding_remove() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_b_definition_id(),
                balance: BalanceForExeTests::user_token_b_holding_remove(),
            }),
            nonce: 0_u128.into(),
        }
    }

    fn user_token_lp_holding_remove() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_lp_definition_id(),
                balance: BalanceForExeTests::user_token_lp_holding_remove(),
            }),
            nonce: 1_u128.into(),
        }
    }

    fn token_lp_definition_remove() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenDefinition::Fungible {
                name: String::from("LP Token"),
                total_supply: BalanceForExeTests::token_lp_supply_remove(),
                metadata_id: None,
            }),
            nonce: 0_u128.into(),
        }
    }

    fn token_lp_definition_init_inactive() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenDefinition::Fungible {
                name: String::from("LP Token"),
                total_supply: 0,
                metadata_id: None,
            }),
            nonce: 0_u128.into(),
        }
    }

    fn vault_a_init_inactive() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_a_definition_id(),
                balance: 0,
            }),
            nonce: 0_u128.into(),
        }
    }

    fn vault_b_init_inactive() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_b_definition_id(),
                balance: 0,
            }),
            nonce: 0_u128.into(),
        }
    }

    fn pool_definition_inactive() -> Account {
        Account {
            program_owner: Program::amm().id(),
            balance: 0_u128,
            data: Data::from(&PoolDefinition {
                definition_token_a_id: IdForExeTests::token_a_definition_id(),
                definition_token_b_id: IdForExeTests::token_b_definition_id(),
                vault_a_id: IdForExeTests::vault_a_id(),
                vault_b_id: IdForExeTests::vault_b_id(),
                liquidity_pool_id: IdForExeTests::token_lp_definition_id(),
                liquidity_pool_supply: 0,
                reserve_a: 0,
                reserve_b: 0,
                fees: 0_u128,
                active: false,
            }),
            nonce: 0_u128.into(),
        }
    }

    fn user_token_a_holding_new_init() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_a_definition_id(),
                balance: BalanceForExeTests::user_token_a_holding_new_definition(),
            }),
            nonce: 1_u128.into(),
        }
    }

    fn user_token_b_holding_new_init() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_b_definition_id(),
                balance: BalanceForExeTests::user_token_b_holding_new_definition(),
            }),
            nonce: 1_u128.into(),
        }
    }

    fn user_token_lp_holding_new_init() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_lp_definition_id(),
                balance: BalanceForExeTests::lp_supply_init(),
            }),
            nonce: 0_u128.into(),
        }
    }

    fn token_lp_definition_new_init() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenDefinition::Fungible {
                name: String::from("LP Token"),
                total_supply: BalanceForExeTests::lp_supply_init(),
                metadata_id: None,
            }),
            nonce: 0_u128.into(),
        }
    }

    fn pool_definition_new_init() -> Account {
        Account {
            program_owner: Program::amm().id(),
            balance: 0_u128,
            data: Data::from(&PoolDefinition {
                definition_token_a_id: IdForExeTests::token_a_definition_id(),
                definition_token_b_id: IdForExeTests::token_b_definition_id(),
                vault_a_id: IdForExeTests::vault_a_id(),
                vault_b_id: IdForExeTests::vault_b_id(),
                liquidity_pool_id: IdForExeTests::token_lp_definition_id(),
                liquidity_pool_supply: BalanceForExeTests::lp_supply_init(),
                reserve_a: BalanceForExeTests::vault_a_balance_init(),
                reserve_b: BalanceForExeTests::vault_b_balance_init(),
                fees: 0_u128,
                active: true,
            }),
            nonce: 0_u128.into(),
        }
    }

    fn user_token_lp_holding_init_zero() -> Account {
        Account {
            program_owner: Program::token().id(),
            balance: 0_u128,
            data: Data::from(&TokenHolding::Fungible {
                definition_id: IdForExeTests::token_lp_definition_id(),
                balance: 0,
            }),
            nonce: 0_u128.into(),
        }
    }
}

#[test]
fn pool_pda_produces_unique_id_for_token_pair() {
    assert!(
        amm_core::compute_pool_pda(
            AMM_PROGRAM_ID,
            IdForTests::token_a_definition_id(),
            IdForTests::token_b_definition_id()
        ) == compute_pool_pda(
            AMM_PROGRAM_ID,
            IdForTests::token_b_definition_id(),
            IdForTests::token_a_definition_id()
        )
    );
}

#[should_panic(expected = "Vault A was not provided")]
#[test]
fn call_add_liquidity_vault_a_omitted() {
    let _post_states = add_liquidity(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_with_wrong_id(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::add_min_amount_lp()).unwrap(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::add_max_amount_b(),
    );
}

#[should_panic(expected = "Vault B was not provided")]
#[test]
fn call_add_liquidity_vault_b_omitted() {
    let _post_states = add_liquidity(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_with_wrong_id(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::add_min_amount_lp()).unwrap(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::add_max_amount_b(),
    );
}

#[should_panic(expected = "LP definition mismatch")]
#[test]
fn call_add_liquidity_lp_definition_mismatch() {
    let _post_states = add_liquidity(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::pool_lp_with_wrong_id(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::add_min_amount_lp()).unwrap(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::add_max_amount_b(),
    );
}

#[should_panic(expected = "Both max-balances must be nonzero")]
#[test]
fn call_add_liquidity_zero_balance_1() {
    let _post_states = add_liquidity(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::add_min_amount_lp()).unwrap(),
        0,
        BalanceForTests::add_max_amount_b(),
    );
}

#[should_panic(expected = "Both max-balances must be nonzero")]
#[test]
fn call_add_liquidity_zero_balance_2() {
    let _post_states = add_liquidity(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::add_min_amount_lp()).unwrap(),
        0,
        BalanceForTests::add_max_amount_a(),
    );
}

#[should_panic(expected = "Vaults' balances must be at least the reserve amounts")]
#[test]
fn call_add_liquidity_vault_insufficient_balance_1() {
    let _post_states = add_liquidity(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_init_zero(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::add_max_amount_a()).unwrap(),
        BalanceForTests::add_max_amount_b(),
        BalanceForTests::add_min_amount_lp(),
    );
}

#[should_panic(expected = "Vaults' balances must be at least the reserve amounts")]
#[test]
fn call_add_liquidity_vault_insufficient_balance_2() {
    let _post_states = add_liquidity(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init_zero(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::add_max_amount_a()).unwrap(),
        BalanceForTests::add_max_amount_b(),
        BalanceForTests::add_min_amount_lp(),
    );
}

#[should_panic(expected = "A trade amount is 0")]
#[test]
fn call_add_liquidity_actual_amount_zero_1() {
    let _post_states = add_liquidity(
        AccountWithMetadataForTests::pool_definition_init_reserve_a_low(),
        AccountWithMetadataForTests::vault_a_init_low(),
        AccountWithMetadataForTests::vault_b_init_high(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::add_min_amount_lp()).unwrap(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::add_max_amount_b(),
    );
}

#[should_panic(expected = "A trade amount is 0")]
#[test]
fn call_add_liquidity_actual_amount_zero_2() {
    let _post_states = add_liquidity(
        AccountWithMetadataForTests::pool_definition_init_reserve_b_low(),
        AccountWithMetadataForTests::vault_a_init_high(),
        AccountWithMetadataForTests::vault_b_init_low(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::add_min_amount_lp()).unwrap(),
        BalanceForTests::add_max_amount_a_low(),
        BalanceForTests::add_max_amount_b_low(),
    );
}

#[should_panic(expected = "Reserves must be nonzero")]
#[test]
fn call_add_liquidity_reserves_zero_1() {
    let _post_states = add_liquidity(
        AccountWithMetadataForTests::pool_definition_init_reserve_a_zero(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::add_min_amount_lp()).unwrap(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::add_max_amount_b(),
    );
}

#[should_panic(expected = "Reserves must be nonzero")]
#[test]
fn call_add_liquidity_reserves_zero_2() {
    let _post_states = add_liquidity(
        AccountWithMetadataForTests::pool_definition_init_reserve_b_zero(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::add_min_amount_lp()).unwrap(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::add_max_amount_b(),
    );
}

#[should_panic(expected = "Payable LP must be nonzero")]
#[test]
fn call_add_liquidity_payable_lp_zero() {
    let _post_states = add_liquidity(
        AccountWithMetadataForTests::pool_definition_add_zero_lp(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::add_min_amount_lp()).unwrap(),
        BalanceForTests::add_max_amount_a_low(),
        BalanceForTests::add_max_amount_b_low(),
    );
}

#[test]
fn call_add_liquidity_chained_call_successsful() {
    let (post_states, chained_calls) = add_liquidity(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::add_min_amount_lp()).unwrap(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::add_max_amount_b(),
    );

    let pool_post = post_states[0].clone();

    assert!(
        AccountWithMetadataForTests::pool_definition_add_successful().account
            == *pool_post.account()
    );

    let chained_call_lp = chained_calls[0].clone();
    let chained_call_b = chained_calls[1].clone();
    let chained_call_a = chained_calls[2].clone();

    assert!(chained_call_a == ChainedCallForTests::cc_add_token_a());
    assert!(chained_call_b == ChainedCallForTests::cc_add_token_b());
    assert!(chained_call_lp == ChainedCallForTests::cc_add_pool_lp());
}

#[should_panic(expected = "Vault A was not provided")]
#[test]
fn call_remove_liquidity_vault_a_omitted() {
    let _post_states = remove_liquidity(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_with_wrong_id(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::remove_amount_lp()).unwrap(),
        BalanceForTests::remove_min_amount_a(),
        BalanceForTests::remove_min_amount_b(),
    );
}

#[should_panic(expected = "Vault B was not provided")]
#[test]
fn call_remove_liquidity_vault_b_omitted() {
    let _post_states = remove_liquidity(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_with_wrong_id(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::remove_amount_lp()).unwrap(),
        BalanceForTests::remove_min_amount_a(),
        BalanceForTests::remove_min_amount_b(),
    );
}

#[should_panic(expected = "LP definition mismatch")]
#[test]
fn call_remove_liquidity_lp_def_mismatch() {
    let _post_states = remove_liquidity(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::pool_lp_with_wrong_id(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::remove_amount_lp()).unwrap(),
        BalanceForTests::remove_min_amount_a(),
        BalanceForTests::remove_min_amount_b(),
    );
}

#[should_panic(expected = "Invalid liquidity account provided")]
#[test]
fn call_remove_liquidity_insufficient_liquidity_amount() {
    let _post_states = remove_liquidity(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_a(), /* different token account than lp to
                                                        * create desired
                                                        * error */
        NonZero::new(BalanceForTests::remove_amount_lp()).unwrap(),
        BalanceForTests::remove_min_amount_a(),
        BalanceForTests::remove_min_amount_b(),
    );
}

#[should_panic(
    expected = "Insufficient minimal withdraw amount (Token A) provided for liquidity amount"
)]
#[test]
fn call_remove_liquidity_insufficient_balance_1() {
    let _post_states = remove_liquidity(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::remove_amount_lp_1()).unwrap(),
        BalanceForTests::remove_min_amount_a(),
        BalanceForTests::remove_min_amount_b(),
    );
}

#[should_panic(
    expected = "Insufficient minimal withdraw amount (Token B) provided for liquidity amount"
)]
#[test]
fn call_remove_liquidity_insufficient_balance_2() {
    let _post_states = remove_liquidity(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::remove_amount_lp()).unwrap(),
        BalanceForTests::remove_min_amount_a(),
        BalanceForTests::remove_min_amount_b(),
    );
}

#[should_panic(expected = "Minimum withdraw amount must be nonzero")]
#[test]
fn call_remove_liquidity_min_bal_zero_1() {
    let _post_states = remove_liquidity(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::remove_amount_lp()).unwrap(),
        0,
        BalanceForTests::remove_min_amount_b(),
    );
}

#[should_panic(expected = "Minimum withdraw amount must be nonzero")]
#[test]
fn call_remove_liquidity_min_bal_zero_2() {
    let _post_states = remove_liquidity(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::remove_amount_lp()).unwrap(),
        BalanceForTests::remove_min_amount_a(),
        0,
    );
}

#[test]
fn call_remove_liquidity_chained_call_successful() {
    let (post_states, chained_calls) = remove_liquidity(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::remove_amount_lp()).unwrap(),
        BalanceForTests::remove_min_amount_a(),
        BalanceForTests::remove_min_amount_b_low(),
    );

    let pool_post = post_states[0].clone();

    assert!(
        AccountWithMetadataForTests::pool_definition_remove_successful().account
            == *pool_post.account()
    );

    let chained_call_lp = chained_calls[0].clone();
    let chained_call_b = chained_calls[1].clone();
    let chained_call_a = chained_calls[2].clone();

    assert!(chained_call_a == ChainedCallForTests::cc_remove_token_a());
    assert!(chained_call_b == ChainedCallForTests::cc_remove_token_b());
    assert!(chained_call_lp == ChainedCallForTests::cc_remove_pool_lp());
}

#[should_panic(expected = "Balances must be nonzero")]
#[test]
fn call_new_definition_with_zero_balance_1() {
    let _post_states = new_definition(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_uninit(),
        NonZero::new(0).expect("Balances must be nonzero"),
        NonZero::new(BalanceForTests::vault_b_reserve_init()).unwrap(),
        AMM_PROGRAM_ID,
    );
}

#[should_panic(expected = "Balances must be nonzero")]
#[test]
fn call_new_definition_with_zero_balance_2() {
    let _post_states = new_definition(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_uninit(),
        NonZero::new(BalanceForTests::vault_a_reserve_init()).unwrap(),
        NonZero::new(0).expect("Balances must be nonzero"),
        AMM_PROGRAM_ID,
    );
}

#[should_panic(expected = "Cannot set up a swap for a token with itself")]
#[test]
fn call_new_definition_same_token_definition() {
    let _post_states = new_definition(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_lp_uninit(),
        NonZero::new(BalanceForTests::vault_a_reserve_init()).unwrap(),
        NonZero::new(BalanceForTests::vault_b_reserve_init()).unwrap(),
        AMM_PROGRAM_ID,
    );
}

#[should_panic(expected = "Liquidity pool Token Definition Account ID does not match PDA")]
#[test]
fn call_new_definition_wrong_liquidity_id() {
    let _post_states = new_definition(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::pool_lp_with_wrong_id(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_uninit(),
        NonZero::new(BalanceForTests::vault_a_reserve_init()).unwrap(),
        NonZero::new(BalanceForTests::vault_b_reserve_init()).unwrap(),
        AMM_PROGRAM_ID,
    );
}

#[should_panic(expected = "Pool Definition Account ID does not match PDA")]
#[test]
fn call_new_definition_wrong_pool_id() {
    let _post_states = new_definition(
        AccountWithMetadataForTests::pool_definition_with_wrong_id(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_uninit(),
        NonZero::new(BalanceForTests::vault_a_reserve_init()).unwrap(),
        NonZero::new(BalanceForTests::vault_b_reserve_init()).unwrap(),
        AMM_PROGRAM_ID,
    );
}

#[should_panic(expected = "Vault ID does not match PDA")]
#[test]
fn call_new_definition_wrong_vault_id_1() {
    let _post_states = new_definition(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_with_wrong_id(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_uninit(),
        NonZero::new(BalanceForTests::vault_a_reserve_init()).unwrap(),
        NonZero::new(BalanceForTests::vault_b_reserve_init()).unwrap(),
        AMM_PROGRAM_ID,
    );
}

#[should_panic(expected = "Vault ID does not match PDA")]
#[test]
fn call_new_definition_wrong_vault_id_2() {
    let _post_states = new_definition(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_with_wrong_id(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_uninit(),
        NonZero::new(BalanceForTests::vault_a_reserve_init()).unwrap(),
        NonZero::new(BalanceForTests::vault_b_reserve_init()).unwrap(),
        AMM_PROGRAM_ID,
    );
}

#[should_panic(expected = "Cannot initialize an active Pool Definition")]
#[test]
fn call_new_definition_cannot_initialize_active_pool() {
    let _post_states = new_definition(
        AccountWithMetadataForTests::pool_definition_active(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_uninit(),
        NonZero::new(BalanceForTests::vault_a_reserve_init()).unwrap(),
        NonZero::new(BalanceForTests::vault_b_reserve_init()).unwrap(),
        AMM_PROGRAM_ID,
    );
}

#[should_panic(expected = "Cannot initialize an active Pool Definition")]
#[test]
fn call_new_definition_chained_call_successful() {
    let (post_states, chained_calls) = new_definition(
        AccountWithMetadataForTests::pool_definition_active(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_uninit(),
        NonZero::new(BalanceForTests::vault_a_reserve_init()).unwrap(),
        NonZero::new(BalanceForTests::vault_b_reserve_init()).unwrap(),
        AMM_PROGRAM_ID,
    );

    let pool_post = post_states[0].clone();

    assert!(
        AccountWithMetadataForTests::pool_definition_add_successful().account
            == *pool_post.account()
    );

    let chained_call_lp = chained_calls[0].clone();
    let chained_call_b = chained_calls[1].clone();
    let chained_call_a = chained_calls[2].clone();

    assert!(chained_call_a == ChainedCallForTests::cc_new_definition_token_a());
    assert!(chained_call_b == ChainedCallForTests::cc_new_definition_token_b());
    assert!(chained_call_lp == ChainedCallForTests::cc_new_definition_token_lp());
}

#[should_panic(expected = "AccountId is not a token type for the pool")]
#[test]
fn call_swap_incorrect_token_type() {
    let _post_states = swap(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::min_amount_out(),
        IdForTests::token_lp_definition_id(),
    );
}

#[should_panic(expected = "Vault A was not provided")]
#[test]
fn call_swap_vault_a_omitted() {
    let _post_states = swap(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_with_wrong_id(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::min_amount_out(),
        IdForTests::token_a_definition_id(),
    );
}

#[should_panic(expected = "Vault B was not provided")]
#[test]
fn call_swap_vault_b_omitted() {
    let _post_states = swap(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_with_wrong_id(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::min_amount_out(),
        IdForTests::token_a_definition_id(),
    );
}

#[should_panic(expected = "Reserve for Token A exceeds vault balance")]
#[test]
fn call_swap_reserves_vault_mismatch_1() {
    let _post_states = swap(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_init_low(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::min_amount_out(),
        IdForTests::token_a_definition_id(),
    );
}

#[should_panic(expected = "Reserve for Token B exceeds vault balance")]
#[test]
fn call_swap_reserves_vault_mismatch_2() {
    let _post_states = swap(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init_low(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::min_amount_out(),
        IdForTests::token_a_definition_id(),
    );
}

#[should_panic(expected = "Pool is inactive")]
#[test]
fn call_swap_ianctive() {
    let _post_states = swap(
        AccountWithMetadataForTests::pool_definition_inactive(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::min_amount_out(),
        IdForTests::token_a_definition_id(),
    );
}

#[should_panic(expected = "Withdraw amount is less than minimal amount out")]
#[test]
fn call_swap_below_min_out() {
    let _post_states = swap(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::min_amount_out(),
        IdForTests::token_a_definition_id(),
    );
}

#[test]
fn call_swap_chained_call_successful_1() {
    let (post_states, chained_calls) = swap(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::add_max_amount_a_low(),
        IdForTests::token_a_definition_id(),
    );

    let pool_post = post_states[0].clone();

    assert!(
        AccountWithMetadataForTests::pool_definition_swap_test_1().account == *pool_post.account()
    );

    let chained_call_a = chained_calls[0].clone();
    let chained_call_b = chained_calls[1].clone();

    assert_eq!(
        chained_call_a,
        ChainedCallForTests::cc_swap_token_a_test_1()
    );
    assert_eq!(
        chained_call_b,
        ChainedCallForTests::cc_swap_token_b_test_1()
    );
}

#[test]
fn call_swap_chained_call_successful_2() {
    let (post_states, chained_calls) = swap(
        AccountWithMetadataForTests::pool_definition_init(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        BalanceForTests::add_max_amount_b(),
        BalanceForTests::min_amount_out(),
        IdForTests::token_b_definition_id(),
    );

    let pool_post = post_states[0].clone();

    assert!(
        AccountWithMetadataForTests::pool_definition_swap_test_2().account == *pool_post.account()
    );

    let chained_call_a = chained_calls[1].clone();
    let chained_call_b = chained_calls[0].clone();

    assert_eq!(
        chained_call_a,
        ChainedCallForTests::cc_swap_token_a_test_2()
    );
    assert_eq!(
        chained_call_b,
        ChainedCallForTests::cc_swap_token_b_test_2()
    );
}

#[test]
fn new_definition_lp_asymmetric_amounts() {
    let (post_states, chained_calls) = new_definition(
        AccountWithMetadataForTests::pool_definition_inactive(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_uninit(),
        NonZero::new(BalanceForTests::vault_a_reserve_init()).unwrap(),
        NonZero::new(BalanceForTests::vault_b_reserve_init()).unwrap(),
        AMM_PROGRAM_ID,
    );

    // check the minted LP amount
    let pool_post = post_states[0].clone();
    let pool_def = PoolDefinition::try_from(&pool_post.account().data).unwrap();
    assert_eq!(
        pool_def.liquidity_pool_supply,
        BalanceForTests::lp_supply_init()
    );

    let chained_call_lp = chained_calls[0].clone();
    assert!(chained_call_lp == ChainedCallForTests::cc_new_definition_token_lp());
}

#[test]
fn new_definition_lp_symmetric_amounts() {
    // token_a=100, token_b=100 → LP=sqrt(10_000)=100
    let token_a_amount = 100_u128;
    let token_b_amount = 100_u128;
    let expected_lp = (token_a_amount * token_b_amount).isqrt();
    assert_eq!(expected_lp, 100);

    let (post_states, chained_calls) = new_definition(
        AccountWithMetadataForTests::pool_definition_inactive(),
        AccountWithMetadataForTests::vault_a_init(),
        AccountWithMetadataForTests::vault_b_init(),
        AccountWithMetadataForTests::pool_lp_init(),
        AccountWithMetadataForTests::user_holding_a(),
        AccountWithMetadataForTests::user_holding_b(),
        AccountWithMetadataForTests::user_holding_lp_uninit(),
        NonZero::new(token_a_amount).unwrap(),
        NonZero::new(token_b_amount).unwrap(),
        AMM_PROGRAM_ID,
    );

    let pool_post = post_states[0].clone();
    let pool_def = PoolDefinition::try_from(&pool_post.account().data).unwrap();
    assert_eq!(pool_def.liquidity_pool_supply, expected_lp);

    let chained_call_lp = chained_calls[0].clone();
    let expected_lp_call = ChainedCall::new(
        TOKEN_PROGRAM_ID,
        vec![
            AccountWithMetadataForTests::pool_lp_init(),
            AccountWithMetadataForTests::user_holding_lp_uninit(),
        ],
        &token_core::Instruction::Mint {
            amount_to_mint: expected_lp,
        },
    )
    .with_pda_seeds(vec![compute_liquidity_token_pda_seed(
        IdForTests::pool_definition_id(),
    )]);

    assert_eq!(chained_call_lp, expected_lp_call);
}

fn state_for_amm_tests() -> V02State {
    let initial_data = [];
    let mut state = V02State::new_with_genesis_accounts(&initial_data, &[]);
    state.force_insert_account(
        IdForExeTests::pool_definition_id(),
        AccountsForExeTests::pool_definition_init(),
    );
    state.force_insert_account(
        IdForExeTests::token_a_definition_id(),
        AccountsForExeTests::token_a_definition_account(),
    );
    state.force_insert_account(
        IdForExeTests::token_b_definition_id(),
        AccountsForExeTests::token_b_definition_acc(),
    );
    state.force_insert_account(
        IdForExeTests::token_lp_definition_id(),
        AccountsForExeTests::token_lp_definition_acc(),
    );
    state.force_insert_account(
        IdForExeTests::user_token_a_id(),
        AccountsForExeTests::user_token_a_holding(),
    );
    state.force_insert_account(
        IdForExeTests::user_token_b_id(),
        AccountsForExeTests::user_token_b_holding(),
    );
    state.force_insert_account(
        IdForExeTests::user_token_lp_id(),
        AccountsForExeTests::user_token_lp_holding(),
    );
    state.force_insert_account(
        IdForExeTests::vault_a_id(),
        AccountsForExeTests::vault_a_init(),
    );
    state.force_insert_account(
        IdForExeTests::vault_b_id(),
        AccountsForExeTests::vault_b_init(),
    );

    state
}

fn state_for_amm_tests_with_new_def() -> V02State {
    let initial_data = [];
    let mut state = V02State::new_with_genesis_accounts(&initial_data, &[]);
    state.force_insert_account(
        IdForExeTests::token_a_definition_id(),
        AccountsForExeTests::token_a_definition_account(),
    );
    state.force_insert_account(
        IdForExeTests::token_b_definition_id(),
        AccountsForExeTests::token_b_definition_acc(),
    );
    state.force_insert_account(
        IdForExeTests::user_token_a_id(),
        AccountsForExeTests::user_token_a_holding(),
    );
    state.force_insert_account(
        IdForExeTests::user_token_b_id(),
        AccountsForExeTests::user_token_b_holding(),
    );
    state
}

#[test]
fn simple_amm_remove() {
    let mut state = state_for_amm_tests();

    let instruction = amm_core::Instruction::RemoveLiquidity {
        remove_liquidity_amount: BalanceForExeTests::remove_lp(),
        min_amount_to_remove_token_a: BalanceForExeTests::remove_min_amount_a(),
        min_amount_to_remove_token_b: BalanceForExeTests::remove_min_amount_b(),
    };

    let message = public_transaction::Message::try_new(
        Program::amm().id(),
        vec![
            IdForExeTests::pool_definition_id(),
            IdForExeTests::vault_a_id(),
            IdForExeTests::vault_b_id(),
            IdForExeTests::token_lp_definition_id(),
            IdForExeTests::user_token_a_id(),
            IdForExeTests::user_token_b_id(),
            IdForExeTests::user_token_lp_id(),
        ],
        vec![0_u128.into()],
        instruction,
    )
    .unwrap();

    let witness_set = public_transaction::WitnessSet::for_message(
        &message,
        &[&PrivateKeysForTests::user_token_lp_key()],
    );

    let tx = PublicTransaction::new(message, witness_set);
    state.transition_from_public_transaction(&tx).unwrap();

    let pool_post = state.get_account_by_id(IdForExeTests::pool_definition_id());
    let vault_a_post = state.get_account_by_id(IdForExeTests::vault_a_id());
    let vault_b_post = state.get_account_by_id(IdForExeTests::vault_b_id());
    let token_lp_post = state.get_account_by_id(IdForExeTests::token_lp_definition_id());
    let user_token_a_post = state.get_account_by_id(IdForExeTests::user_token_a_id());
    let user_token_b_post = state.get_account_by_id(IdForExeTests::user_token_b_id());
    let user_token_lp_post = state.get_account_by_id(IdForExeTests::user_token_lp_id());

    let expected_pool = AccountsForExeTests::pool_definition_remove();
    let expected_vault_a = AccountsForExeTests::vault_a_remove();
    let expected_vault_b = AccountsForExeTests::vault_b_remove();
    let expected_token_lp = AccountsForExeTests::token_lp_definition_remove();
    let expected_user_token_a = AccountsForExeTests::user_token_a_holding_remove();
    let expected_user_token_b = AccountsForExeTests::user_token_b_holding_remove();
    let expected_user_token_lp = AccountsForExeTests::user_token_lp_holding_remove();

    assert_eq!(pool_post, expected_pool);
    assert_eq!(vault_a_post, expected_vault_a);
    assert_eq!(vault_b_post, expected_vault_b);
    assert_eq!(token_lp_post, expected_token_lp);
    assert_eq!(user_token_a_post, expected_user_token_a);
    assert_eq!(user_token_b_post, expected_user_token_b);
    assert_eq!(user_token_lp_post, expected_user_token_lp);
}

#[test]
fn simple_amm_new_definition_inactive_initialized_pool_and_uninit_user_lp() {
    let mut state = state_for_amm_tests_with_new_def();

    // Uninitialized in constructor
    state.force_insert_account(
        IdForExeTests::vault_a_id(),
        AccountsForExeTests::vault_a_init_inactive(),
    );
    state.force_insert_account(
        IdForExeTests::vault_b_id(),
        AccountsForExeTests::vault_b_init_inactive(),
    );
    state.force_insert_account(
        IdForExeTests::pool_definition_id(),
        AccountsForExeTests::pool_definition_inactive(),
    );
    state.force_insert_account(
        IdForExeTests::token_lp_definition_id(),
        AccountsForExeTests::token_lp_definition_init_inactive(),
    );

    let instruction = amm_core::Instruction::NewDefinition {
        token_a_amount: BalanceForExeTests::vault_a_balance_init(),
        token_b_amount: BalanceForExeTests::vault_b_balance_init(),
        amm_program_id: Program::amm().id(),
    };

    let message = public_transaction::Message::try_new(
        Program::amm().id(),
        vec![
            IdForExeTests::pool_definition_id(),
            IdForExeTests::vault_a_id(),
            IdForExeTests::vault_b_id(),
            IdForExeTests::token_lp_definition_id(),
            IdForExeTests::user_token_a_id(),
            IdForExeTests::user_token_b_id(),
            IdForExeTests::user_token_lp_id(),
        ],
        vec![0_u128.into(), 0_u128.into()],
        instruction,
    )
    .unwrap();

    let witness_set = public_transaction::WitnessSet::for_message(
        &message,
        &[
            &PrivateKeysForTests::user_token_a_key(),
            &PrivateKeysForTests::user_token_b_key(),
        ],
    );

    let tx = PublicTransaction::new(message, witness_set);
    state.transition_from_public_transaction(&tx).unwrap();

    let pool_post = state.get_account_by_id(IdForExeTests::pool_definition_id());
    let vault_a_post = state.get_account_by_id(IdForExeTests::vault_a_id());
    let vault_b_post = state.get_account_by_id(IdForExeTests::vault_b_id());
    let token_lp_post = state.get_account_by_id(IdForExeTests::token_lp_definition_id());
    let user_token_a_post = state.get_account_by_id(IdForExeTests::user_token_a_id());
    let user_token_b_post = state.get_account_by_id(IdForExeTests::user_token_b_id());
    let user_token_lp_post = state.get_account_by_id(IdForExeTests::user_token_lp_id());

    let expected_pool = AccountsForExeTests::pool_definition_new_init();
    let expected_vault_a = AccountsForExeTests::vault_a_init();
    let expected_vault_b = AccountsForExeTests::vault_b_init();
    let expected_token_lp = AccountsForExeTests::token_lp_definition_new_init();
    let expected_user_token_a = AccountsForExeTests::user_token_a_holding_new_init();
    let expected_user_token_b = AccountsForExeTests::user_token_b_holding_new_init();
    let expected_user_token_lp = AccountsForExeTests::user_token_lp_holding_new_init();

    assert_eq!(pool_post, expected_pool);
    assert_eq!(vault_a_post, expected_vault_a);
    assert_eq!(vault_b_post, expected_vault_b);
    assert_eq!(token_lp_post, expected_token_lp);
    assert_eq!(user_token_a_post, expected_user_token_a);
    assert_eq!(user_token_b_post, expected_user_token_b);
    assert_eq!(user_token_lp_post, expected_user_token_lp);
}

#[test]
fn simple_amm_new_definition_inactive_initialized_pool_init_user_lp() {
    let mut state = state_for_amm_tests_with_new_def();

    // Uninitialized in constructor
    state.force_insert_account(
        IdForExeTests::vault_a_id(),
        AccountsForExeTests::vault_a_init_inactive(),
    );
    state.force_insert_account(
        IdForExeTests::vault_b_id(),
        AccountsForExeTests::vault_b_init_inactive(),
    );
    state.force_insert_account(
        IdForExeTests::pool_definition_id(),
        AccountsForExeTests::pool_definition_inactive(),
    );
    state.force_insert_account(
        IdForExeTests::token_lp_definition_id(),
        AccountsForExeTests::token_lp_definition_init_inactive(),
    );
    state.force_insert_account(
        IdForExeTests::user_token_lp_id(),
        AccountsForExeTests::user_token_lp_holding_init_zero(),
    );

    let instruction = amm_core::Instruction::NewDefinition {
        token_a_amount: BalanceForExeTests::vault_a_balance_init(),
        token_b_amount: BalanceForExeTests::vault_b_balance_init(),
        amm_program_id: Program::amm().id(),
    };

    let message = public_transaction::Message::try_new(
        Program::amm().id(),
        vec![
            IdForExeTests::pool_definition_id(),
            IdForExeTests::vault_a_id(),
            IdForExeTests::vault_b_id(),
            IdForExeTests::token_lp_definition_id(),
            IdForExeTests::user_token_a_id(),
            IdForExeTests::user_token_b_id(),
            IdForExeTests::user_token_lp_id(),
        ],
        vec![0_u128.into(), 0_u128.into()],
        instruction,
    )
    .unwrap();

    let witness_set = public_transaction::WitnessSet::for_message(
        &message,
        &[
            &PrivateKeysForTests::user_token_a_key(),
            &PrivateKeysForTests::user_token_b_key(),
        ],
    );

    let tx = PublicTransaction::new(message, witness_set);
    state.transition_from_public_transaction(&tx).unwrap();

    let pool_post = state.get_account_by_id(IdForExeTests::pool_definition_id());
    let vault_a_post = state.get_account_by_id(IdForExeTests::vault_a_id());
    let vault_b_post = state.get_account_by_id(IdForExeTests::vault_b_id());
    let token_lp_post = state.get_account_by_id(IdForExeTests::token_lp_definition_id());
    let user_token_a_post = state.get_account_by_id(IdForExeTests::user_token_a_id());
    let user_token_b_post = state.get_account_by_id(IdForExeTests::user_token_b_id());
    let user_token_lp_post = state.get_account_by_id(IdForExeTests::user_token_lp_id());

    let expected_pool = AccountsForExeTests::pool_definition_new_init();
    let expected_vault_a = AccountsForExeTests::vault_a_init();
    let expected_vault_b = AccountsForExeTests::vault_b_init();
    let expected_token_lp = AccountsForExeTests::token_lp_definition_new_init();
    let expected_user_token_a = AccountsForExeTests::user_token_a_holding_new_init();
    let expected_user_token_b = AccountsForExeTests::user_token_b_holding_new_init();
    let expected_user_token_lp = AccountsForExeTests::user_token_lp_holding_new_init();

    assert_eq!(pool_post, expected_pool);
    assert_eq!(vault_a_post, expected_vault_a);
    assert_eq!(vault_b_post, expected_vault_b);
    assert_eq!(token_lp_post, expected_token_lp);
    assert_eq!(user_token_a_post, expected_user_token_a);
    assert_eq!(user_token_b_post, expected_user_token_b);
    assert_eq!(user_token_lp_post, expected_user_token_lp);
}

#[test]
fn simple_amm_new_definition_uninitialized_pool() {
    let mut state = state_for_amm_tests_with_new_def();

    // Uninitialized in constructor
    state.force_insert_account(
        IdForExeTests::vault_a_id(),
        AccountsForExeTests::vault_a_init_inactive(),
    );
    state.force_insert_account(
        IdForExeTests::vault_b_id(),
        AccountsForExeTests::vault_b_init_inactive(),
    );

    let instruction = amm_core::Instruction::NewDefinition {
        token_a_amount: BalanceForExeTests::vault_a_balance_init(),
        token_b_amount: BalanceForExeTests::vault_b_balance_init(),
        amm_program_id: Program::amm().id(),
    };

    let message = public_transaction::Message::try_new(
        Program::amm().id(),
        vec![
            IdForExeTests::pool_definition_id(),
            IdForExeTests::vault_a_id(),
            IdForExeTests::vault_b_id(),
            IdForExeTests::token_lp_definition_id(),
            IdForExeTests::user_token_a_id(),
            IdForExeTests::user_token_b_id(),
            IdForExeTests::user_token_lp_id(),
        ],
        vec![0_u128.into(), 0_u128.into()],
        instruction,
    )
    .unwrap();

    let witness_set = public_transaction::WitnessSet::for_message(
        &message,
        &[
            &PrivateKeysForTests::user_token_a_key(),
            &PrivateKeysForTests::user_token_b_key(),
        ],
    );

    let tx = PublicTransaction::new(message, witness_set);
    state.transition_from_public_transaction(&tx).unwrap();

    let pool_post = state.get_account_by_id(IdForExeTests::pool_definition_id());
    let vault_a_post = state.get_account_by_id(IdForExeTests::vault_a_id());
    let vault_b_post = state.get_account_by_id(IdForExeTests::vault_b_id());
    let token_lp_post = state.get_account_by_id(IdForExeTests::token_lp_definition_id());
    let user_token_a_post = state.get_account_by_id(IdForExeTests::user_token_a_id());
    let user_token_b_post = state.get_account_by_id(IdForExeTests::user_token_b_id());
    let user_token_lp_post = state.get_account_by_id(IdForExeTests::user_token_lp_id());

    let expected_pool = AccountsForExeTests::pool_definition_new_init();
    let expected_vault_a = AccountsForExeTests::vault_a_init();
    let expected_vault_b = AccountsForExeTests::vault_b_init();
    let expected_token_lp = AccountsForExeTests::token_lp_definition_new_init();
    let expected_user_token_a = AccountsForExeTests::user_token_a_holding_new_init();
    let expected_user_token_b = AccountsForExeTests::user_token_b_holding_new_init();
    let expected_user_token_lp = AccountsForExeTests::user_token_lp_holding_new_init();

    assert_eq!(pool_post, expected_pool);
    assert_eq!(vault_a_post, expected_vault_a);
    assert_eq!(vault_b_post, expected_vault_b);
    assert_eq!(token_lp_post, expected_token_lp);
    assert_eq!(user_token_a_post, expected_user_token_a);
    assert_eq!(user_token_b_post, expected_user_token_b);
    assert_eq!(user_token_lp_post, expected_user_token_lp);
}

#[test]
fn simple_amm_add() {
    let mut state = state_for_amm_tests();

    let instruction = amm_core::Instruction::AddLiquidity {
        min_amount_liquidity: BalanceForExeTests::add_min_amount_lp(),
        max_amount_to_add_token_a: BalanceForExeTests::add_max_amount_a(),
        max_amount_to_add_token_b: BalanceForExeTests::add_max_amount_b(),
    };

    let message = public_transaction::Message::try_new(
        Program::amm().id(),
        vec![
            IdForExeTests::pool_definition_id(),
            IdForExeTests::vault_a_id(),
            IdForExeTests::vault_b_id(),
            IdForExeTests::token_lp_definition_id(),
            IdForExeTests::user_token_a_id(),
            IdForExeTests::user_token_b_id(),
            IdForExeTests::user_token_lp_id(),
        ],
        vec![0_u128.into(), 0_u128.into()],
        instruction,
    )
    .unwrap();

    let witness_set = public_transaction::WitnessSet::for_message(
        &message,
        &[
            &PrivateKeysForTests::user_token_a_key(),
            &PrivateKeysForTests::user_token_b_key(),
        ],
    );

    let tx = PublicTransaction::new(message, witness_set);
    state.transition_from_public_transaction(&tx).unwrap();

    let pool_post = state.get_account_by_id(IdForExeTests::pool_definition_id());
    let vault_a_post = state.get_account_by_id(IdForExeTests::vault_a_id());
    let vault_b_post = state.get_account_by_id(IdForExeTests::vault_b_id());
    let token_lp_post = state.get_account_by_id(IdForExeTests::token_lp_definition_id());
    let user_token_a_post = state.get_account_by_id(IdForExeTests::user_token_a_id());
    let user_token_b_post = state.get_account_by_id(IdForExeTests::user_token_b_id());
    let user_token_lp_post = state.get_account_by_id(IdForExeTests::user_token_lp_id());

    let expected_pool = AccountsForExeTests::pool_definition_add();
    let expected_vault_a = AccountsForExeTests::vault_a_add();
    let expected_vault_b = AccountsForExeTests::vault_b_add();
    let expected_token_lp = AccountsForExeTests::token_lp_definition_add();
    let expected_user_token_a = AccountsForExeTests::user_token_a_holding_add();
    let expected_user_token_b = AccountsForExeTests::user_token_b_holding_add();
    let expected_user_token_lp = AccountsForExeTests::user_token_lp_holding_add();

    assert_eq!(pool_post, expected_pool);
    assert_eq!(vault_a_post, expected_vault_a);
    assert_eq!(vault_b_post, expected_vault_b);
    assert_eq!(token_lp_post, expected_token_lp);
    assert_eq!(user_token_a_post, expected_user_token_a);
    assert_eq!(user_token_b_post, expected_user_token_b);
    assert_eq!(user_token_lp_post, expected_user_token_lp);
}

#[test]
fn simple_amm_swap_1() {
    let mut state = state_for_amm_tests();

    let instruction = amm_core::Instruction::Swap {
        swap_amount_in: BalanceForExeTests::swap_amount_in(),
        min_amount_out: BalanceForExeTests::swap_min_amount_out(),
        token_definition_id_in: IdForExeTests::token_b_definition_id(),
    };

    let message = public_transaction::Message::try_new(
        Program::amm().id(),
        vec![
            IdForExeTests::pool_definition_id(),
            IdForExeTests::vault_a_id(),
            IdForExeTests::vault_b_id(),
            IdForExeTests::user_token_a_id(),
            IdForExeTests::user_token_b_id(),
        ],
        vec![0_u128.into()],
        instruction,
    )
    .unwrap();

    let witness_set = public_transaction::WitnessSet::for_message(
        &message,
        &[&PrivateKeysForTests::user_token_b_key()],
    );

    let tx = PublicTransaction::new(message, witness_set);
    state.transition_from_public_transaction(&tx).unwrap();

    let pool_post = state.get_account_by_id(IdForExeTests::pool_definition_id());
    let vault_a_post = state.get_account_by_id(IdForExeTests::vault_a_id());
    let vault_b_post = state.get_account_by_id(IdForExeTests::vault_b_id());
    let user_token_a_post = state.get_account_by_id(IdForExeTests::user_token_a_id());
    let user_token_b_post = state.get_account_by_id(IdForExeTests::user_token_b_id());

    let expected_pool = AccountsForExeTests::pool_definition_swap_1();
    let expected_vault_a = AccountsForExeTests::vault_a_swap_1();
    let expected_vault_b = AccountsForExeTests::vault_b_swap_1();
    let expected_user_token_a = AccountsForExeTests::user_token_a_holding_swap_1();
    let expected_user_token_b = AccountsForExeTests::user_token_b_holding_swap_1();

    assert_eq!(pool_post, expected_pool);
    assert_eq!(vault_a_post, expected_vault_a);
    assert_eq!(vault_b_post, expected_vault_b);
    assert_eq!(user_token_a_post, expected_user_token_a);
    assert_eq!(user_token_b_post, expected_user_token_b);
}

#[test]
fn simple_amm_swap_2() {
    let mut state = state_for_amm_tests();

    let instruction = amm_core::Instruction::Swap {
        swap_amount_in: BalanceForExeTests::swap_amount_in(),
        min_amount_out: BalanceForExeTests::swap_min_amount_out(),
        token_definition_id_in: IdForExeTests::token_a_definition_id(),
    };
    let message = public_transaction::Message::try_new(
        Program::amm().id(),
        vec![
            IdForExeTests::pool_definition_id(),
            IdForExeTests::vault_a_id(),
            IdForExeTests::vault_b_id(),
            IdForExeTests::user_token_a_id(),
            IdForExeTests::user_token_b_id(),
        ],
        vec![0_u128.into()],
        instruction,
    )
    .unwrap();

    let witness_set = public_transaction::WitnessSet::for_message(
        &message,
        &[&PrivateKeysForTests::user_token_a_key()],
    );

    let tx = PublicTransaction::new(message, witness_set);
    state.transition_from_public_transaction(&tx).unwrap();

    let pool_post = state.get_account_by_id(IdForExeTests::pool_definition_id());
    let vault_a_post = state.get_account_by_id(IdForExeTests::vault_a_id());
    let vault_b_post = state.get_account_by_id(IdForExeTests::vault_b_id());
    let user_token_a_post = state.get_account_by_id(IdForExeTests::user_token_a_id());
    let user_token_b_post = state.get_account_by_id(IdForExeTests::user_token_b_id());

    let expected_pool = AccountsForExeTests::pool_definition_swap_2();
    let expected_vault_a = AccountsForExeTests::vault_a_swap_2();
    let expected_vault_b = AccountsForExeTests::vault_b_swap_2();
    let expected_user_token_a = AccountsForExeTests::user_token_a_holding_swap_2();
    let expected_user_token_b = AccountsForExeTests::user_token_b_holding_swap_2();

    assert_eq!(pool_post, expected_pool);
    assert_eq!(vault_a_post, expected_vault_a);
    assert_eq!(vault_b_post, expected_vault_b);
    assert_eq!(user_token_a_post, expected_user_token_a);
    assert_eq!(user_token_b_post, expected_user_token_b);
}
