#![cfg(test)]

use std::num::NonZero;

use amm_core::{
    MINIMUM_LIQUIDITY, PoolDefinition, RecoverSurplusMode, compute_liquidity_token_pda,
    compute_liquidity_token_pda_seed, compute_lp_lock_holding_pda, compute_pool_pda,
    compute_vault_pda, compute_vault_pda_seed,
};
use nssa_core::{
    account::{Account, AccountId, AccountWithMetadata, Data},
    program::{ChainedCall, ProgramId},
};
use token_core::{TokenDefinition, TokenHolding};

use crate::{
    add::add_liquidity, new_definition::new_definition, recover::recover_surplus,
    remove::remove_liquidity, swap::swap, sync::sync_reserves,
};

const TOKEN_PROGRAM_ID: ProgramId = [15; 8];
const AMM_PROGRAM_ID: ProgramId = [42; 8];

struct BalanceForTests;
struct ChainedCallForTests;
struct IdForTests;
struct AccountForTests;

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
        (BalanceForTests::vault_a_reserve_init() * BalanceForTests::vault_b_reserve_init()).isqrt()
    }

    fn lp_user_init() -> u128 {
        BalanceForTests::lp_supply_init() - MINIMUM_LIQUIDITY
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
                AccountForTests::user_holding_a(),
                AccountForTests::vault_a_init(),
            ],
            &token_core::Instruction::Transfer {
                amount_to_transfer: BalanceForTests::add_max_amount_a(),
            },
        )
    }

    fn cc_swap_token_b_test_1() -> ChainedCall {
        let swap_amount: u128 = 166;

        let mut vault_b_auth = AccountForTests::vault_b_init();
        vault_b_auth.is_authorized = true;

        ChainedCall::new(
            TOKEN_PROGRAM_ID,
            vec![vault_b_auth, AccountForTests::user_holding_b()],
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

        let mut vault_a_auth = AccountForTests::vault_a_init();
        vault_a_auth.is_authorized = true;

        ChainedCall::new(
            TOKEN_PROGRAM_ID,
            vec![vault_a_auth, AccountForTests::user_holding_a()],
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
                AccountForTests::user_holding_b(),
                AccountForTests::vault_b_init(),
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
                AccountForTests::user_holding_a(),
                AccountForTests::vault_a_init(),
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
                AccountForTests::user_holding_b(),
                AccountForTests::vault_b_init(),
            ],
            &token_core::Instruction::Transfer {
                amount_to_transfer: BalanceForTests::add_successful_amount_b(),
            },
        )
    }

    fn cc_add_pool_lp() -> ChainedCall {
        let mut pool_lp_auth = AccountForTests::pool_lp_init();
        pool_lp_auth.is_authorized = true;

        ChainedCall::new(
            TOKEN_PROGRAM_ID,
            vec![pool_lp_auth, AccountForTests::user_holding_lp_init()],
            &token_core::Instruction::Mint {
                amount_to_mint: 282,
            },
        )
        .with_pda_seeds(vec![compute_liquidity_token_pda_seed(
            IdForTests::pool_definition_id(),
        )])
    }

    fn cc_remove_token_a() -> ChainedCall {
        let mut vault_a_auth = AccountForTests::vault_a_init();
        vault_a_auth.is_authorized = true;

        ChainedCall::new(
            TOKEN_PROGRAM_ID,
            vec![vault_a_auth, AccountForTests::user_holding_a()],
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
        let mut vault_b_auth = AccountForTests::vault_b_init();
        vault_b_auth.is_authorized = true;

        ChainedCall::new(
            TOKEN_PROGRAM_ID,
            vec![vault_b_auth, AccountForTests::user_holding_b()],
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
        let mut pool_lp_auth = AccountForTests::pool_lp_init();
        pool_lp_auth.is_authorized = true;

        ChainedCall::new(
            TOKEN_PROGRAM_ID,
            vec![pool_lp_auth, AccountForTests::user_holding_lp_init()],
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
                AccountForTests::user_holding_a(),
                AccountForTests::vault_a_init(),
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
                AccountForTests::user_holding_b(),
                AccountForTests::vault_b_init(),
            ],
            &token_core::Instruction::Transfer {
                amount_to_transfer: BalanceForTests::add_successful_amount_b(),
            },
        )
    }

    fn cc_new_definition_token_lp_lock() -> ChainedCall {
        let mut pool_lp_auth = AccountForTests::pool_lp_init();
        pool_lp_auth.is_authorized = true;

        ChainedCall::new(
            TOKEN_PROGRAM_ID,
            vec![pool_lp_auth, AccountForTests::lp_lock_holding_uninit()],
            &token_core::Instruction::Mint {
                amount_to_mint: MINIMUM_LIQUIDITY,
            },
        )
        .with_pda_seeds(vec![compute_liquidity_token_pda_seed(
            IdForTests::pool_definition_id(),
        )])
    }

    fn cc_new_definition_token_lp_user() -> ChainedCall {
        let mut pool_lp_auth = AccountForTests::pool_lp_init();
        pool_lp_auth.is_authorized = true;

        ChainedCall::new(
            TOKEN_PROGRAM_ID,
            vec![pool_lp_auth, AccountForTests::user_holding_lp_uninit()],
            &token_core::Instruction::Mint {
                amount_to_mint: BalanceForTests::lp_user_init(),
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
        compute_liquidity_token_pda(AMM_PROGRAM_ID, IdForTests::pool_definition_id())
    }

    fn lp_lock_holding_id() -> AccountId {
        compute_lp_lock_holding_pda(AMM_PROGRAM_ID, IdForTests::pool_definition_id())
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
            IdForTests::token_a_definition_id(),
            IdForTests::token_b_definition_id(),
        )
    }

    fn vault_a_id() -> AccountId {
        compute_vault_pda(
            AMM_PROGRAM_ID,
            IdForTests::pool_definition_id(),
            IdForTests::token_a_definition_id(),
        )
    }

    fn vault_b_id() -> AccountId {
        compute_vault_pda(
            AMM_PROGRAM_ID,
            IdForTests::pool_definition_id(),
            IdForTests::token_b_definition_id(),
        )
    }
}

impl AccountForTests {
    fn user_holding_a() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_a_definition_id(),
                    balance: BalanceForTests::user_token_a_balance(),
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::user_token_a_id(),
        }
    }

    fn user_holding_b() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_b_definition_id(),
                    balance: BalanceForTests::user_token_b_balance(),
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::user_token_b_id(),
        }
    }

    fn vault_a_init() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_a_definition_id(),
                    balance: BalanceForTests::vault_a_reserve_init(),
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::vault_a_id(),
        }
    }

    fn vault_b_init() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_b_definition_id(),
                    balance: BalanceForTests::vault_b_reserve_init(),
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::vault_b_id(),
        }
    }

    fn vault_a_init_high() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_a_definition_id(),
                    balance: BalanceForTests::vault_a_reserve_high(),
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::vault_a_id(),
        }
    }

    fn vault_b_init_high() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_b_definition_id(),
                    balance: BalanceForTests::vault_b_reserve_high(),
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::vault_b_id(),
        }
    }

    fn vault_a_init_low() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_a_definition_id(),
                    balance: BalanceForTests::vault_a_reserve_low(),
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::vault_a_id(),
        }
    }

    fn vault_b_init_low() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_b_definition_id(),
                    balance: BalanceForTests::vault_b_reserve_low(),
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::vault_b_id(),
        }
    }

    fn vault_a_init_zero() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_a_definition_id(),
                    balance: 0,
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::vault_a_id(),
        }
    }

    fn vault_b_init_zero() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_b_definition_id(),
                    balance: 0,
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::vault_b_id(),
        }
    }

    fn pool_lp_init() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0u128,
                data: Data::from(&TokenDefinition::Fungible {
                    name: String::from("test"),
                    total_supply: BalanceForTests::lp_supply_init(),
                    metadata_id: None,
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::token_lp_definition_id(),
        }
    }

    fn pool_lp_uninit() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account::default(),
            is_authorized: true,
            account_id: IdForTests::token_lp_definition_id(),
        }
    }

    fn pool_lp_with_wrong_id() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0u128,
                data: Data::from(&TokenDefinition::Fungible {
                    name: String::from("test"),
                    total_supply: BalanceForTests::lp_supply_init(),
                    metadata_id: None,
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::vault_a_id(),
        }
    }

    fn user_holding_lp_uninit() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_lp_definition_id(),
                    balance: 0,
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::user_token_lp_id(),
        }
    }

    fn user_holding_lp_init() -> AccountWithMetadata {
        AccountForTests::user_holding_lp_with_balance(BalanceForTests::user_token_lp_balance())
    }

    fn user_holding_lp_with_balance(balance: u128) -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_lp_definition_id(),
                    balance,
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::user_token_lp_id(),
        }
    }

    fn lp_lock_holding_uninit() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account::default(),
            is_authorized: false,
            account_id: IdForTests::lp_lock_holding_id(),
        }
    }

    fn pool_definition_init() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: ProgramId::default(),
                balance: 0u128,
                data: Data::from(&PoolDefinition {
                    definition_token_a_id: IdForTests::token_a_definition_id(),
                    definition_token_b_id: IdForTests::token_b_definition_id(),
                    vault_a_id: IdForTests::vault_a_id(),
                    vault_b_id: IdForTests::vault_b_id(),
                    liquidity_pool_id: IdForTests::token_lp_definition_id(),
                    liquidity_pool_supply: BalanceForTests::lp_supply_init(),
                    reserve_a: BalanceForTests::vault_a_reserve_init(),
                    reserve_b: BalanceForTests::vault_b_reserve_init(),
                    fees: 0u128,
                    active: true,
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn pool_definition_init_reserve_a_zero() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: ProgramId::default(),
                balance: 0u128,
                data: Data::from(&PoolDefinition {
                    definition_token_a_id: IdForTests::token_a_definition_id(),
                    definition_token_b_id: IdForTests::token_b_definition_id(),
                    vault_a_id: IdForTests::vault_a_id(),
                    vault_b_id: IdForTests::vault_b_id(),
                    liquidity_pool_id: IdForTests::token_lp_definition_id(),
                    liquidity_pool_supply: BalanceForTests::lp_supply_init(),
                    reserve_a: 0,
                    reserve_b: BalanceForTests::vault_b_reserve_init(),
                    fees: 0u128,
                    active: true,
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn pool_definition_init_reserve_b_zero() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: ProgramId::default(),
                balance: 0u128,
                data: Data::from(&PoolDefinition {
                    definition_token_a_id: IdForTests::token_a_definition_id(),
                    definition_token_b_id: IdForTests::token_b_definition_id(),
                    vault_a_id: IdForTests::vault_a_id(),
                    vault_b_id: IdForTests::vault_b_id(),
                    liquidity_pool_id: IdForTests::token_lp_definition_id(),
                    liquidity_pool_supply: BalanceForTests::lp_supply_init(),
                    reserve_a: BalanceForTests::vault_a_reserve_init(),
                    reserve_b: 0,
                    fees: 0u128,
                    active: true,
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn pool_definition_init_reserve_a_low() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: ProgramId::default(),
                balance: 0u128,
                data: Data::from(&PoolDefinition {
                    definition_token_a_id: IdForTests::token_a_definition_id(),
                    definition_token_b_id: IdForTests::token_b_definition_id(),
                    vault_a_id: IdForTests::vault_a_id(),
                    vault_b_id: IdForTests::vault_b_id(),
                    liquidity_pool_id: IdForTests::token_lp_definition_id(),
                    liquidity_pool_supply: BalanceForTests::vault_a_reserve_low(),
                    reserve_a: BalanceForTests::vault_a_reserve_low(),
                    reserve_b: BalanceForTests::vault_b_reserve_high(),
                    fees: 0u128,
                    active: true,
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn pool_definition_init_reserve_b_low() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: ProgramId::default(),
                balance: 0u128,
                data: Data::from(&PoolDefinition {
                    definition_token_a_id: IdForTests::token_a_definition_id(),
                    definition_token_b_id: IdForTests::token_b_definition_id(),
                    vault_a_id: IdForTests::vault_a_id(),
                    vault_b_id: IdForTests::vault_b_id(),
                    liquidity_pool_id: IdForTests::token_lp_definition_id(),
                    liquidity_pool_supply: BalanceForTests::vault_a_reserve_high(),
                    reserve_a: BalanceForTests::vault_a_reserve_high(),
                    reserve_b: BalanceForTests::vault_b_reserve_low(),
                    fees: 0u128,
                    active: true,
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn pool_definition_swap_test_1() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: ProgramId::default(),
                balance: 0u128,
                data: Data::from(&PoolDefinition {
                    definition_token_a_id: IdForTests::token_a_definition_id(),
                    definition_token_b_id: IdForTests::token_b_definition_id(),
                    vault_a_id: IdForTests::vault_a_id(),
                    vault_b_id: IdForTests::vault_b_id(),
                    liquidity_pool_id: IdForTests::token_lp_definition_id(),
                    liquidity_pool_supply: BalanceForTests::lp_supply_init(),
                    reserve_a: BalanceForTests::vault_a_swap_test_1(),
                    reserve_b: BalanceForTests::vault_b_swap_test_1(),
                    fees: 0u128,
                    active: true,
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn pool_definition_swap_test_2() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: ProgramId::default(),
                balance: 0u128,
                data: Data::from(&PoolDefinition {
                    definition_token_a_id: IdForTests::token_a_definition_id(),
                    definition_token_b_id: IdForTests::token_b_definition_id(),
                    vault_a_id: IdForTests::vault_a_id(),
                    vault_b_id: IdForTests::vault_b_id(),
                    liquidity_pool_id: IdForTests::token_lp_definition_id(),
                    liquidity_pool_supply: BalanceForTests::lp_supply_init(),
                    reserve_a: BalanceForTests::vault_a_swap_test_2(),
                    reserve_b: BalanceForTests::vault_b_swap_test_2(),
                    fees: 0u128,
                    active: true,
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn pool_definition_add_zero_lp() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: ProgramId::default(),
                balance: 0u128,
                data: Data::from(&PoolDefinition {
                    definition_token_a_id: IdForTests::token_a_definition_id(),
                    definition_token_b_id: IdForTests::token_b_definition_id(),
                    vault_a_id: IdForTests::vault_a_id(),
                    vault_b_id: IdForTests::vault_b_id(),
                    liquidity_pool_id: IdForTests::token_lp_definition_id(),
                    liquidity_pool_supply: BalanceForTests::vault_a_reserve_low(),
                    reserve_a: BalanceForTests::vault_a_reserve_init(),
                    reserve_b: BalanceForTests::vault_b_reserve_init(),
                    fees: 0u128,
                    active: true,
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn pool_definition_add_successful() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: ProgramId::default(),
                balance: 0u128,
                data: Data::from(&PoolDefinition {
                    definition_token_a_id: IdForTests::token_a_definition_id(),
                    definition_token_b_id: IdForTests::token_b_definition_id(),
                    vault_a_id: IdForTests::vault_a_id(),
                    vault_b_id: IdForTests::vault_b_id(),
                    liquidity_pool_id: IdForTests::token_lp_definition_id(),
                    liquidity_pool_supply: 989,
                    reserve_a: BalanceForTests::vault_a_add_successful(),
                    reserve_b: BalanceForTests::vault_b_add_successful(),
                    fees: 0u128,
                    active: true,
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn pool_definition_remove_successful() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: ProgramId::default(),
                balance: 0u128,
                data: Data::from(&PoolDefinition {
                    definition_token_a_id: IdForTests::token_a_definition_id(),
                    definition_token_b_id: IdForTests::token_b_definition_id(),
                    vault_a_id: IdForTests::vault_a_id(),
                    vault_b_id: IdForTests::vault_b_id(),
                    liquidity_pool_id: IdForTests::token_lp_definition_id(),
                    liquidity_pool_supply: 607,
                    reserve_a: BalanceForTests::vault_a_remove_successful(),
                    reserve_b: BalanceForTests::vault_b_remove_successful(),
                    fees: 0u128,
                    active: true,
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn pool_definition_inactive() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: ProgramId::default(),
                balance: 0u128,
                data: Data::from(&PoolDefinition {
                    definition_token_a_id: IdForTests::token_a_definition_id(),
                    definition_token_b_id: IdForTests::token_b_definition_id(),
                    vault_a_id: IdForTests::vault_a_id(),
                    vault_b_id: IdForTests::vault_b_id(),
                    liquidity_pool_id: IdForTests::token_lp_definition_id(),
                    liquidity_pool_supply: BalanceForTests::lp_supply_init(),
                    reserve_a: BalanceForTests::vault_a_reserve_init(),
                    reserve_b: BalanceForTests::vault_b_reserve_init(),
                    fees: 0u128,
                    active: false,
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }

    fn pool_definition_with_wrong_id() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: ProgramId::default(),
                balance: 0u128,
                data: Data::from(&PoolDefinition {
                    definition_token_a_id: IdForTests::token_a_definition_id(),
                    definition_token_b_id: IdForTests::token_b_definition_id(),
                    vault_a_id: IdForTests::vault_a_id(),
                    vault_b_id: IdForTests::vault_b_id(),
                    liquidity_pool_id: IdForTests::token_lp_definition_id(),
                    liquidity_pool_supply: BalanceForTests::lp_supply_init(),
                    reserve_a: BalanceForTests::vault_a_reserve_init(),
                    reserve_b: BalanceForTests::vault_b_reserve_init(),
                    fees: 0u128,
                    active: false,
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: AccountId::new([4; 32]),
        }
    }

    fn vault_a_with_wrong_id() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_a_definition_id(),
                    balance: BalanceForTests::vault_a_reserve_init(),
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: AccountId::new([4; 32]),
        }
    }

    fn vault_b_with_wrong_id() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_b_definition_id(),
                    balance: BalanceForTests::vault_b_reserve_init(),
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: AccountId::new([4; 32]),
        }
    }

    fn pool_definition_active() -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account {
                program_owner: ProgramId::default(),
                balance: 0u128,
                data: Data::from(&PoolDefinition {
                    definition_token_a_id: IdForTests::token_a_definition_id(),
                    definition_token_b_id: IdForTests::token_b_definition_id(),
                    vault_a_id: IdForTests::vault_a_id(),
                    vault_b_id: IdForTests::vault_b_id(),
                    liquidity_pool_id: IdForTests::token_lp_definition_id(),
                    liquidity_pool_supply: BalanceForTests::lp_supply_init(),
                    reserve_a: BalanceForTests::vault_a_reserve_init(),
                    reserve_b: BalanceForTests::vault_b_reserve_init(),
                    fees: 0u128,
                    active: true,
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::pool_definition_id(),
        }
    }
}

#[test]
fn test_pool_pda_produces_unique_id_for_token_pair() {
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
fn test_call_add_liquidity_vault_a_omitted() {
    let _post_states = add_liquidity(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_with_wrong_id(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::add_min_amount_lp()).unwrap(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::add_max_amount_b(),
    );
}

#[should_panic(expected = "Vault B was not provided")]
#[test]
fn test_call_add_liquidity_vault_b_omitted() {
    let _post_states = add_liquidity(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_with_wrong_id(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::add_min_amount_lp()).unwrap(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::add_max_amount_b(),
    );
}

#[should_panic(expected = "LP definition mismatch")]
#[test]
fn test_call_add_liquidity_lp_definition_mismatch() {
    let _post_states = add_liquidity(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_with_wrong_id(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::add_min_amount_lp()).unwrap(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::add_max_amount_b(),
    );
}

#[should_panic(expected = "Both max-balances must be nonzero")]
#[test]
fn test_call_add_liquidity_zero_balance_1() {
    let _post_states = add_liquidity(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::add_min_amount_lp()).unwrap(),
        0,
        BalanceForTests::add_max_amount_b(),
    );
}

#[should_panic(expected = "Both max-balances must be nonzero")]
#[test]
fn test_call_add_liquidity_zero_balance_2() {
    let _post_states = add_liquidity(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::add_min_amount_lp()).unwrap(),
        0,
        BalanceForTests::add_max_amount_a(),
    );
}

#[should_panic(expected = "Vaults' balances must be at least the reserve amounts")]
#[test]
fn test_call_add_liquidity_vault_insufficient_balance_1() {
    let _post_states = add_liquidity(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_init_zero(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::add_max_amount_a()).unwrap(),
        BalanceForTests::add_max_amount_b(),
        BalanceForTests::add_min_amount_lp(),
    );
}

#[should_panic(expected = "Vaults' balances must be at least the reserve amounts")]
#[test]
fn test_call_add_liquidity_vault_insufficient_balance_2() {
    let _post_states = add_liquidity(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init_zero(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::add_max_amount_a()).unwrap(),
        BalanceForTests::add_max_amount_b(),
        BalanceForTests::add_min_amount_lp(),
    );
}

#[should_panic(expected = "A trade amount is 0")]
#[test]
fn test_call_add_liquidity_actual_amount_zero_1() {
    let _post_states = add_liquidity(
        AccountForTests::pool_definition_init_reserve_a_low(),
        AccountForTests::vault_a_init_low(),
        AccountForTests::vault_b_init_high(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::add_min_amount_lp()).unwrap(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::add_max_amount_b(),
    );
}

#[should_panic(expected = "A trade amount is 0")]
#[test]
fn test_call_add_liquidity_actual_amount_zero_2() {
    let _post_states = add_liquidity(
        AccountForTests::pool_definition_init_reserve_b_low(),
        AccountForTests::vault_a_init_high(),
        AccountForTests::vault_b_init_low(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::add_min_amount_lp()).unwrap(),
        BalanceForTests::add_max_amount_a_low(),
        BalanceForTests::add_max_amount_b_low(),
    );
}

#[should_panic(expected = "Reserves must be nonzero")]
#[test]
fn test_call_add_liquidity_reserves_zero_1() {
    let _post_states = add_liquidity(
        AccountForTests::pool_definition_init_reserve_a_zero(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::add_min_amount_lp()).unwrap(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::add_max_amount_b(),
    );
}

#[should_panic(expected = "Reserves must be nonzero")]
#[test]
fn test_call_add_liquidity_reserves_zero_2() {
    let _post_states = add_liquidity(
        AccountForTests::pool_definition_init_reserve_b_zero(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::add_min_amount_lp()).unwrap(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::add_max_amount_b(),
    );
}

#[should_panic(expected = "Payable LP must be nonzero")]
#[test]
fn test_call_add_liquidity_payable_lp_zero() {
    let _post_states = add_liquidity(
        AccountForTests::pool_definition_add_zero_lp(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::add_min_amount_lp()).unwrap(),
        BalanceForTests::add_max_amount_a_low(),
        BalanceForTests::add_max_amount_b_low(),
    );
}

#[test]
fn test_call_add_liquidity_chained_call_successsful() {
    let (post_states, chained_calls) = add_liquidity(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::add_min_amount_lp()).unwrap(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::add_max_amount_b(),
    );

    let pool_post = post_states[0].clone();

    assert!(AccountForTests::pool_definition_add_successful().account == *pool_post.account());

    let chained_call_lp = chained_calls[0].clone();
    let chained_call_b = chained_calls[1].clone();
    let chained_call_a = chained_calls[2].clone();

    assert!(chained_call_a == ChainedCallForTests::cc_add_token_a());
    assert!(chained_call_b == ChainedCallForTests::cc_add_token_b());
    assert!(chained_call_lp == ChainedCallForTests::cc_add_pool_lp());
}

#[should_panic(expected = "Vault A was not provided")]
#[test]
fn test_call_remove_liquidity_vault_a_omitted() {
    let _post_states = remove_liquidity(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_with_wrong_id(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::remove_amount_lp()).unwrap(),
        BalanceForTests::remove_min_amount_a(),
        BalanceForTests::remove_min_amount_b(),
    );
}

#[should_panic(expected = "Vault B was not provided")]
#[test]
fn test_call_remove_liquidity_vault_b_omitted() {
    let _post_states = remove_liquidity(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_with_wrong_id(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::remove_amount_lp()).unwrap(),
        BalanceForTests::remove_min_amount_a(),
        BalanceForTests::remove_min_amount_b(),
    );
}

#[should_panic(expected = "LP definition mismatch")]
#[test]
fn test_call_remove_liquidity_lp_def_mismatch() {
    let _post_states = remove_liquidity(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_with_wrong_id(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::remove_amount_lp()).unwrap(),
        BalanceForTests::remove_min_amount_a(),
        BalanceForTests::remove_min_amount_b(),
    );
}

#[should_panic(expected = "Invalid liquidity account provided")]
#[test]
fn test_call_remove_liquidity_insufficient_liquidity_amount() {
    let _post_states = remove_liquidity(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_a(), /* different token account than lp to create desired
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
fn test_call_remove_liquidity_insufficient_balance_1() {
    let _post_states = remove_liquidity(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::remove_amount_lp_1()).unwrap(),
        BalanceForTests::remove_min_amount_a(),
        BalanceForTests::remove_min_amount_b(),
    );
}

#[should_panic(
    expected = "Insufficient minimal withdraw amount (Token B) provided for liquidity amount"
)]
#[test]
fn test_call_remove_liquidity_insufficient_balance_2() {
    let _post_states = remove_liquidity(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::remove_amount_lp()).unwrap(),
        BalanceForTests::remove_min_amount_a(),
        BalanceForTests::remove_min_amount_b(),
    );
}

#[should_panic(expected = "Minimum withdraw amount must be nonzero")]
#[test]
fn test_call_remove_liquidity_min_bal_zero_1() {
    let _post_states = remove_liquidity(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::remove_amount_lp()).unwrap(),
        0,
        BalanceForTests::remove_min_amount_b(),
    );
}

#[should_panic(expected = "Minimum withdraw amount must be nonzero")]
#[test]
fn test_call_remove_liquidity_min_bal_zero_2() {
    let _post_states = remove_liquidity(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::remove_amount_lp()).unwrap(),
        BalanceForTests::remove_min_amount_a(),
        0,
    );
}

#[test]
fn test_call_remove_liquidity_chained_call_successful() {
    let (post_states, chained_calls) = remove_liquidity(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_init(),
        NonZero::new(BalanceForTests::remove_amount_lp()).unwrap(),
        BalanceForTests::remove_min_amount_a(),
        BalanceForTests::remove_min_amount_b_low(),
    );

    let pool_post = post_states[0].clone();

    assert!(AccountForTests::pool_definition_remove_successful().account == *pool_post.account());

    let chained_call_lp = chained_calls[0].clone();
    let chained_call_b = chained_calls[1].clone();
    let chained_call_a = chained_calls[2].clone();

    assert!(chained_call_a == ChainedCallForTests::cc_remove_token_a());
    assert!(chained_call_b == ChainedCallForTests::cc_remove_token_b());
    assert!(chained_call_lp == ChainedCallForTests::cc_remove_pool_lp());
}

#[should_panic(expected = "Balances must be nonzero")]
#[test]
fn test_call_new_definition_with_zero_balance_1() {
    let _post_states = new_definition(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_uninit(),
        NonZero::new(0).expect("Balances must be nonzero"),
        NonZero::new(BalanceForTests::vault_b_reserve_init()).unwrap(),
        AMM_PROGRAM_ID,
    );
}

#[should_panic(expected = "Balances must be nonzero")]
#[test]
fn test_call_new_definition_with_zero_balance_2() {
    let _post_states = new_definition(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_uninit(),
        NonZero::new(BalanceForTests::vault_a_reserve_init()).unwrap(),
        NonZero::new(0).expect("Balances must be nonzero"),
        AMM_PROGRAM_ID,
    );
}

#[should_panic(expected = "Cannot set up a swap for a token with itself")]
#[test]
fn test_call_new_definition_same_token_definition() {
    let _post_states = new_definition(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_lp_uninit(),
        NonZero::new(BalanceForTests::vault_a_reserve_init()).unwrap(),
        NonZero::new(BalanceForTests::vault_b_reserve_init()).unwrap(),
        AMM_PROGRAM_ID,
    );
}

#[should_panic(expected = "Liquidity pool Token Definition Account ID does not match PDA")]
#[test]
fn test_call_new_definition_wrong_liquidity_id() {
    let _post_states = new_definition(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_with_wrong_id(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_uninit(),
        NonZero::new(BalanceForTests::vault_a_reserve_init()).unwrap(),
        NonZero::new(BalanceForTests::vault_b_reserve_init()).unwrap(),
        AMM_PROGRAM_ID,
    );
}

#[should_panic(expected = "Pool Definition Account ID does not match PDA")]
#[test]
fn test_call_new_definition_wrong_pool_id() {
    let _post_states = new_definition(
        AccountForTests::pool_definition_with_wrong_id(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_uninit(),
        NonZero::new(BalanceForTests::vault_a_reserve_init()).unwrap(),
        NonZero::new(BalanceForTests::vault_b_reserve_init()).unwrap(),
        AMM_PROGRAM_ID,
    );
}

#[should_panic(expected = "Vault ID does not match PDA")]
#[test]
fn test_call_new_definition_wrong_vault_id_1() {
    let _post_states = new_definition(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_with_wrong_id(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_uninit(),
        NonZero::new(BalanceForTests::vault_a_reserve_init()).unwrap(),
        NonZero::new(BalanceForTests::vault_b_reserve_init()).unwrap(),
        AMM_PROGRAM_ID,
    );
}

#[should_panic(expected = "Vault ID does not match PDA")]
#[test]
fn test_call_new_definition_wrong_vault_id_2() {
    let _post_states = new_definition(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_with_wrong_id(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_uninit(),
        NonZero::new(BalanceForTests::vault_a_reserve_init()).unwrap(),
        NonZero::new(BalanceForTests::vault_b_reserve_init()).unwrap(),
        AMM_PROGRAM_ID,
    );
}

#[should_panic(expected = "Cannot initialize an active Pool Definition")]
#[test]
fn test_call_new_definition_cannot_initialize_active_pool() {
    let _post_states = new_definition(
        AccountForTests::pool_definition_active(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_uninit(),
        NonZero::new(BalanceForTests::vault_a_reserve_init()).unwrap(),
        NonZero::new(BalanceForTests::vault_b_reserve_init()).unwrap(),
        AMM_PROGRAM_ID,
    );
}

#[should_panic(expected = "Cannot initialize an active Pool Definition")]
#[test]
fn test_call_new_definition_chained_call_successful() {
    let (post_states, chained_calls) = new_definition(
        AccountForTests::pool_definition_active(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_uninit(),
        NonZero::new(BalanceForTests::vault_a_reserve_init()).unwrap(),
        NonZero::new(BalanceForTests::vault_b_reserve_init()).unwrap(),
        AMM_PROGRAM_ID,
    );

    let pool_post = post_states[0].clone();

    assert!(AccountForTests::pool_definition_add_successful().account == *pool_post.account());

    let chained_call_lp_lock = chained_calls[0].clone();
    let chained_call_lp_user = chained_calls[1].clone();
    let chained_call_b = chained_calls[2].clone();
    let chained_call_a = chained_calls[3].clone();

    assert!(chained_call_a == ChainedCallForTests::cc_new_definition_token_a());
    assert!(chained_call_b == ChainedCallForTests::cc_new_definition_token_b());
    assert!(chained_call_lp_lock == ChainedCallForTests::cc_new_definition_token_lp_lock());
    assert!(chained_call_lp_user == ChainedCallForTests::cc_new_definition_token_lp_user());
}

#[should_panic(expected = "AccountId is not a token type for the pool")]
#[test]
fn test_call_swap_incorrect_token_type() {
    let _post_states = swap(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::min_amount_out(),
        IdForTests::token_lp_definition_id(),
    );
}

#[should_panic(expected = "Vault A was not provided")]
#[test]
fn test_call_swap_vault_a_omitted() {
    let _post_states = swap(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_with_wrong_id(),
        AccountForTests::vault_b_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::min_amount_out(),
        IdForTests::token_a_definition_id(),
    );
}

#[should_panic(expected = "Vault B was not provided")]
#[test]
fn test_call_swap_vault_b_omitted() {
    let _post_states = swap(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_with_wrong_id(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::min_amount_out(),
        IdForTests::token_a_definition_id(),
    );
}

#[should_panic(expected = "Reserve for Token A exceeds vault balance")]
#[test]
fn test_call_swap_reserves_vault_mismatch_1() {
    let _post_states = swap(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_init_low(),
        AccountForTests::vault_b_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::min_amount_out(),
        IdForTests::token_a_definition_id(),
    );
}

#[should_panic(expected = "Reserve for Token B exceeds vault balance")]
#[test]
fn test_call_swap_reserves_vault_mismatch_2() {
    let _post_states = swap(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init_low(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::min_amount_out(),
        IdForTests::token_a_definition_id(),
    );
}

#[should_panic(expected = "Pool is inactive")]
#[test]
fn test_call_swap_ianctive() {
    let _post_states = swap(
        AccountForTests::pool_definition_inactive(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::min_amount_out(),
        IdForTests::token_a_definition_id(),
    );
}

#[should_panic(expected = "Withdraw amount is less than minimal amount out")]
#[test]
fn test_call_swap_below_min_out() {
    let _post_states = swap(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::min_amount_out(),
        IdForTests::token_a_definition_id(),
    );
}

#[test]
fn test_call_swap_chained_call_successful_1() {
    let (post_states, chained_calls) = swap(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        BalanceForTests::add_max_amount_a(),
        BalanceForTests::add_max_amount_a_low(),
        IdForTests::token_a_definition_id(),
    );

    let pool_post = post_states[0].clone();

    assert!(AccountForTests::pool_definition_swap_test_1().account == *pool_post.account());

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
fn test_call_swap_chained_call_successful_2() {
    let (post_states, chained_calls) = swap(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        BalanceForTests::add_max_amount_b(),
        BalanceForTests::min_amount_out(),
        IdForTests::token_b_definition_id(),
    );

    let pool_post = post_states[0].clone();

    assert!(AccountForTests::pool_definition_swap_test_2().account == *pool_post.account());

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
fn test_new_definition_lp_asymmetric_amounts() {
    let (post_states, chained_calls) = new_definition(
        AccountForTests::pool_definition_inactive(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_uninit(),
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

    let chained_call_lp_lock = chained_calls[0].clone();
    let chained_call_lp_user = chained_calls[1].clone();
    assert!(chained_call_lp_lock == ChainedCallForTests::cc_new_definition_token_lp_lock());
    assert!(chained_call_lp_user == ChainedCallForTests::cc_new_definition_token_lp_user());
}

#[test]
fn test_new_definition_lp_symmetric_amounts() {
    // token_a=100, token_b=100 → LP=sqrt(10_000)=100
    let token_a_amount = 100u128;
    let token_b_amount = 100u128;
    let expected_lp = (token_a_amount * token_b_amount).isqrt();
    assert_eq!(expected_lp, 100);

    let (post_states, chained_calls) = new_definition(
        AccountForTests::pool_definition_inactive(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_uninit(),
        NonZero::new(token_a_amount).unwrap(),
        NonZero::new(token_b_amount).unwrap(),
        AMM_PROGRAM_ID,
    );

    let pool_post = post_states[0].clone();
    let pool_def = PoolDefinition::try_from(&pool_post.account().data).unwrap();
    assert_eq!(pool_def.liquidity_pool_supply, expected_lp);

    let chained_call_lp_lock = chained_calls[0].clone();
    let chained_call_lp_user = chained_calls[1].clone();

    let mut pool_lp_auth = AccountForTests::pool_lp_init();
    pool_lp_auth.is_authorized = true;
    let expected_lp_lock_call = ChainedCall::new(
        TOKEN_PROGRAM_ID,
        vec![
            pool_lp_auth.clone(),
            AccountForTests::lp_lock_holding_uninit(),
        ],
        &token_core::Instruction::Mint {
            amount_to_mint: MINIMUM_LIQUIDITY,
        },
    )
    .with_pda_seeds(vec![compute_liquidity_token_pda_seed(
        IdForTests::pool_definition_id(),
    )]);

    let expected_lp_user_call = ChainedCall::new(
        TOKEN_PROGRAM_ID,
        vec![pool_lp_auth, AccountForTests::user_holding_lp_uninit()],
        &token_core::Instruction::Mint {
            amount_to_mint: expected_lp - MINIMUM_LIQUIDITY,
        },
    )
    .with_pda_seeds(vec![compute_liquidity_token_pda_seed(
        IdForTests::pool_definition_id(),
    )]);

    assert_eq!(chained_call_lp_lock, expected_lp_lock_call);
    assert_eq!(chained_call_lp_user, expected_lp_user_call);
}

#[test]
fn test_sync_reserves_with_donation() {
    let pool = AccountForTests::pool_definition_init();
    let donation_a = 111u128;

    let mut donated_vault_a = AccountForTests::vault_a_init();
    donated_vault_a.account.data = Data::from(&TokenHolding::Fungible {
        definition_id: IdForTests::token_a_definition_id(),
        balance: BalanceForTests::vault_a_reserve_init() + donation_a,
    });

    let pool_pre = PoolDefinition::try_from(&pool.account.data).unwrap();
    assert_eq!(pool_pre.reserve_a, BalanceForTests::vault_a_reserve_init());

    let (post_states, chained_calls) =
        sync_reserves(pool, donated_vault_a, AccountForTests::vault_b_init());
    assert!(chained_calls.is_empty());

    let pool_post = PoolDefinition::try_from(&post_states[0].account().data).unwrap();
    assert_eq!(
        pool_post.reserve_a,
        BalanceForTests::vault_a_reserve_init() + donation_a
    );
    assert_eq!(pool_post.reserve_b, BalanceForTests::vault_b_reserve_init());
}

#[test]
fn test_recover_surplus_inactive_pool_transfers_only_surplus() {
    let donation_a = 25u128;

    let mut donated_vault_a = AccountForTests::vault_a_init();
    donated_vault_a.account.data = Data::from(&TokenHolding::Fungible {
        definition_id: IdForTests::token_a_definition_id(),
        balance: BalanceForTests::vault_a_reserve_init() + donation_a,
    });

    let (post_states, chained_calls) = recover_surplus(
        AccountForTests::pool_definition_inactive(),
        donated_vault_a.clone(),
        AccountForTests::vault_b_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        RecoverSurplusMode::InactiveOrZeroSupplyOnly,
    );

    let pool_post = PoolDefinition::try_from(&post_states[0].account().data).unwrap();
    assert_eq!(pool_post.reserve_a, BalanceForTests::vault_a_reserve_init());
    assert_eq!(pool_post.reserve_b, BalanceForTests::vault_b_reserve_init());

    assert_eq!(chained_calls.len(), 1);

    let mut donated_vault_a_auth = donated_vault_a;
    donated_vault_a_auth.is_authorized = true;
    let expected_call = ChainedCall::new(
        TOKEN_PROGRAM_ID,
        vec![donated_vault_a_auth, AccountForTests::user_holding_a()],
        &token_core::Instruction::Transfer {
            amount_to_transfer: donation_a,
        },
    )
    .with_pda_seeds(vec![compute_vault_pda_seed(
        IdForTests::pool_definition_id(),
        IdForTests::token_a_definition_id(),
    )]);

    assert_eq!(chained_calls[0], expected_call);

    let resulting_vault_balance = BalanceForTests::vault_a_reserve_init() + donation_a - donation_a;
    assert_eq!(
        resulting_vault_balance,
        BalanceForTests::vault_a_reserve_init()
    );
}

#[should_panic(expected = "Recover surplus is only allowed for inactive or zero-supply pools")]
#[test]
fn test_recover_surplus_forbidden_for_active_pool() {
    let mut donated_vault_a = AccountForTests::vault_a_init();
    donated_vault_a.account.data = Data::from(&TokenHolding::Fungible {
        definition_id: IdForTests::token_a_definition_id(),
        balance: BalanceForTests::vault_a_reserve_init() + 1,
    });

    let _ = recover_surplus(
        AccountForTests::pool_definition_init(),
        donated_vault_a,
        AccountForTests::vault_b_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        RecoverSurplusMode::InactiveOrZeroSupplyOnly,
    );
}

#[test]
fn test_minimum_liquidity_lock_and_remove_all_user_lp() {
    let pool_uninitialized = AccountWithMetadata {
        account: Account::default(),
        is_authorized: true,
        account_id: IdForTests::pool_definition_id(),
    };
    let token_a_amount = BalanceForTests::vault_a_reserve_init();
    let token_b_amount = BalanceForTests::vault_b_reserve_init();
    let initial_lp = (token_a_amount * token_b_amount).isqrt();
    let user_lp = initial_lp - MINIMUM_LIQUIDITY;

    let (post_states, chained_calls) = new_definition(
        pool_uninitialized,
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_uninit(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_uninit(),
        NonZero::new(token_a_amount).unwrap(),
        NonZero::new(token_b_amount).unwrap(),
        AMM_PROGRAM_ID,
    );

    let mut pool_lp_auth = AccountForTests::pool_lp_uninit();
    pool_lp_auth.is_authorized = true;

    let expected_lock_call = ChainedCall::new(
        TOKEN_PROGRAM_ID,
        vec![
            pool_lp_auth.clone(),
            AccountForTests::lp_lock_holding_uninit(),
        ],
        &token_core::Instruction::NewFungibleDefinition {
            name: String::from("LP Token"),
            total_supply: MINIMUM_LIQUIDITY,
        },
    )
    .with_pda_seeds(vec![compute_liquidity_token_pda_seed(
        IdForTests::pool_definition_id(),
    )]);
    let expected_user_call = ChainedCall::new(
        TOKEN_PROGRAM_ID,
        vec![pool_lp_auth, AccountForTests::user_holding_lp_uninit()],
        &token_core::Instruction::Mint {
            amount_to_mint: user_lp,
        },
    )
    .with_pda_seeds(vec![compute_liquidity_token_pda_seed(
        IdForTests::pool_definition_id(),
    )]);
    assert_eq!(chained_calls[0], expected_lock_call);
    assert_eq!(chained_calls[1], expected_user_call);

    let pool_post = PoolDefinition::try_from(&post_states[0].account().data).unwrap();
    assert_eq!(pool_post.liquidity_pool_supply, initial_lp);

    let pool_for_remove = AccountWithMetadata {
        account: post_states[0].account().clone(),
        is_authorized: true,
        account_id: IdForTests::pool_definition_id(),
    };
    let (remove_post_states, _) = remove_liquidity(
        pool_for_remove,
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_with_balance(user_lp),
        NonZero::new(user_lp).unwrap(),
        1,
        1,
    );

    let pool_after_remove =
        PoolDefinition::try_from(&remove_post_states[0].account().data).unwrap();
    assert_eq!(pool_after_remove.liquidity_pool_supply, MINIMUM_LIQUIDITY);
    assert!(pool_after_remove.reserve_a > 0);
    assert!(pool_after_remove.reserve_b > 0);
    assert!(pool_after_remove.active);
}

#[test]
fn test_donation_then_add_liquidity_sync_mitigates_mispricing() {
    let donation_a = 100u128;

    let mut donated_vault_a = AccountForTests::vault_a_init();
    donated_vault_a.account.data = Data::from(&TokenHolding::Fungible {
        definition_id: IdForTests::token_a_definition_id(),
        balance: BalanceForTests::vault_a_reserve_init() + donation_a,
    });
    let donated_vault_b = AccountForTests::vault_b_init();

    let (post_unsynced, _) = add_liquidity(
        AccountForTests::pool_definition_init(),
        donated_vault_a.clone(),
        donated_vault_b.clone(),
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_init(),
        NonZero::new(1).unwrap(),
        100,
        50,
    );
    let unsynced_pool_post = PoolDefinition::try_from(&post_unsynced[0].account().data).unwrap();
    let unsynced_delta_lp =
        unsynced_pool_post.liquidity_pool_supply - BalanceForTests::lp_supply_init();

    let donated_vault_a_for_synced_add = donated_vault_a.clone();
    let donated_vault_b_for_synced_add = donated_vault_b.clone();

    let (sync_post, _) = sync_reserves(
        AccountForTests::pool_definition_init(),
        donated_vault_a,
        donated_vault_b,
    );
    let synced_pool = AccountWithMetadata {
        account: sync_post[0].account().clone(),
        is_authorized: true,
        account_id: IdForTests::pool_definition_id(),
    };

    let (post_synced, _) = add_liquidity(
        synced_pool,
        donated_vault_a_for_synced_add,
        donated_vault_b_for_synced_add,
        AccountForTests::pool_lp_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        AccountForTests::user_holding_lp_init(),
        NonZero::new(1).unwrap(),
        100,
        50,
    );
    let synced_pool_post = PoolDefinition::try_from(&post_synced[0].account().data).unwrap();
    let synced_delta_lp = synced_pool_post.liquidity_pool_supply
        - PoolDefinition::try_from(&sync_post[0].account().data)
            .unwrap()
            .liquidity_pool_supply;

    assert!(synced_delta_lp < unsynced_delta_lp);
}
