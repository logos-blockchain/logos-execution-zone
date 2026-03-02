#![cfg(test)]

use std::num::NonZero;

use amm_core::{
    PoolDefinition, compute_liquidity_token_pda, compute_liquidity_token_pda_seed,
    compute_pool_pda, compute_vault_pda, compute_vault_pda_seed,
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

    fn cc_new_definition_token_lp() -> ChainedCall {
        ChainedCall::new(
            TOKEN_PROGRAM_ID,
            vec![
                AccountForTests::pool_lp_init(),
                AccountForTests::user_holding_lp_uninit(),
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
        compute_liquidity_token_pda(AMM_PROGRAM_ID, IdForTests::pool_definition_id())
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
        AccountWithMetadata {
            account: Account {
                program_owner: TOKEN_PROGRAM_ID,
                balance: 0u128,
                data: Data::from(&TokenHolding::Fungible {
                    definition_id: IdForTests::token_lp_definition_id(),
                    balance: BalanceForTests::user_token_lp_balance(),
                }),
                nonce: 0,
            },
            is_authorized: true,
            account_id: IdForTests::user_token_lp_id(),
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

fn pool_with_reserves(reserve_a: u128, reserve_b: u128) -> AccountWithMetadata {
    let mut pool = AccountForTests::pool_definition_init();
    let mut pool_definition =
        PoolDefinition::try_from(&pool.account.data).expect("Pool definition must be valid");

    pool_definition.reserve_a = reserve_a;
    pool_definition.reserve_b = reserve_b;
    pool.account.data = Data::from(&pool_definition);

    pool
}

fn vault_a_with_balance(balance: u128) -> AccountWithMetadata {
    let mut vault = AccountForTests::vault_a_init();
    vault.account.data = Data::from(&TokenHolding::Fungible {
        definition_id: IdForTests::token_a_definition_id(),
        balance,
    });
    vault
}

fn vault_b_with_balance(balance: u128) -> AccountWithMetadata {
    let mut vault = AccountForTests::vault_b_init();
    vault.account.data = Data::from(&TokenHolding::Fungible {
        definition_id: IdForTests::token_b_definition_id(),
        balance,
    });
    vault
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

    let chained_call_lp = chained_calls[0].clone();
    let chained_call_b = chained_calls[1].clone();
    let chained_call_a = chained_calls[2].clone();

    assert!(chained_call_a == ChainedCallForTests::cc_new_definition_token_a());
    assert!(chained_call_b == ChainedCallForTests::cc_new_definition_token_b());
    assert!(chained_call_lp == ChainedCallForTests::cc_new_definition_token_lp());
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

#[should_panic(expected = "Swap amount in should be nonzero")]
#[test]
fn test_call_swap_zero_amount_in() {
    let _post_states = swap(
        AccountForTests::pool_definition_init(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        0,
        0,
        IdForTests::token_a_definition_id(),
    );
}

#[should_panic(expected = "Withdraw amount must be less than reserve withdraw amount")]
#[test]
fn test_call_swap_withdraw_equal_to_reserve() {
    let _post_states = swap(
        AccountForTests::pool_definition_init_reserve_a_zero(),
        AccountForTests::vault_a_init(),
        AccountForTests::vault_b_init(),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        1,
        0,
        IdForTests::token_a_definition_id(),
    );
}

#[should_panic(expected = "Swap withdraw numerator overflow")]
#[test]
fn test_call_swap_withdraw_numerator_overflow() {
    let _post_states = swap(
        pool_with_reserves(1, u128::MAX),
        vault_a_with_balance(1),
        vault_b_with_balance(u128::MAX),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        2,
        0,
        IdForTests::token_a_definition_id(),
    );
}

#[should_panic(expected = "Swap withdraw denominator overflow")]
#[test]
fn test_call_swap_withdraw_denominator_overflow() {
    let _post_states = swap(
        pool_with_reserves(u128::MAX, 10),
        vault_a_with_balance(u128::MAX),
        vault_b_with_balance(10),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        1,
        0,
        IdForTests::token_a_definition_id(),
    );
}

#[test]
fn test_call_swap_widened_k_boundary() {
    let old_reserve_a = u128::MAX - 2;
    let old_reserve_b = u128::MAX - 1;

    assert!(old_reserve_a.checked_mul(old_reserve_b).is_none());

    let (post_states, _chained_calls) = swap(
        pool_with_reserves(old_reserve_a, old_reserve_b),
        vault_a_with_balance(old_reserve_a),
        vault_b_with_balance(old_reserve_b),
        AccountForTests::user_holding_a(),
        AccountForTests::user_holding_b(),
        1,
        0,
        IdForTests::token_a_definition_id(),
    );

    let pool_post = post_states[0].clone();
    let pool_post_definition = PoolDefinition::try_from(&pool_post.account().data).unwrap();

    assert_eq!(pool_post_definition.reserve_a, u128::MAX - 1);
    assert_eq!(pool_post_definition.reserve_b, u128::MAX - 2);
    assert!(
        pool_post_definition
            .reserve_a
            .checked_mul(pool_post_definition.reserve_b)
            .is_none()
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

    let chained_call_lp = chained_calls[0].clone();
    assert!(chained_call_lp == ChainedCallForTests::cc_new_definition_token_lp());
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

    let chained_call_lp = chained_calls[0].clone();
    let expected_lp_call = ChainedCall::new(
        TOKEN_PROGRAM_ID,
        vec![
            AccountForTests::pool_lp_init(),
            AccountForTests::user_holding_lp_uninit(),
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
