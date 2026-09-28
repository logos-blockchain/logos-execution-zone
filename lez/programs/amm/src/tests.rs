#![cfg(test)]
#![expect(
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "fixtures compute overflow boundaries directly"
)]

use amm_core::{
    Instruction, PoolDefinition, compute_liquidity_token_pda, compute_liquidity_token_pda_seed,
    compute_pool_pda, compute_vault_pda, compute_vault_pda_seed,
};
use lee_core::{
    account::{AccountId, ProgramShardSelector, ShardData},
    program::{AccountMeta, PdaSeed, Plan, PlanInput},
};
use token_core::{TokenDescriptor, TokenKind};

use crate::{Effect, add::AddBinding, swap::SwapBinding};

const AMM_PROGRAM_ID: AccountId = AccountId::new([1; 32]);
const TOKEN_PROGRAM_ID: AccountId = AccountId::new([15; 32]);
const STRANGER_PROGRAM_ID: AccountId = AccountId::new([0xEE; 32]);
const TOKEN_A_ID: AccountId = AccountId::new([42; 32]);
const TOKEN_B_ID: AccountId = AccountId::new([43; 32]);
const USER_A_ID: AccountId = AccountId::new([45; 32]);
const USER_B_ID: AccountId = AccountId::new([46; 32]);
const USER_LP_ID: AccountId = AccountId::new([47; 32]);
const UNRELATED_ID: AccountId = AccountId::new([4; 32]);

const RESERVE_A: u128 = 1_000;
const RESERVE_B: u128 = 500;
// isqrt(RESERVE_A * RESERVE_B)
const LP_SUPPLY: u128 = 707;

const ADD_MAX_A: u128 = 500;
const ADD_MAX_B: u128 = 200;
const ADD_ACTUAL_A: u128 = 400;
const ADD_ACTUAL_B: u128 = 200;
const ADD_LP: u128 = 282;

const REMOVE_LP: u128 = 100;
const REMOVE_A: u128 = 141;
const REMOVE_B: u128 = 70;

fn pool_id() -> AccountId {
    compute_pool_pda(AMM_PROGRAM_ID, TOKEN_A_ID, TOKEN_B_ID, TOKEN_PROGRAM_ID)
}

fn vault_a_id() -> AccountId {
    compute_vault_pda(AMM_PROGRAM_ID, pool_id(), TOKEN_A_ID)
}

fn vault_b_id() -> AccountId {
    compute_vault_pda(AMM_PROGRAM_ID, pool_id(), TOKEN_B_ID)
}

fn token_lp_id() -> AccountId {
    compute_liquidity_token_pda(AMM_PROGRAM_ID, pool_id())
}

fn pool_base() -> PoolDefinition {
    PoolDefinition {
        token_program_id: TOKEN_PROGRAM_ID,
        definition_token_a_id: TOKEN_A_ID,
        definition_token_b_id: TOKEN_B_ID,
        vault_a_id: vault_a_id(),
        vault_b_id: vault_b_id(),
        liquidity_pool_id: token_lp_id(),
        liquidity_pool_supply: LP_SUPPLY,
        reserve_a: RESERVE_A,
        reserve_b: RESERVE_B,
        fees: 0,
        active: true,
    }
}

fn pool_shard(pool: &PoolDefinition) -> ShardData {
    ShardData::from(pool)
}

fn amm_handle(account_id: AccountId) -> AccountMeta {
    AccountMeta::new(account_id, true, AMM_PROGRAM_ID)
}

fn token_handle(account_id: AccountId) -> AccountMeta {
    AccountMeta::new(account_id, true, TOKEN_PROGRAM_ID)
}

fn liquidity_accounts() -> Vec<AccountMeta> {
    vec![
        amm_handle(pool_id()),
        token_handle(vault_a_id()),
        token_handle(vault_b_id()),
        token_handle(token_lp_id()),
        token_handle(USER_A_ID),
        token_handle(USER_B_ID),
        token_handle(USER_LP_ID),
    ]
}

fn definitions(input_is_token_a: bool) -> (AccountId, AccountId) {
    if input_is_token_a {
        (TOKEN_A_ID, TOKEN_B_ID)
    } else {
        (TOKEN_B_ID, TOKEN_A_ID)
    }
}

// Input vault, output vault, input holding, output holding.
fn swap_route(input_is_token_a: bool) -> [AccountId; 4] {
    if input_is_token_a {
        [vault_a_id(), vault_b_id(), USER_A_ID, USER_B_ID]
    } else {
        [vault_b_id(), vault_a_id(), USER_B_ID, USER_A_ID]
    }
}

fn swap_accounts(input_is_token_a: bool) -> Vec<AccountMeta> {
    std::iter::once(amm_handle(pool_id()))
        .chain(swap_route(input_is_token_a).map(token_handle))
        .collect()
}

// Drives the real entrypoint, so account arity, shard selection and every planner-side bound the
// instruction carries are on the path a test exercises.
fn plan_for(accounts: Vec<AccountMeta>, instruction: Instruction) -> Plan {
    crate::plan(
        &PlanInput {
            self_account_id: AMM_PROGRAM_ID,
            caller_account_id: None,
            accounts,
            instruction_data: borsh::to_vec(&instruction).expect("the instruction serializes"),
        },
        instruction,
    )
}

fn apply_to_pool(pool: &PoolDefinition, effect: Effect) -> PoolDefinition {
    let written =
        crate::apply(effect, &pool_shard(pool)).expect("a pool effect writes the pool shard");
    PoolDefinition::try_from(&written).expect("apply wrote a pool definition")
}

// Two positions of one guard are the same case only if they are refused for the same reason, so a
// table of positions reads the message rather than settling for any panic.
fn rejection(call: impl FnOnce() + std::panic::UnwindSafe) -> String {
    let payload = std::panic::catch_unwind(call).expect_err("the AMM accepted the proposal");
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

fn effect_of(plan: &Plan, index: usize) -> Effect {
    borsh::from_slice(&plan.output().effects[index].data).expect("the plan wrote its own effect")
}

fn selector_of(plan: &Plan, index: usize) -> ProgramShardSelector {
    plan.output().effects[index].selector
}

fn call_instruction(plan: &Plan, index: usize) -> token_core::Instruction {
    borsh::from_slice(&plan.output().chained_calls[index].instruction_data)
        .expect("the plan called the token program")
}

// `token_core::Instruction` carries no `PartialEq`, so the encodings are what a test compares.
fn assert_call(plan: &Plan, index: usize, instruction: &token_core::Instruction) {
    assert_eq!(
        plan.output().chained_calls[index].instruction_data,
        borsh::to_vec(instruction).expect("the instruction serializes"),
        "chained call {index} is not the expected token instruction"
    );
}

fn transferred(plan: &Plan, index: usize) -> (u128, TokenDescriptor) {
    let token_core::Instruction::Transfer {
        amount_to_transfer,
        descriptor,
    } = call_instruction(plan, index)
    else {
        panic!("chained call {index} is not a transfer");
    };
    (amount_to_transfer, descriptor)
}

// A seed authorizes the account it derives for the one call that carries it, so only a vault debit
// or an LP mint may carry one; a deposit or a burn needs only its sender's authority.
fn seeds(plan: &Plan) -> Vec<Vec<PdaSeed>> {
    plan.output()
        .chained_calls
        .iter()
        .map(|call| call.pda_seeds.clone())
        .collect()
}

fn fungible_of(definition_id: AccountId) -> TokenDescriptor {
    TokenDescriptor {
        definition_id,
        kind: TokenKind::Fungible,
    }
}

fn add_instruction(
    max_a: u128,
    max_b: u128,
    amount_a: u128,
    amount_b: u128,
    amount_liquidity: u128,
) -> Instruction {
    Instruction::AddLiquidity {
        max_amount_to_add_token_a: max_a,
        max_amount_to_add_token_b: max_b,
        token_program_id: TOKEN_PROGRAM_ID,
        definition_token_a_id: TOKEN_A_ID,
        definition_token_b_id: TOKEN_B_ID,
        amount_to_add_token_a: amount_a,
        amount_to_add_token_b: amount_b,
        amount_liquidity,
    }
}

fn add_successfully() -> Instruction {
    add_instruction(ADD_MAX_A, ADD_MAX_B, ADD_ACTUAL_A, ADD_ACTUAL_B, ADD_LP)
}

fn remove_instruction(
    remove_liquidity_amount: u128,
    amount_a: u128,
    amount_b: u128,
) -> Instruction {
    Instruction::RemoveLiquidity {
        remove_liquidity_amount,
        token_program_id: TOKEN_PROGRAM_ID,
        definition_token_a_id: TOKEN_A_ID,
        definition_token_b_id: TOKEN_B_ID,
        amount_to_remove_token_a: amount_a,
        amount_to_remove_token_b: amount_b,
    }
}

fn remove_successfully() -> Instruction {
    remove_instruction(REMOVE_LP, REMOVE_A, REMOVE_B)
}

fn new_definition_instruction(
    token_a_amount: u128,
    token_b_amount: u128,
    pool_is_empty: bool,
) -> Instruction {
    Instruction::NewDefinition {
        token_a_amount,
        token_b_amount,
        token_program_id: TOKEN_PROGRAM_ID,
        definition_token_a_id: TOKEN_A_ID,
        definition_token_b_id: TOKEN_B_ID,
        pool_is_empty,
    }
}

fn swap_instruction(input_is_token_a: bool, amount_in: u128, amount_out: u128) -> Instruction {
    let (definition_id_in, definition_id_out) = definitions(input_is_token_a);
    Instruction::Swap {
        token_program_id: TOKEN_PROGRAM_ID,
        definition_id_in,
        definition_id_out,
        amount_in,
        amount_out,
    }
}

fn swap_on(
    pool: &PoolDefinition,
    input_is_token_a: bool,
    amount_in: u128,
    amount_out: u128,
) -> PoolDefinition {
    let plan = plan_for(
        swap_accounts(input_is_token_a),
        swap_instruction(input_is_token_a, amount_in, amount_out),
    );
    apply_to_pool(pool, effect_of(&plan, 0))
}

fn swap_binding_of(plan: &Plan) -> SwapBinding {
    let Effect::Swap(binding) = effect_of(plan, 0) else {
        panic!("the first swap effect is the pool's");
    };
    binding
}

#[test]
fn pool_pda_produces_unique_id_for_token_pair() {
    assert_eq!(
        compute_pool_pda(AMM_PROGRAM_ID, TOKEN_A_ID, TOKEN_B_ID, TOKEN_PROGRAM_ID),
        compute_pool_pda(AMM_PROGRAM_ID, TOKEN_B_ID, TOKEN_A_ID, TOKEN_PROGRAM_ID)
    );
}

#[test]
fn the_pool_of_a_stranger_program_is_a_different_address() {
    assert_ne!(
        compute_pool_pda(AMM_PROGRAM_ID, TOKEN_A_ID, TOKEN_B_ID, TOKEN_PROGRAM_ID),
        compute_pool_pda(AMM_PROGRAM_ID, TOKEN_A_ID, TOKEN_B_ID, STRANGER_PROGRAM_ID),
        "each token program must get its own pool for a pair"
    );
}

#[test]
fn call_add_liquidity_zero_balance() {
    for (position, max_a, max_b) in [("Token A", 0, ADD_MAX_B), ("Token B", ADD_MAX_A, 0)] {
        assert!(
            rejection(|| {
                let _plan = plan_for(
                    liquidity_accounts(),
                    add_instruction(max_a, max_b, ADD_ACTUAL_A, ADD_ACTUAL_B, ADD_LP),
                );
            })
            .contains("Both max-balances must be nonzero"),
            "a zero max balance for {position} was accepted"
        );
    }
}

#[test]
fn call_add_liquidity_actual_amount_zero() {
    for (position, amount_a, amount_b) in
        [("Token A", 0, ADD_ACTUAL_B), ("Token B", ADD_ACTUAL_A, 0)]
    {
        assert!(
            rejection(|| {
                let _plan = plan_for(
                    liquidity_accounts(),
                    add_instruction(ADD_MAX_A, ADD_MAX_B, amount_a, amount_b, ADD_LP),
                );
            })
            .contains("A trade amount is 0"),
            "a zero deposit of {position} was accepted"
        );
    }
}

#[should_panic(expected = "Payable LP must be nonzero")]
#[test]
fn call_add_liquidity_payable_lp_zero() {
    let _plan = plan_for(
        liquidity_accounts(),
        add_instruction(ADD_MAX_A, ADD_MAX_B, ADD_ACTUAL_A, ADD_ACTUAL_B, 0),
    );
}

#[should_panic(expected = "Actual trade amounts cannot exceed max_amounts")]
#[test]
fn call_add_liquidity_actual_amount_above_max() {
    let _plan = plan_for(
        liquidity_accounts(),
        add_instruction(ADD_MAX_A, ADD_MAX_B, ADD_MAX_A + 1, ADD_ACTUAL_B, ADD_LP),
    );
}

// The pool's `apply`, not the planner, is what ties an add to the pool's real reserves: a caller
// who proposes the deposit that a larger pool would have priced is rejected there.
#[should_panic(expected = "Proposed Token A deposit does not match the pool's ideal amount")]
#[test]
fn add_liquidity_inflated_token_a_deposit_is_rejected() {
    let plan = plan_for(
        liquidity_accounts(),
        add_instruction(ADD_MAX_A, ADD_MAX_B, ADD_MAX_A, ADD_ACTUAL_B, ADD_LP),
    );
    let _pool = apply_to_pool(&pool_base(), effect_of(&plan, 0));
}

#[should_panic(expected = "Proposed Token B deposit does not match the pool's ideal amount")]
#[test]
fn add_liquidity_inflated_token_b_deposit_is_rejected() {
    let plan = plan_for(
        liquidity_accounts(),
        add_instruction(ADD_MAX_A, ADD_MAX_B, ADD_ACTUAL_A, ADD_ACTUAL_B - 1, ADD_LP),
    );
    let _pool = apply_to_pool(&pool_base(), effect_of(&plan, 0));
}

#[should_panic(expected = "Proposed LP amount does not match the pool's mint calculation")]
#[test]
fn add_liquidity_inflated_liquidity_mint_is_rejected() {
    let plan = plan_for(
        liquidity_accounts(),
        add_instruction(ADD_MAX_A, ADD_MAX_B, ADD_ACTUAL_A, ADD_ACTUAL_B, ADD_LP * 2),
    );
    let _pool = apply_to_pool(&pool_base(), effect_of(&plan, 0));
}

#[should_panic(expected = "Vault A was not provided")]
#[test]
fn call_add_liquidity_vault_a_omitted() {
    let mut accounts = liquidity_accounts();
    accounts[1] = token_handle(UNRELATED_ID);
    let plan = plan_for(accounts, add_successfully());
    let _pool = apply_to_pool(&pool_base(), effect_of(&plan, 0));
}

#[should_panic(expected = "Vault B was not provided")]
#[test]
fn call_add_liquidity_vault_b_omitted() {
    let mut accounts = liquidity_accounts();
    accounts[2] = token_handle(UNRELATED_ID);
    let plan = plan_for(accounts, add_successfully());
    let _pool = apply_to_pool(&pool_base(), effect_of(&plan, 0));
}

#[should_panic(expected = "LP definition mismatch")]
#[test]
fn call_add_liquidity_lp_definition_mismatch() {
    let mut accounts = liquidity_accounts();
    accounts[3] = token_handle(UNRELATED_ID);
    let plan = plan_for(accounts, add_successfully());
    let _pool = apply_to_pool(&pool_base(), effect_of(&plan, 0));
}

#[test]
fn call_add_liquidity_reserves_zero() {
    let plan = plan_for(liquidity_accounts(), add_successfully());
    let effect = effect_of(&plan, 0);
    let cases = [
        (
            "Token A",
            PoolDefinition {
                reserve_a: 0,
                ..pool_base()
            },
        ),
        (
            "Token B",
            PoolDefinition {
                reserve_b: 0,
                ..pool_base()
            },
        ),
    ];

    for (position, pool) in cases {
        assert!(
            rejection(|| {
                let _pool = apply_to_pool(&pool, effect.clone());
            })
            .contains("Reserves must be nonzero"),
            "an empty {position} reserve was accepted"
        );
    }
}

#[should_panic(expected = "Add liquidity routes through a token program the pool does not use")]
#[test]
fn add_liquidity_through_a_foreign_token_program_is_rejected() {
    let plan = plan_for(liquidity_accounts(), add_successfully());
    let Effect::AddLiquidity(binding) = effect_of(&plan, 0) else {
        panic!("the first add effect is the pool's");
    };
    let forged = Effect::AddLiquidity(AddBinding {
        token_program_id: STRANGER_PROGRAM_ID,
        ..binding
    });
    let _pool = apply_to_pool(&pool_base(), forged);
}

#[test]
fn call_add_liquidity_chained_call_successsful() {
    let plan = plan_for(liquidity_accounts(), add_successfully());
    let Effect::AddLiquidity(binding) = effect_of(&plan, 0) else {
        panic!("the first add effect is the pool's");
    };

    let pool = apply_to_pool(&pool_base(), effect_of(&plan, 0));
    assert_eq!(
        pool,
        PoolDefinition {
            liquidity_pool_supply: LP_SUPPLY + ADD_LP,
            reserve_a: RESERVE_A + ADD_ACTUAL_A,
            reserve_b: RESERVE_B + ADD_ACTUAL_B,
            ..pool_base()
        }
    );

    // The amounts the pool effect is checked against and the amounts the token program is asked to
    // move are one and the same value, so a guard on one cannot be satisfied by a different
    // transfer.
    assert_eq!(
        (
            binding.amount_to_add_token_a,
            binding.amount_to_add_token_b,
            binding.amount_liquidity
        ),
        (ADD_ACTUAL_A, ADD_ACTUAL_B, ADD_LP)
    );
    assert_call(
        &plan,
        0,
        &token_core::Instruction::Mint {
            amount_to_mint: binding.amount_liquidity,
        },
    );
    assert_eq!(
        seeds(&plan),
        vec![
            vec![compute_liquidity_token_pda_seed(pool_id())],
            vec![],
            vec![]
        ]
    );
    assert_eq!(
        transferred(&plan, 1),
        (binding.amount_to_add_token_b, fungible_of(TOKEN_B_ID))
    );
    assert_eq!(
        transferred(&plan, 2),
        (binding.amount_to_add_token_a, fungible_of(TOKEN_A_ID))
    );
    assert_eq!(
        plan.output().chained_calls[2].shard_selectors,
        vec![
            ProgramShardSelector::new(USER_A_ID, TOKEN_PROGRAM_ID),
            ProgramShardSelector::new(vault_a_id(), TOKEN_PROGRAM_ID),
        ]
    );
}

#[should_panic(expected = "Remove liquidity amount must be nonzero")]
#[test]
fn call_remove_liquidity_amount_zero() {
    let _plan = plan_for(liquidity_accounts(), remove_instruction(0, 0, 0));
}

#[test]
fn call_remove_liquidity_withdraw_amount_zero() {
    for (position, amount_a, amount_b) in [("Token A", 0, REMOVE_B), ("Token B", REMOVE_A, 0)] {
        assert!(
            rejection(|| {
                let _plan = plan_for(
                    liquidity_accounts(),
                    remove_instruction(REMOVE_LP, amount_a, amount_b),
                );
            })
            .contains("Withdraw amounts must be nonzero"),
            "a zero withdrawal of {position} was accepted"
        );
    }
}

#[should_panic(expected = "Withdraw amounts must be nonzero")]
#[test]
fn remove_liquidity_worth_nothing_of_one_token_is_refused() {
    // The pool's own price for one LP, so only the planner keeps the burn from paying out nothing.
    let amount_a = amm_core::withdrawal_share(RESERVE_A, 1, LP_SUPPLY).expect("the share fits");
    let amount_b = amm_core::withdrawal_share(RESERVE_B, 1, LP_SUPPLY).expect("the share fits");
    assert_eq!((amount_a, amount_b), (1, 0));
    let _plan = plan_for(
        liquidity_accounts(),
        remove_instruction(1, amount_a, amount_b),
    );
}

#[should_panic(expected = "Pool is inactive")]
#[test]
fn call_remove_liquidity_inactive() {
    let plan = plan_for(liquidity_accounts(), remove_successfully());
    let pool = PoolDefinition {
        active: false,
        ..pool_base()
    };
    let _pool = apply_to_pool(&pool, effect_of(&plan, 0));
}

#[should_panic(expected = "Vault A was not provided")]
#[test]
fn call_remove_liquidity_vault_a_omitted() {
    let mut accounts = liquidity_accounts();
    accounts[1] = token_handle(UNRELATED_ID);
    let plan = plan_for(accounts, remove_successfully());
    let _pool = apply_to_pool(&pool_base(), effect_of(&plan, 0));
}

#[should_panic(expected = "Vault B was not provided")]
#[test]
fn call_remove_liquidity_vault_b_omitted() {
    let mut accounts = liquidity_accounts();
    accounts[2] = token_handle(UNRELATED_ID);
    let plan = plan_for(accounts, remove_successfully());
    let _pool = apply_to_pool(&pool_base(), effect_of(&plan, 0));
}

#[should_panic(expected = "LP definition mismatch")]
#[test]
fn call_remove_liquidity_lp_def_mismatch() {
    let mut accounts = liquidity_accounts();
    accounts[3] = token_handle(UNRELATED_ID);
    let plan = plan_for(accounts, remove_successfully());
    let _pool = apply_to_pool(&pool_base(), effect_of(&plan, 0));
}

#[should_panic(
    expected = "Proposed Token A withdrawal does not match the pool's removal calculation"
)]
#[test]
fn remove_liquidity_inflated_withdrawal_is_rejected() {
    let plan = plan_for(
        liquidity_accounts(),
        remove_instruction(REMOVE_LP, RESERVE_A, REMOVE_B),
    );
    let _pool = apply_to_pool(&pool_base(), effect_of(&plan, 0));
}

// 708 LP of a 707 supply would price at 1,001 A / 500 B, so an `apply` that computed the shares
// before checking the supply would accept these and then underflow the reserves.
#[should_panic(expected = "Removal burns more LP than the pool's supply")]
#[test]
fn remove_liquidity_refuses_burning_more_lp_than_the_supply() {
    let plan = plan_for(
        liquidity_accounts(),
        remove_instruction(LP_SUPPLY + 1, 1_001, 500),
    );
    let _pool = apply_to_pool(&pool_base(), effect_of(&plan, 0));
}

#[test]
fn call_remove_liquidity_chained_call_successful() {
    let plan = plan_for(liquidity_accounts(), remove_successfully());
    let Effect::RemoveLiquidity(binding) = effect_of(&plan, 0) else {
        panic!("the first remove effect is the pool's");
    };

    let pool = apply_to_pool(&pool_base(), effect_of(&plan, 0));
    assert_eq!(
        pool,
        PoolDefinition {
            liquidity_pool_supply: LP_SUPPLY - REMOVE_LP,
            reserve_a: RESERVE_A - REMOVE_A,
            reserve_b: RESERVE_B - REMOVE_B,
            ..pool_base()
        }
    );

    // The amounts the pool effect is checked against and the amounts the token program is asked to
    // move are one and the same value, so a guard on one cannot be satisfied by a different
    // transfer.
    assert_eq!(
        (
            binding.amount_to_remove_token_a,
            binding.amount_to_remove_token_b,
            binding.remove_liquidity_amount
        ),
        (REMOVE_A, REMOVE_B, REMOVE_LP)
    );
    assert_call(
        &plan,
        0,
        &token_core::Instruction::Burn {
            amount_to_burn: binding.remove_liquidity_amount,
            kind: TokenKind::Fungible,
        },
    );
    assert_eq!(
        transferred(&plan, 1),
        (binding.amount_to_remove_token_b, fungible_of(TOKEN_B_ID))
    );
    assert_eq!(
        transferred(&plan, 2),
        (binding.amount_to_remove_token_a, fungible_of(TOKEN_A_ID))
    );
    assert_eq!(
        seeds(&plan),
        vec![
            vec![],
            vec![compute_vault_pda_seed(pool_id(), TOKEN_B_ID)],
            vec![compute_vault_pda_seed(pool_id(), TOKEN_A_ID)],
        ]
    );
}

#[test]
fn remove_liquidity_full_drain_deactivates_the_pool() {
    let plan = plan_for(
        liquidity_accounts(),
        remove_instruction(LP_SUPPLY, RESERVE_A, RESERVE_B),
    );
    let pool = apply_to_pool(&pool_base(), effect_of(&plan, 0));

    assert_eq!(
        pool,
        PoolDefinition {
            liquidity_pool_supply: 0,
            reserve_a: 0,
            reserve_b: 0,
            active: false,
            ..pool_base()
        }
    );
}

#[should_panic(expected = "Token A should have a nonzero amount")]
#[test]
fn call_new_definition_with_zero_balance_1() {
    let _plan = plan_for(
        liquidity_accounts(),
        new_definition_instruction(0, RESERVE_B, true),
    );
}

#[should_panic(expected = "Token B should have a nonzero amount")]
#[test]
fn call_new_definition_with_zero_balance_2() {
    let _plan = plan_for(
        liquidity_accounts(),
        new_definition_instruction(RESERVE_A, 0, true),
    );
}

#[should_panic(expected = "Cannot set up a swap for a token with itself")]
#[test]
fn call_new_definition_same_token_definition() {
    let _plan = plan_for(
        liquidity_accounts(),
        Instruction::NewDefinition {
            token_a_amount: RESERVE_A,
            token_b_amount: RESERVE_B,
            token_program_id: TOKEN_PROGRAM_ID,
            definition_token_a_id: TOKEN_A_ID,
            definition_token_b_id: TOKEN_A_ID,
            pool_is_empty: true,
        },
    );
}

#[should_panic(expected = "Pool Definition Account ID does not match PDA")]
#[test]
fn call_new_definition_wrong_pool_id() {
    let mut accounts = liquidity_accounts();
    accounts[0] = amm_handle(UNRELATED_ID);
    let _plan = plan_for(
        accounts,
        new_definition_instruction(RESERVE_A, RESERVE_B, true),
    );
}

#[test]
fn call_new_definition_wrong_vault_id() {
    for (position, index) in [("Vault A", 1), ("Vault B", 2)] {
        assert!(
            rejection(|| {
                let mut accounts = liquidity_accounts();
                accounts[index] = token_handle(UNRELATED_ID);
                let _plan = plan_for(
                    accounts,
                    new_definition_instruction(RESERVE_A, RESERVE_B, true),
                );
            })
            .contains("Vault ID does not match PDA"),
            "{position} was accepted at an address that is not its PDA"
        );
    }
}

#[should_panic(expected = "Liquidity pool Token Definition Account ID does not match PDA")]
#[test]
fn call_new_definition_wrong_liquidity_id() {
    let mut accounts = liquidity_accounts();
    accounts[3] = token_handle(UNRELATED_ID);
    let _plan = plan_for(
        accounts,
        new_definition_instruction(RESERVE_A, RESERVE_B, true),
    );
}

#[should_panic(expected = "Cannot initialize an active Pool Definition")]
#[test]
fn call_new_definition_cannot_initialize_active_pool() {
    let plan = plan_for(
        liquidity_accounts(),
        new_definition_instruction(RESERVE_A, RESERVE_B, false),
    );
    let _pool = apply_to_pool(&pool_base(), effect_of(&plan, 0));
}

#[should_panic(expected = "Pool emptiness does not match the planned initialization branch")]
#[test]
fn new_definition_empty_branch_against_an_initialized_pool_is_rejected() {
    let plan = plan_for(
        liquidity_accounts(),
        new_definition_instruction(RESERVE_A, RESERVE_B, true),
    );
    let inactive = PoolDefinition {
        active: false,
        ..pool_base()
    };
    let _pool = apply_to_pool(&inactive, effect_of(&plan, 0));
}

#[should_panic(expected = "Pool emptiness does not match the planned initialization branch")]
#[test]
fn new_definition_inactive_branch_against_an_empty_pool_is_rejected() {
    let plan = plan_for(
        liquidity_accounts(),
        new_definition_instruction(RESERVE_A, RESERVE_B, false),
    );
    let written = crate::apply(effect_of(&plan, 0), &ShardData::empty());
    let _written = written.expect("a pool effect writes the pool shard");
}

#[test]
fn new_definition_uninitialized_pool_creates_the_liquidity_definition() {
    let plan = plan_for(
        liquidity_accounts(),
        new_definition_instruction(RESERVE_A, RESERVE_B, true),
    );
    let effect = effect_of(&plan, 0);
    let Effect::InitializePool { definition, .. } = &effect else {
        panic!("the new definition effect is the pool's");
    };

    let written = crate::apply(effect.clone(), &ShardData::empty())
        .expect("a pool effect writes the pool shard");
    let pool = PoolDefinition::try_from(&written).expect("apply wrote a pool definition");
    assert_eq!(pool, pool_base());

    // The supply the pool records and the supply the LP definition is created with are one value.
    assert_call(
        &plan,
        0,
        &token_core::Instruction::NewFungibleDefinition {
            name: String::from("LP Token"),
            total_supply: definition.liquidity_pool_supply,
        },
    );
    assert_eq!(
        transferred(&plan, 1),
        (definition.reserve_b, fungible_of(TOKEN_B_ID))
    );
    assert_eq!(
        transferred(&plan, 2),
        (definition.reserve_a, fungible_of(TOKEN_A_ID))
    );
    assert_eq!(
        seeds(&plan),
        vec![
            vec![compute_liquidity_token_pda_seed(pool_id())],
            vec![],
            vec![]
        ]
    );
}

#[test]
fn new_definition_lp_asymmetric_amounts() {
    let plan = plan_for(
        liquidity_accounts(),
        new_definition_instruction(RESERVE_A, RESERVE_B, false),
    );

    let inactive = PoolDefinition {
        active: false,
        liquidity_pool_supply: 1,
        ..pool_base()
    };
    let pool = apply_to_pool(&inactive, effect_of(&plan, 0));
    assert_eq!(pool.liquidity_pool_supply, LP_SUPPLY);

    assert_call(
        &plan,
        0,
        &token_core::Instruction::Mint {
            amount_to_mint: LP_SUPPLY,
        },
    );
    assert_eq!(
        seeds(&plan),
        vec![
            vec![compute_liquidity_token_pda_seed(pool_id())],
            vec![],
            vec![]
        ]
    );
}

#[test]
fn new_definition_lp_symmetric_amounts() {
    // token_a = 100, token_b = 100 -> LP = sqrt(10_000) = 100
    let plan = plan_for(
        liquidity_accounts(),
        new_definition_instruction(100, 100, true),
    );

    let written = crate::apply(effect_of(&plan, 0), &ShardData::empty())
        .expect("a pool effect writes the pool shard");
    let pool = PoolDefinition::try_from(&written).expect("apply wrote a pool definition");

    assert_eq!(pool.liquidity_pool_supply, 100);
    assert_call(
        &plan,
        0,
        &token_core::Instruction::NewFungibleDefinition {
            name: String::from("LP Token"),
            total_supply: 100,
        },
    );
}

// Reserves are 1,000 A / 500 B, so a leg read against the wrong reserve prices differently. Every
// expected pool below is worked out by hand from `amount_out <= floor(Y * I / (X + I))`: 500 A
// quotes 166 B, 99 A quotes 45 B while 98 A quotes 44 B, and 200 B quotes 285 A. An offer below
// its quote settles too, leaving the surplus in the reserves.
#[test]
fn a_swap_settles_any_offer_the_live_curve_can_afford() {
    let (a_to_b, b_to_a) = (true, false);
    let with_reserves = |reserve_a, reserve_b| PoolDefinition {
        reserve_a,
        reserve_b,
        ..pool_base()
    };
    let settles = |input_is_token_a, amount_in, amount_out, (reserve_a, reserve_b)| {
        assert_eq!(
            swap_on(&pool_base(), input_is_token_a, amount_in, amount_out),
            with_reserves(reserve_a, reserve_b),
            "{amount_in} for {amount_out} (input is token A: {input_is_token_a})"
        );
    };
    let refuses = |pool: PoolDefinition, input_is_token_a, amount_in, amount_out, message: &str| {
        let refusal = rejection(|| {
            let _pool = swap_on(&pool, input_is_token_a, amount_in, amount_out);
        });
        assert!(
            refusal.contains(message),
            "{amount_in} for {amount_out} (input is token A: {input_is_token_a}): {refusal}"
        );
    };

    settles(a_to_b, 500, 166, (1_500, 334));
    settles(a_to_b, 500, 100, (1_500, 400));
    settles(a_to_b, 150, 45, (1_150, 455));
    settles(a_to_b, 99, 45, (1_099, 455));
    settles(b_to_a, 200, 285, (715, 700));
    settles(b_to_a, 200, 250, (750, 700));

    let cannot_afford = "The pool cannot afford this offer at its live price";
    refuses(pool_base(), a_to_b, 500, 167, cannot_afford);
    refuses(pool_base(), a_to_b, 98, 45, cannot_afford);
    refuses(pool_base(), b_to_a, 200, 286, cannot_afford);
    let zero = "Swap amounts must be nonzero";
    refuses(pool_base(), a_to_b, 0, 45, zero);
    refuses(pool_base(), a_to_b, 99, 0, zero);
    refuses(pool_base(), b_to_a, 0, 250, zero);
    let exhausts = "Swap output exhausts the reserve";
    refuses(pool_base(), a_to_b, 1_000_000, 500, exhausts);
    refuses(pool_base(), b_to_a, 1_000_000, 1_000, exhausts);
    let inactive = PoolDefinition {
        active: false,
        ..pool_base()
    };
    refuses(inactive.clone(), a_to_b, 500, 166, "Pool is inactive");
    refuses(inactive, b_to_a, 200, 285, "Pool is inactive");
    let empty = "Pool reserves must be nonzero";
    refuses(with_reserves(0, RESERVE_B), a_to_b, 500, 1, empty);
    refuses(with_reserves(0, RESERVE_B), b_to_a, 200, 1, empty);
    let (huge, overflow) = (u128::MAX / 2 + 1, "overflows u128");
    refuses(with_reserves(RESERVE_A, huge), a_to_b, 2, 1, overflow);
    refuses(with_reserves(huge, RESERVE_B), b_to_a, 2, 1, overflow);
    refuses(with_reserves(u128::MAX, RESERVE_B), a_to_b, 1, 1, overflow);
}

#[test]
fn a_swap_refuses_a_forged_binding() {
    for input_is_token_a in [true, false] {
        let binding = swap_binding_of(&plan_for(
            swap_accounts(input_is_token_a),
            swap_instruction(input_is_token_a, 100, 1),
        ));
        let forgeries = [
            (
                "token program",
                "Swap routes through a token program the pool does not use",
                SwapBinding {
                    token_program_id: STRANGER_PROGRAM_ID,
                    ..binding
                },
            ),
            (
                "input definition",
                "AccountId is not a token type for the pool",
                SwapBinding {
                    definition_id_in: token_lp_id(),
                    ..binding
                },
            ),
            (
                "output definition",
                "AccountId is not a token type for the pool",
                SwapBinding {
                    definition_id_out: binding.definition_id_in,
                    ..binding
                },
            ),
            (
                "input vault",
                "Input vault was not provided",
                SwapBinding {
                    input_vault_id: UNRELATED_ID,
                    ..binding
                },
            ),
            (
                "output vault",
                "Output vault was not provided",
                SwapBinding {
                    output_vault_id: UNRELATED_ID,
                    ..binding
                },
            ),
            // Both are real vaults of the pool, each on the other leg.
            (
                "vault order",
                "Input vault was not provided",
                SwapBinding {
                    input_vault_id: binding.output_vault_id,
                    output_vault_id: binding.input_vault_id,
                    ..binding
                },
            ),
        ];
        for (field, message, forged) in forgeries {
            assert!(
                rejection(|| {
                    let _pool = apply_to_pool(&pool_base(), Effect::Swap(forged));
                })
                .contains(message),
                "a forged {field} was accepted (input is token A: {input_is_token_a})"
            );
        }
    }
}

// The offer, not the quote, is what moves: the surplus these offers leave stays in the pool.
#[test]
fn a_swap_pays_the_signed_amounts_and_seeds_only_the_withdrawal() {
    for (input_is_token_a, amount_in, amount_out) in [(true, 500, 100), (false, 200, 250)] {
        let (definition_id_in, definition_id_out) = definitions(input_is_token_a);
        let [input_vault, output_vault, user_input, user_output] = swap_route(input_is_token_a);
        let plan = plan_for(
            swap_accounts(input_is_token_a),
            swap_instruction(input_is_token_a, amount_in, amount_out),
        );

        assert_eq!(plan.output().effects.len(), 1);
        assert_eq!(
            selector_of(&plan, 0),
            ProgramShardSelector::new(pool_id(), AMM_PROGRAM_ID)
        );
        assert_eq!(
            swap_binding_of(&plan),
            SwapBinding {
                token_program_id: TOKEN_PROGRAM_ID,
                input_vault_id: input_vault,
                output_vault_id: output_vault,
                definition_id_in,
                definition_id_out,
                amount_in,
                amount_out,
            }
        );

        let calls = &plan.output().chained_calls;
        assert_eq!(calls.len(), 2);
        assert_eq!(
            transferred(&plan, 0),
            (amount_in, fungible_of(definition_id_in))
        );
        assert_eq!(
            calls[0].shard_selectors,
            vec![
                ProgramShardSelector::new(user_input, TOKEN_PROGRAM_ID),
                ProgramShardSelector::new(input_vault, TOKEN_PROGRAM_ID),
            ]
        );
        assert_eq!(
            transferred(&plan, 1),
            (amount_out, fungible_of(definition_id_out))
        );
        assert_eq!(
            calls[1].shard_selectors,
            vec![
                ProgramShardSelector::new(output_vault, TOKEN_PROGRAM_ID),
                ProgramShardSelector::new(user_output, TOKEN_PROGRAM_ID),
            ]
        );
        assert_eq!(
            seeds(&plan),
            vec![
                vec![],
                vec![compute_vault_pda_seed(pool_id(), definition_id_out)]
            ]
        );
    }
}

#[test]
fn a_swap_refuses_a_trader_holding_that_is_a_vault() {
    for input_is_token_a in [true, false] {
        let [input_vault, output_vault, ..] = swap_route(input_is_token_a);
        for (endpoint, index) in [("input holding", 3), ("output holding", 4)] {
            for vault in [input_vault, output_vault] {
                let mut accounts = swap_accounts(input_is_token_a);
                accounts[index] = token_handle(vault);
                assert!(
                    rejection(|| {
                        let _plan = plan_for(accounts, swap_instruction(input_is_token_a, 99, 45));
                    })
                    .contains("A trader holding cannot be a pool vault"),
                    "the {endpoint} was accepted as the vault {vault}"
                );
            }
        }
    }
}

#[should_panic(expected = "names the shard of")]
#[test]
fn a_swap_pool_row_must_name_the_amm_shard() {
    let mut accounts = swap_accounts(true);
    accounts[0] = token_handle(pool_id());
    let _plan = plan_for(accounts, swap_instruction(true, 99, 45));
}
