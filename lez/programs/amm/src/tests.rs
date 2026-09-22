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
    program::{AccountMeta, Plan, ProgramInput, ResolveInput},
};
use token_core::{TokenDescriptor, TokenHolding, TokenKind};

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
const ADD_MIN_LP: u128 = 20;
const ADD_ACTUAL_A: u128 = 400;
const ADD_ACTUAL_B: u128 = 200;
const ADD_LP: u128 = 282;

const REMOVE_LP: u128 = 100;
const REMOVE_MIN_A: u128 = 50;
const REMOVE_MIN_B: u128 = 50;
const REMOVE_A: u128 = 141;
const REMOVE_B: u128 = 70;

const SWAP_IN_A: u128 = 500;
const SWAP_OUT_B: u128 = 166;
const SWAP_IN_B: u128 = 200;
const SWAP_OUT_A: u128 = 285;
const EXACT_OUT_DEPOSIT_A: u128 = 498;
const EXACT_OUT_DEPOSIT_B: u128 = 200;

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

fn fungible(definition_id: AccountId, balance: u128) -> ShardData {
    ShardData::from(&TokenHolding::Fungible {
        definition_id,
        balance,
    })
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

fn swap_accounts() -> Vec<AccountMeta> {
    vec![
        amm_handle(pool_id()),
        token_handle(vault_a_id()),
        token_handle(vault_b_id()),
        token_handle(USER_A_ID),
        token_handle(USER_B_ID),
    ]
}

// Drives the real entrypoint, so account arity, shard selection and every planner-side bound the
// instruction carries are on the path a test exercises.
fn plan_for(accounts: Vec<AccountMeta>, instruction: Instruction) -> Plan {
    let instruction_data = borsh::to_vec(&instruction).expect("the instruction serializes");
    crate::execute(
        ProgramInput {
            self_account_id: AMM_PROGRAM_ID,
            caller_account_id: None,
            accounts,
            instruction,
        },
        instruction_data,
    )
}

fn resolve_on(
    account_id: AccountId,
    program_account_id: AccountId,
    pre_data: ShardData,
    effect: &Effect,
) -> Option<ShardData> {
    crate::resolve(&ResolveInput {
        self_account_id: AMM_PROGRAM_ID,
        selector: ProgramShardSelector::new(account_id, program_account_id),
        pre_data,
        effect_data: borsh::to_vec(effect).expect("the effect serializes"),
    })
}

fn resolve_pool(pool: &PoolDefinition, effect: &Effect) -> PoolDefinition {
    let written = resolve_on(pool_id(), AMM_PROGRAM_ID, pool_shard(pool), effect)
        .expect("a pool effect writes the pool shard");
    PoolDefinition::try_from(&written).expect("the resolver wrote a pool definition")
}

fn resolve_vault(account_id: AccountId, pre_data: ShardData, effect: &Effect) {
    let kept = resolve_on(account_id, TOKEN_PROGRAM_ID, pre_data, effect);
    assert!(kept.is_none(), "a token holding guard must never write");
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

fn fungible_of(definition_id: AccountId) -> TokenDescriptor {
    TokenDescriptor {
        definition_id,
        kind: TokenKind::Fungible,
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "mirrors the instruction's fields"
)]
fn add_instruction(
    min_amount_liquidity: u128,
    max_a: u128,
    max_b: u128,
    amount_a: u128,
    amount_b: u128,
    amount_liquidity: u128,
    reserve_bound_a: u128,
    reserve_bound_b: u128,
) -> Instruction {
    Instruction::AddLiquidity {
        min_amount_liquidity,
        max_amount_to_add_token_a: max_a,
        max_amount_to_add_token_b: max_b,
        token_program_id: TOKEN_PROGRAM_ID,
        definition_token_a_id: TOKEN_A_ID,
        definition_token_b_id: TOKEN_B_ID,
        amount_to_add_token_a: amount_a,
        amount_to_add_token_b: amount_b,
        amount_liquidity,
        reserve_bound_a,
        reserve_bound_b,
    }
}

fn add_successfully() -> Instruction {
    add_instruction(
        ADD_MIN_LP,
        ADD_MAX_A,
        ADD_MAX_B,
        ADD_ACTUAL_A,
        ADD_ACTUAL_B,
        ADD_LP,
        RESERVE_A,
        RESERVE_B,
    )
}

fn remove_instruction(
    remove_liquidity_amount: u128,
    min_a: u128,
    min_b: u128,
    amount_a: u128,
    amount_b: u128,
    burned: u128,
) -> Instruction {
    Instruction::RemoveLiquidity {
        remove_liquidity_amount,
        min_amount_to_remove_token_a: min_a,
        min_amount_to_remove_token_b: min_b,
        token_program_id: TOKEN_PROGRAM_ID,
        definition_token_a_id: TOKEN_A_ID,
        definition_token_b_id: TOKEN_B_ID,
        amount_to_remove_token_a: amount_a,
        amount_to_remove_token_b: amount_b,
        amount_liquidity_burned: burned,
        liquidity_supply_bound: LP_SUPPLY,
    }
}

fn remove_successfully() -> Instruction {
    remove_instruction(
        REMOVE_LP,
        REMOVE_MIN_A,
        REMOVE_MIN_B,
        REMOVE_A,
        REMOVE_B,
        REMOVE_LP,
    )
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

fn exact_input(
    swap_amount_in: u128,
    min_amount_out: u128,
    amount_out: u128,
    input_is_token_a: bool,
) -> Instruction {
    let (definition_in, definition_out) = if input_is_token_a {
        (TOKEN_A_ID, TOKEN_B_ID)
    } else {
        (TOKEN_B_ID, TOKEN_A_ID)
    };
    Instruction::SwapExactInput {
        swap_amount_in,
        min_amount_out,
        token_definition_id_in: definition_in,
        token_program_id: TOKEN_PROGRAM_ID,
        token_definition_id_out: definition_out,
        input_is_token_a,
        amount_out,
        reserve_bound_a: RESERVE_A,
        reserve_bound_b: RESERVE_B,
    }
}

fn exact_output(
    exact_amount_out: u128,
    max_amount_in: u128,
    amount_in: u128,
    input_is_token_a: bool,
) -> Instruction {
    let (definition_in, definition_out) = if input_is_token_a {
        (TOKEN_A_ID, TOKEN_B_ID)
    } else {
        (TOKEN_B_ID, TOKEN_A_ID)
    };
    Instruction::SwapExactOutput {
        exact_amount_out,
        max_amount_in,
        token_definition_id_in: definition_in,
        token_program_id: TOKEN_PROGRAM_ID,
        token_definition_id_out: definition_out,
        input_is_token_a,
        amount_in,
        reserve_bound_a: RESERVE_A,
        reserve_bound_b: RESERVE_B,
    }
}

fn swap_binding_of(plan: &Plan) -> SwapBinding {
    match effect_of(plan, 0) {
        Effect::SwapExactInput(binding) | Effect::SwapExactOutput(binding) => binding,
        Effect::InitializePool { .. }
        | Effect::AddLiquidity(_)
        | Effect::RemoveLiquidity(_)
        | Effect::VaultCovers { .. }
        | Effect::LiquidityHoldingIsBounded { .. }
        | Effect::HoldingIsDefinedBy { .. } => panic!("the first swap effect is the pool's"),
    }
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

#[should_panic(expected = "The AMM Program resolves pool effects on its own shard")]
#[test]
fn a_pool_effect_aimed_at_a_foreign_shard_is_rejected() {
    let plan = plan_for(swap_accounts(), exact_input(SWAP_IN_A, 0, SWAP_OUT_B, true));
    let _kept = resolve_on(
        pool_id(),
        TOKEN_PROGRAM_ID,
        pool_shard(&pool_base()),
        &effect_of(&plan, 0),
    );
}

#[should_panic(expected = "The AMM Program inspects token holdings on the pool's token program")]
#[test]
fn a_vault_guard_aimed_at_a_foreign_shard_is_rejected() {
    let plan = plan_for(swap_accounts(), exact_input(SWAP_IN_A, 0, SWAP_OUT_B, true));
    // The AMM's own shard is exactly the shard a `== self_account_id` pin would have accepted, and
    // it is one an attacker can fill: the vault guard must name the pool's token program instead.
    let _kept = resolve_on(
        vault_a_id(),
        AMM_PROGRAM_ID,
        fungible(TOKEN_A_ID, RESERVE_A),
        &effect_of(&plan, 1),
    );
}

#[should_panic(expected = "The AMM Program inspects token holdings on the pool's token program")]
#[test]
fn a_new_definition_holding_guard_aimed_at_a_foreign_shard_is_rejected() {
    let plan = plan_for(
        liquidity_accounts(),
        new_definition_instruction(RESERVE_A, RESERVE_B, true),
    );
    let _kept = resolve_on(
        USER_A_ID,
        AMM_PROGRAM_ID,
        fungible(TOKEN_A_ID, RESERVE_A),
        &effect_of(&plan, 0),
    );
}

#[test]
fn every_amm_guard_names_the_shard_it_parses() {
    let plan = plan_for(swap_accounts(), exact_input(SWAP_IN_A, 0, SWAP_OUT_B, true));

    assert_eq!(selector_of(&plan, 0).program_account_id, AMM_PROGRAM_ID);
    assert_eq!(selector_of(&plan, 1).program_account_id, TOKEN_PROGRAM_ID);
    assert_eq!(selector_of(&plan, 2).program_account_id, TOKEN_PROGRAM_ID);
}

#[test]
fn call_add_liquidity_zero_balance() {
    for (position, max_a, max_b) in [("Token A", 0, ADD_MAX_B), ("Token B", ADD_MAX_A, 0)] {
        assert!(
            rejection(|| {
                let _plan = plan_for(
                    liquidity_accounts(),
                    add_instruction(
                        ADD_MIN_LP,
                        max_a,
                        max_b,
                        ADD_ACTUAL_A,
                        ADD_ACTUAL_B,
                        ADD_LP,
                        RESERVE_A,
                        RESERVE_B,
                    ),
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
                    add_instruction(
                        ADD_MIN_LP, ADD_MAX_A, ADD_MAX_B, amount_a, amount_b, ADD_LP, RESERVE_A,
                        RESERVE_B,
                    ),
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
        add_instruction(
            ADD_MIN_LP,
            ADD_MAX_A,
            ADD_MAX_B,
            ADD_ACTUAL_A,
            ADD_ACTUAL_B,
            0,
            RESERVE_A,
            RESERVE_B,
        ),
    );
}

#[should_panic(expected = "Payable LP is less than provided minimum LP amount")]
#[test]
fn call_add_liquidity_payable_lp_below_minimum() {
    let _plan = plan_for(
        liquidity_accounts(),
        add_instruction(
            ADD_LP + 1,
            ADD_MAX_A,
            ADD_MAX_B,
            ADD_ACTUAL_A,
            ADD_ACTUAL_B,
            ADD_LP,
            RESERVE_A,
            RESERVE_B,
        ),
    );
}

#[should_panic(expected = "Actual trade amounts cannot exceed max_amounts")]
#[test]
fn call_add_liquidity_actual_amount_above_max() {
    let _plan = plan_for(
        liquidity_accounts(),
        add_instruction(
            ADD_MIN_LP,
            ADD_MAX_A,
            ADD_MAX_B,
            ADD_MAX_A + 1,
            ADD_ACTUAL_B,
            ADD_LP,
            RESERVE_A,
            RESERVE_B,
        ),
    );
}

// The pool resolver, not the planner, is what ties an add to the pool's real reserves: a caller
// who proposes the deposit that a larger pool would have priced is rejected there.
#[should_panic(expected = "Proposed Token A deposit does not match the pool's ideal amount")]
#[test]
fn add_liquidity_inflated_token_a_deposit_is_rejected() {
    let plan = plan_for(
        liquidity_accounts(),
        add_instruction(
            ADD_MIN_LP,
            ADD_MAX_A,
            ADD_MAX_B,
            ADD_MAX_A,
            ADD_ACTUAL_B,
            ADD_LP,
            RESERVE_A,
            RESERVE_B,
        ),
    );
    let _pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));
}

#[should_panic(expected = "Proposed Token B deposit does not match the pool's ideal amount")]
#[test]
fn add_liquidity_inflated_token_b_deposit_is_rejected() {
    let plan = plan_for(
        liquidity_accounts(),
        add_instruction(
            ADD_MIN_LP,
            ADD_MAX_A,
            ADD_MAX_B,
            ADD_ACTUAL_A,
            ADD_ACTUAL_B - 1,
            ADD_LP,
            RESERVE_A,
            RESERVE_B,
        ),
    );
    let _pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));
}

#[should_panic(expected = "Proposed LP amount does not match the pool's mint calculation")]
#[test]
fn add_liquidity_inflated_liquidity_mint_is_rejected() {
    let plan = plan_for(
        liquidity_accounts(),
        add_instruction(
            ADD_MIN_LP,
            ADD_MAX_A,
            ADD_MAX_B,
            ADD_ACTUAL_A,
            ADD_ACTUAL_B,
            ADD_LP * 2,
            RESERVE_A,
            RESERVE_B,
        ),
    );
    let _pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));
}

#[should_panic(expected = "Vault A was not provided")]
#[test]
fn call_add_liquidity_vault_a_omitted() {
    let mut accounts = liquidity_accounts();
    accounts[1] = token_handle(UNRELATED_ID);
    let plan = plan_for(accounts, add_successfully());
    let _pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));
}

#[should_panic(expected = "Vault B was not provided")]
#[test]
fn call_add_liquidity_vault_b_omitted() {
    let mut accounts = liquidity_accounts();
    accounts[2] = token_handle(UNRELATED_ID);
    let plan = plan_for(accounts, add_successfully());
    let _pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));
}

#[should_panic(expected = "LP definition mismatch")]
#[test]
fn call_add_liquidity_lp_definition_mismatch() {
    let mut accounts = liquidity_accounts();
    accounts[3] = token_handle(UNRELATED_ID);
    let plan = plan_for(accounts, add_successfully());
    let _pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));
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
                let _pool = resolve_pool(&pool, &effect);
            })
            .contains("Reserves must be nonzero"),
            "an empty {position} reserve was accepted"
        );
    }
}

#[test]
fn call_add_liquidity_vault_insufficient_balance() {
    let plan = plan_for(liquidity_accounts(), add_successfully());

    for (position, vault_id, definition_id, index) in [
        ("Vault A", vault_a_id(), TOKEN_A_ID, 1),
        ("Vault B", vault_b_id(), TOKEN_B_ID, 2),
    ] {
        let effect = effect_of(&plan, index);
        assert!(
            rejection(|| resolve_vault(vault_id, fungible(definition_id, 0), &effect))
                .contains("Reserve bound exceeds the vault's balance"),
            "{position} was accepted below the bound it was checked against"
        );
    }
}

// The pool half of the vault-coverage certificate: a caller who understates the bound the vaults
// were measured against is rejected by the pool instead.
#[should_panic(expected = "Reserve for Token A exceeds the bound the vault was checked against")]
#[test]
fn add_liquidity_understated_reserve_bound_is_rejected() {
    let plan = plan_for(
        liquidity_accounts(),
        add_instruction(
            ADD_MIN_LP,
            ADD_MAX_A,
            ADD_MAX_B,
            ADD_ACTUAL_A,
            ADD_ACTUAL_B,
            ADD_LP,
            RESERVE_A - 1,
            RESERVE_B,
        ),
    );
    let _pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));
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
    let _pool = resolve_pool(&pool_base(), &forged);
}

#[test]
fn call_add_liquidity_chained_call_successsful() {
    let plan = plan_for(liquidity_accounts(), add_successfully());
    let Effect::AddLiquidity(binding) = effect_of(&plan, 0) else {
        panic!("the first add effect is the pool's");
    };

    let pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));
    assert_eq!(
        pool,
        PoolDefinition {
            liquidity_pool_supply: LP_SUPPLY + ADD_LP,
            reserve_a: RESERVE_A + ADD_ACTUAL_A,
            reserve_b: RESERVE_B + ADD_ACTUAL_B,
            ..pool_base()
        }
    );

    resolve_vault(
        vault_a_id(),
        fungible(TOKEN_A_ID, RESERVE_A),
        &effect_of(&plan, 1),
    );
    resolve_vault(
        vault_b_id(),
        fungible(TOKEN_B_ID, RESERVE_B),
        &effect_of(&plan, 2),
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
        plan.output().chained_calls[0].pda_seeds,
        vec![compute_liquidity_token_pda_seed(pool_id())]
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
    let _plan = plan_for(
        liquidity_accounts(),
        remove_instruction(0, REMOVE_MIN_A, REMOVE_MIN_B, 0, 0, 0),
    );
}

#[test]
fn call_remove_liquidity_min_bal_zero() {
    for (position, min_a, min_b) in [("Token A", 0, REMOVE_MIN_B), ("Token B", REMOVE_MIN_A, 0)] {
        assert!(
            rejection(|| {
                let _plan = plan_for(
                    liquidity_accounts(),
                    remove_instruction(REMOVE_LP, min_a, min_b, REMOVE_A, REMOVE_B, REMOVE_LP),
                );
            })
            .contains("Minimum withdraw amount must be nonzero"),
            "a zero minimum withdrawal for {position} was accepted"
        );
    }
}

#[should_panic(
    expected = "Insufficient minimal withdraw amount (Token A) provided for liquidity amount"
)]
#[test]
fn call_remove_liquidity_insufficient_balance_1() {
    // 30 LP of a 707 supply withdraws 42 of Token A, under the 50 the caller demanded.
    let _plan = plan_for(
        liquidity_accounts(),
        remove_instruction(30, REMOVE_MIN_A, REMOVE_MIN_B, 42, 21, 30),
    );
}

#[should_panic(
    expected = "Insufficient minimal withdraw amount (Token B) provided for liquidity amount"
)]
#[test]
fn call_remove_liquidity_insufficient_balance_2() {
    let _plan = plan_for(
        liquidity_accounts(),
        remove_instruction(REMOVE_LP, REMOVE_MIN_A, 100, REMOVE_A, REMOVE_B, REMOVE_LP),
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
    let _pool = resolve_pool(&pool, &effect_of(&plan, 0));
}

#[should_panic(expected = "Vault A was not provided")]
#[test]
fn call_remove_liquidity_vault_a_omitted() {
    let mut accounts = liquidity_accounts();
    accounts[1] = token_handle(UNRELATED_ID);
    let plan = plan_for(accounts, remove_successfully());
    let _pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));
}

#[should_panic(expected = "Vault B was not provided")]
#[test]
fn call_remove_liquidity_vault_b_omitted() {
    let mut accounts = liquidity_accounts();
    accounts[2] = token_handle(UNRELATED_ID);
    let plan = plan_for(accounts, remove_successfully());
    let _pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));
}

#[should_panic(expected = "LP definition mismatch")]
#[test]
fn call_remove_liquidity_lp_def_mismatch() {
    let mut accounts = liquidity_accounts();
    accounts[3] = token_handle(UNRELATED_ID);
    let plan = plan_for(accounts, remove_successfully());
    let _pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));
}

#[should_panic(expected = "Invalid liquidity account provided")]
#[test]
fn call_remove_liquidity_insufficient_liquidity_amount() {
    let plan = plan_for(liquidity_accounts(), remove_successfully());
    resolve_vault(
        USER_LP_ID,
        fungible(TOKEN_A_ID, REMOVE_LP),
        &effect_of(&plan, 1),
    );
}

#[should_panic(expected = "Invalid liquidity account provided")]
#[test]
fn remove_liquidity_holding_above_supply_bound_is_rejected() {
    let plan = plan_for(liquidity_accounts(), remove_successfully());
    resolve_vault(
        USER_LP_ID,
        fungible(token_lp_id(), LP_SUPPLY + 1),
        &effect_of(&plan, 1),
    );
}

#[should_panic(expected = "Invalid liquidity account provided")]
#[test]
fn remove_liquidity_supply_bound_above_actual_supply_is_rejected() {
    let plan = plan_for(liquidity_accounts(), remove_successfully());
    let pool = PoolDefinition {
        liquidity_pool_supply: LP_SUPPLY - 1,
        ..pool_base()
    };
    let _pool = resolve_pool(&pool, &effect_of(&plan, 0));
}

#[should_panic(
    expected = "Proposed Token A withdrawal does not match the pool's removal calculation"
)]
#[test]
fn remove_liquidity_inflated_withdrawal_is_rejected() {
    let plan = plan_for(
        liquidity_accounts(),
        remove_instruction(
            REMOVE_LP,
            REMOVE_MIN_A,
            REMOVE_MIN_B,
            RESERVE_A,
            REMOVE_B,
            REMOVE_LP,
        ),
    );
    let _pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));
}

#[should_panic(expected = "Proposed LP burn does not match the pool's removal calculation")]
#[test]
fn remove_liquidity_understated_burn_is_rejected() {
    let plan = plan_for(
        liquidity_accounts(),
        remove_instruction(REMOVE_LP, REMOVE_MIN_A, REMOVE_MIN_B, REMOVE_A, REMOVE_B, 1),
    );
    let _pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));
}

#[test]
fn call_remove_liquidity_chained_call_successful() {
    let plan = plan_for(liquidity_accounts(), remove_successfully());
    let Effect::RemoveLiquidity(binding) = effect_of(&plan, 0) else {
        panic!("the first remove effect is the pool's");
    };

    let pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));
    assert_eq!(
        pool,
        PoolDefinition {
            liquidity_pool_supply: LP_SUPPLY - REMOVE_LP,
            reserve_a: RESERVE_A - REMOVE_A,
            reserve_b: RESERVE_B - REMOVE_B,
            ..pool_base()
        }
    );

    resolve_vault(
        USER_LP_ID,
        fungible(token_lp_id(), REMOVE_LP),
        &effect_of(&plan, 1),
    );

    // The amounts the pool effect is checked against and the amounts the token program is asked to
    // move are one and the same value, so a guard on one cannot be satisfied by a different
    // transfer.
    assert_eq!(
        (
            binding.amount_to_remove_token_a,
            binding.amount_to_remove_token_b,
            binding.amount_liquidity_burned
        ),
        (REMOVE_A, REMOVE_B, REMOVE_LP)
    );
    assert_call(
        &plan,
        0,
        &token_core::Instruction::Burn {
            amount_to_burn: binding.amount_liquidity_burned,
            kind: TokenKind::Fungible,
        },
    );
    assert_eq!(
        transferred(&plan, 1),
        (binding.amount_to_remove_token_b, fungible_of(TOKEN_B_ID))
    );
    assert_eq!(
        plan.output().chained_calls[1].pda_seeds,
        vec![compute_vault_pda_seed(pool_id(), TOKEN_B_ID)]
    );
    assert_eq!(
        transferred(&plan, 2),
        (binding.amount_to_remove_token_a, fungible_of(TOKEN_A_ID))
    );
    assert_eq!(
        plan.output().chained_calls[2].pda_seeds,
        vec![compute_vault_pda_seed(pool_id(), TOKEN_A_ID)]
    );
}

#[test]
fn remove_liquidity_full_drain_deactivates_the_pool() {
    let plan = plan_for(
        liquidity_accounts(),
        remove_instruction(
            LP_SUPPLY,
            REMOVE_MIN_A,
            REMOVE_MIN_B,
            RESERVE_A,
            RESERVE_B,
            LP_SUPPLY,
        ),
    );
    let pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));

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

// A forged Token A definition mis-keys the pool's whole PDA family, so the holding the vault is
// funded from is what the guard measures it against.
#[should_panic(expected = "Proposed token definition is not the one the holding carries")]
#[test]
fn new_definition_forged_token_a_definition_is_rejected() {
    let plan = plan_for(
        liquidity_accounts(),
        new_definition_instruction(RESERVE_A, RESERVE_B, true),
    );
    resolve_vault(
        USER_A_ID,
        fungible(TOKEN_B_ID, RESERVE_A),
        &effect_of(&plan, 0),
    );
}

#[should_panic(expected = "Cannot initialize an active Pool Definition")]
#[test]
fn call_new_definition_cannot_initialize_active_pool() {
    let plan = plan_for(
        liquidity_accounts(),
        new_definition_instruction(RESERVE_A, RESERVE_B, false),
    );
    let _pool = resolve_pool(&pool_base(), &effect_of(&plan, 2));
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
    let _pool = resolve_pool(&inactive, &effect_of(&plan, 2));
}

#[should_panic(expected = "Pool emptiness does not match the planned initialization branch")]
#[test]
fn new_definition_inactive_branch_against_an_empty_pool_is_rejected() {
    let plan = plan_for(
        liquidity_accounts(),
        new_definition_instruction(RESERVE_A, RESERVE_B, false),
    );
    let written = resolve_on(
        pool_id(),
        AMM_PROGRAM_ID,
        ShardData::empty(),
        &effect_of(&plan, 2),
    );
    let _written = written.expect("a pool effect writes the pool shard");
}

#[test]
fn new_definition_uninitialized_pool_creates_the_liquidity_definition() {
    let plan = plan_for(
        liquidity_accounts(),
        new_definition_instruction(RESERVE_A, RESERVE_B, true),
    );
    let effect = effect_of(&plan, 2);
    let Effect::InitializePool { definition, .. } = &effect else {
        panic!("the third new definition effect is the pool's");
    };

    let written = resolve_on(pool_id(), AMM_PROGRAM_ID, ShardData::empty(), &effect)
        .expect("a pool effect writes the pool shard");
    let pool = PoolDefinition::try_from(&written).expect("the resolver wrote a pool definition");
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
    let pool = resolve_pool(&inactive, &effect_of(&plan, 2));
    assert_eq!(pool.liquidity_pool_supply, LP_SUPPLY);

    assert_call(
        &plan,
        0,
        &token_core::Instruction::Mint {
            amount_to_mint: LP_SUPPLY,
        },
    );
    assert_eq!(
        plan.output().chained_calls[0].pda_seeds,
        vec![compute_liquidity_token_pda_seed(pool_id())]
    );
}

#[test]
fn new_definition_lp_symmetric_amounts() {
    // token_a = 100, token_b = 100 -> LP = sqrt(10_000) = 100
    let plan = plan_for(
        liquidity_accounts(),
        new_definition_instruction(100, 100, true),
    );

    let written = resolve_on(
        pool_id(),
        AMM_PROGRAM_ID,
        ShardData::empty(),
        &effect_of(&plan, 2),
    )
    .expect("a pool effect writes the pool shard");
    let pool = PoolDefinition::try_from(&written).expect("the resolver wrote a pool definition");

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

#[should_panic(expected = "Withdraw amount is less than minimal amount out")]
#[test]
fn call_swap_below_min_out() {
    let _plan = plan_for(
        swap_accounts(),
        exact_input(SWAP_IN_A, SWAP_OUT_B + 1, SWAP_OUT_B, true),
    );
}

#[should_panic(expected = "Withdraw amount should be nonzero")]
#[test]
fn call_swap_zero_out() {
    let _plan = plan_for(swap_accounts(), exact_input(SWAP_IN_A, 0, 0, true));
}

#[should_panic(expected = "AccountId is not a token type for the pool")]
#[test]
fn call_swap_incorrect_token_type() {
    let plan = plan_for(swap_accounts(), exact_input(SWAP_IN_A, 0, SWAP_OUT_B, true));
    let forged = Effect::SwapExactInput(SwapBinding {
        definition_id_in: token_lp_id(),
        ..swap_binding_of(&plan)
    });
    let _pool = resolve_pool(&pool_base(), &forged);
}

// Route and orientation are proposals: claiming the Token A leg while naming Token B's definition
// leaves the deposit and withdraw handles swapped, and the pool rejects the pair.
#[should_panic(expected = "AccountId is not a token type for the pool")]
#[test]
fn call_swap_forged_route_is_rejected() {
    let plan = plan_for(swap_accounts(), exact_input(SWAP_IN_A, 0, SWAP_OUT_B, true));
    let forged = Effect::SwapExactInput(SwapBinding {
        input_is_token_a: false,
        ..swap_binding_of(&plan)
    });
    let _pool = resolve_pool(&pool_base(), &forged);
}

#[should_panic(expected = "AccountId is not a token type for the pool")]
#[test]
fn call_swap_forged_output_definition_is_rejected() {
    let plan = plan_for(swap_accounts(), exact_input(SWAP_IN_A, 0, SWAP_OUT_B, true));
    let forged = Effect::SwapExactInput(SwapBinding {
        definition_id_out: TOKEN_A_ID,
        ..swap_binding_of(&plan)
    });
    let _pool = resolve_pool(&pool_base(), &forged);
}

#[should_panic(expected = "Vault A was not provided")]
#[test]
fn call_swap_vault_a_omitted() {
    let mut accounts = swap_accounts();
    accounts[1] = token_handle(UNRELATED_ID);
    let plan = plan_for(accounts, exact_input(SWAP_IN_A, 0, SWAP_OUT_B, true));
    let _pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));
}

#[should_panic(expected = "Vault B was not provided")]
#[test]
fn call_swap_vault_b_omitted() {
    let mut accounts = swap_accounts();
    accounts[2] = token_handle(UNRELATED_ID);
    let plan = plan_for(accounts, exact_input(SWAP_IN_A, 0, SWAP_OUT_B, true));
    let _pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));
}

#[test]
fn call_swap_reserves_vault_mismatch() {
    let plan = plan_for(swap_accounts(), exact_input(SWAP_IN_A, 0, SWAP_OUT_B, true));

    for (position, vault_id, definition_id, index) in [
        ("Vault A", vault_a_id(), TOKEN_A_ID, 1),
        ("Vault B", vault_b_id(), TOKEN_B_ID, 2),
    ] {
        let effect = effect_of(&plan, index);
        assert!(
            rejection(|| resolve_vault(vault_id, fungible(definition_id, 10), &effect))
                .contains("Reserve bound exceeds the vault's balance"),
            "{position} was accepted below the bound it was checked against"
        );
    }
}

#[should_panic(expected = "Reserve for Token B exceeds the bound the vault was checked against")]
#[test]
fn call_swap_understated_reserve_bound_is_rejected() {
    let plan = plan_for(swap_accounts(), exact_input(SWAP_IN_A, 0, SWAP_OUT_B, true));
    let forged = Effect::SwapExactInput(SwapBinding {
        reserve_bound_b: RESERVE_B - 1,
        ..swap_binding_of(&plan)
    });
    let _pool = resolve_pool(&pool_base(), &forged);
}

#[should_panic(expected = "Swap routes through a token program the pool does not use")]
#[test]
fn call_swap_through_a_foreign_token_program_is_rejected() {
    let plan = plan_for(swap_accounts(), exact_input(SWAP_IN_A, 0, SWAP_OUT_B, true));
    let forged = Effect::SwapExactInput(SwapBinding {
        token_program_id: STRANGER_PROGRAM_ID,
        ..swap_binding_of(&plan)
    });
    let _pool = resolve_pool(&pool_base(), &forged);
}

#[should_panic(expected = "Pool is inactive")]
#[test]
fn call_swap_ianctive() {
    let plan = plan_for(swap_accounts(), exact_input(SWAP_IN_A, 0, SWAP_OUT_B, true));
    let pool = PoolDefinition {
        active: false,
        ..pool_base()
    };
    let _pool = resolve_pool(&pool, &effect_of(&plan, 0));
}

// The `dy` case: a caller who proposes a larger output than the constant product prices is the
// vault drain this guard exists for.
#[should_panic(expected = "Proposed output does not match the pool's exact-input price")]
#[test]
fn swap_exact_input_inflated_output_is_rejected() {
    let plan = plan_for(
        swap_accounts(),
        exact_input(SWAP_IN_A, 0, RESERVE_B - 1, true),
    );
    let _pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));
}

// One unit *below* the true price, and demanded as the caller's own minimum, so the planner's
// slippage bound is satisfied and exactness is the only thing left that can reject it. An upper
// bound in its place would take the reserve the pool priced while the withdraw leg pays out less,
// leaving the pool's books and its vault apart.
#[should_panic(expected = "Proposed output does not match the pool's exact-input price")]
#[test]
fn swap_exact_input_price_is_exact_not_a_slippage_range() {
    let plan = plan_for(
        swap_accounts(),
        exact_input(SWAP_IN_A, SWAP_OUT_B - 1, SWAP_OUT_B - 1, true),
    );
    let _pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));
}

#[test]
fn call_swap_chained_call_successful_1() {
    let plan = plan_for(
        swap_accounts(),
        exact_input(SWAP_IN_A, SWAP_OUT_B, SWAP_OUT_B, true),
    );
    let binding = swap_binding_of(&plan);

    let pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));
    assert_eq!(
        pool,
        PoolDefinition {
            reserve_a: RESERVE_A + SWAP_IN_A,
            reserve_b: RESERVE_B - SWAP_OUT_B,
            ..pool_base()
        }
    );

    // The proposed output reaches the pool's guard and the withdraw call as one value, so no plan
    // can price the pool against one amount and pay out another.
    assert_eq!(
        (
            binding.amount_in,
            binding.amount_out,
            binding.definition_id_out
        ),
        (SWAP_IN_A, SWAP_OUT_B, TOKEN_B_ID)
    );
    assert_eq!(
        transferred(&plan, 0),
        (binding.amount_in, fungible_of(TOKEN_A_ID))
    );
    assert_eq!(
        plan.output().chained_calls[0].shard_selectors,
        vec![
            ProgramShardSelector::new(USER_A_ID, TOKEN_PROGRAM_ID),
            ProgramShardSelector::new(vault_a_id(), TOKEN_PROGRAM_ID),
        ]
    );
    assert_eq!(
        transferred(&plan, 1),
        (binding.amount_out, fungible_of(binding.definition_id_out))
    );
    assert_eq!(
        plan.output().chained_calls[1].shard_selectors,
        vec![
            ProgramShardSelector::new(vault_b_id(), TOKEN_PROGRAM_ID),
            ProgramShardSelector::new(USER_B_ID, TOKEN_PROGRAM_ID),
        ]
    );
    assert_eq!(
        plan.output().chained_calls[1].pda_seeds,
        vec![compute_vault_pda_seed(pool_id(), binding.definition_id_out)]
    );
}

#[test]
fn call_swap_chained_call_successful_2() {
    let plan = plan_for(
        swap_accounts(),
        exact_input(SWAP_IN_B, SWAP_OUT_A, SWAP_OUT_A, false),
    );

    let pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));
    assert_eq!(
        pool,
        PoolDefinition {
            reserve_a: RESERVE_A - SWAP_OUT_A,
            reserve_b: RESERVE_B + SWAP_IN_B,
            ..pool_base()
        }
    );

    assert_eq!(transferred(&plan, 0), (SWAP_IN_B, fungible_of(TOKEN_B_ID)));
    assert_eq!(
        plan.output().chained_calls[0].shard_selectors,
        vec![
            ProgramShardSelector::new(USER_B_ID, TOKEN_PROGRAM_ID),
            ProgramShardSelector::new(vault_b_id(), TOKEN_PROGRAM_ID),
        ]
    );
    assert_eq!(transferred(&plan, 1), (SWAP_OUT_A, fungible_of(TOKEN_A_ID)));
    assert_eq!(
        plan.output().chained_calls[1].pda_seeds,
        vec![compute_vault_pda_seed(pool_id(), TOKEN_A_ID)]
    );
}

#[should_panic(expected = "Exact amount out must be nonzero")]
#[test]
fn call_swap_exact_output_zero() {
    let _plan = plan_for(swap_accounts(), exact_output(0, RESERVE_A, 1, true));
}

#[should_panic(expected = "Required input exceeds maximum amount in")]
#[test]
fn call_swap_exact_output_exceeds_max_in() {
    let _plan = plan_for(
        swap_accounts(),
        exact_output(SWAP_OUT_B, 100, EXACT_OUT_DEPOSIT_A, true),
    );
}

#[should_panic(expected = "Exact amount out exceeds reserve")]
#[test]
fn call_swap_exact_output_exceeds_reserve() {
    let plan = plan_for(swap_accounts(), exact_output(RESERVE_B, u128::MAX, 1, true));
    let _pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));
}

#[should_panic(expected = "AccountId is not a token type for the pool")]
#[test]
fn call_swap_exact_output_incorrect_token_type() {
    let plan = plan_for(
        swap_accounts(),
        exact_output(SWAP_OUT_B, RESERVE_A, EXACT_OUT_DEPOSIT_A, true),
    );
    let forged = Effect::SwapExactOutput(SwapBinding {
        definition_id_in: token_lp_id(),
        ..swap_binding_of(&plan)
    });
    let _pool = resolve_pool(&pool_base(), &forged);
}

#[should_panic(expected = "Vault A was not provided")]
#[test]
fn call_swap_exact_output_vault_a_omitted() {
    let mut accounts = swap_accounts();
    accounts[1] = token_handle(UNRELATED_ID);
    let plan = plan_for(
        accounts,
        exact_output(SWAP_OUT_B, RESERVE_A, EXACT_OUT_DEPOSIT_A, true),
    );
    let _pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));
}

#[should_panic(expected = "Vault B was not provided")]
#[test]
fn call_swap_exact_output_vault_b_omitted() {
    let mut accounts = swap_accounts();
    accounts[2] = token_handle(UNRELATED_ID);
    let plan = plan_for(
        accounts,
        exact_output(SWAP_OUT_B, RESERVE_A, EXACT_OUT_DEPOSIT_A, true),
    );
    let _pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));
}

#[test]
fn call_swap_exact_output_reserves_vault_mismatch() {
    let plan = plan_for(
        swap_accounts(),
        exact_output(SWAP_OUT_B, RESERVE_A, EXACT_OUT_DEPOSIT_A, true),
    );

    for (position, vault_id, definition_id, index) in [
        ("Vault A", vault_a_id(), TOKEN_A_ID, 1),
        ("Vault B", vault_b_id(), TOKEN_B_ID, 2),
    ] {
        let effect = effect_of(&plan, index);
        assert!(
            rejection(|| resolve_vault(vault_id, fungible(definition_id, 10), &effect))
                .contains("Reserve bound exceeds the vault's balance"),
            "{position} was accepted below the bound it was checked against"
        );
    }
}

#[should_panic(expected = "Pool is inactive")]
#[test]
fn call_swap_exact_output_inactive() {
    let plan = plan_for(
        swap_accounts(),
        exact_output(SWAP_OUT_B, RESERVE_A, EXACT_OUT_DEPOSIT_A, true),
    );
    let pool = PoolDefinition {
        active: false,
        ..pool_base()
    };
    let _pool = resolve_pool(&pool, &effect_of(&plan, 0));
}

#[should_panic(expected = "Proposed input does not match the pool's exact-output price")]
#[test]
fn swap_exact_output_understated_input_is_rejected() {
    let plan = plan_for(
        swap_accounts(),
        exact_output(SWAP_OUT_B, RESERVE_A, 1, true),
    );
    let _pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));
}

// The mirror of the exact-input exactness case. Every other exact-output fixture proposes an input
// at or below the quote, so an upper-bound check would pass them all: the pool would credit its
// reserve with the quoted deposit while the chained call moved the larger proposed amount, leaving
// the vault and the pool's books apart in the LPs' favour.
#[should_panic(expected = "Proposed input does not match the pool's exact-output price")]
#[test]
fn swap_exact_output_price_is_exact_not_a_lower_bound() {
    let plan = plan_for(
        swap_accounts(),
        exact_output(SWAP_OUT_B, RESERVE_A, EXACT_OUT_DEPOSIT_A + 1, true),
    );
    let _pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));
}

// Rounding is part of the price: the floor of the exact-output quote is one unit short and is
// rejected, which is what stops a caller from buying out a pool a unit at a time.
#[should_panic(expected = "Proposed input does not match the pool's exact-output price")]
#[test]
fn swap_exact_output_rounds_the_deposit_up() {
    let plan = plan_for(
        swap_accounts(),
        exact_output(SWAP_OUT_B, RESERVE_A, EXACT_OUT_DEPOSIT_A - 1, true),
    );
    let _pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));
}

#[test]
fn call_swap_exact_output_chained_call_successful() {
    let plan = plan_for(
        swap_accounts(),
        exact_output(SWAP_OUT_B, RESERVE_A, EXACT_OUT_DEPOSIT_A, true),
    );
    let binding = swap_binding_of(&plan);

    let pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));
    assert_eq!(
        pool,
        PoolDefinition {
            reserve_a: RESERVE_A + EXACT_OUT_DEPOSIT_A,
            reserve_b: RESERVE_B - SWAP_OUT_B,
            ..pool_base()
        }
    );

    // The deposit the pool is priced against and the deposit the token program is asked to move
    // are one value, and the fixed output reaches the withdraw leg unchanged.
    assert_eq!(
        (
            binding.amount_in,
            binding.amount_out,
            binding.definition_id_in
        ),
        (EXACT_OUT_DEPOSIT_A, SWAP_OUT_B, TOKEN_A_ID)
    );
    assert_eq!(
        transferred(&plan, 0),
        (binding.amount_in, fungible_of(binding.definition_id_in))
    );
    assert_eq!(
        transferred(&plan, 1),
        (binding.amount_out, fungible_of(TOKEN_B_ID))
    );
}

#[test]
fn call_swap_exact_output_chained_call_successful_2() {
    let plan = plan_for(
        swap_accounts(),
        exact_output(SWAP_OUT_A, 300, EXACT_OUT_DEPOSIT_B, false),
    );

    let pool = resolve_pool(&pool_base(), &effect_of(&plan, 0));
    assert_eq!(
        pool,
        PoolDefinition {
            reserve_a: RESERVE_A - SWAP_OUT_A,
            reserve_b: RESERVE_B + EXACT_OUT_DEPOSIT_B,
            ..pool_base()
        }
    );

    assert_eq!(
        transferred(&plan, 0),
        (EXACT_OUT_DEPOSIT_B, fungible_of(TOKEN_B_ID))
    );
    assert_eq!(transferred(&plan, 1), (SWAP_OUT_A, fungible_of(TOKEN_A_ID)));
}

// Without the check, `reserve_a * exact_amount_out` silently wraps to 0 in release mode, making
// the required deposit 0: the caller receives `exact_amount_out` while paying nothing.
#[should_panic(expected = "reserve * amount_out overflows u128")]
#[test]
fn swap_exact_output_overflow_protection() {
    // reserve_a chosen so that reserve_a * 2 overflows u128:
    //   (u128::MAX / 2 + 1) * 2 = u128::MAX + 1 -> wraps to 0
    let large_reserve: u128 = u128::MAX / 2 + 1;
    let pool = PoolDefinition {
        liquidity_pool_supply: 1,
        reserve_a: large_reserve,
        reserve_b: RESERVE_A,
        ..pool_base()
    };

    let plan = plan_for(
        swap_accounts(),
        Instruction::SwapExactOutput {
            exact_amount_out: 2,
            max_amount_in: 1,
            token_definition_id_in: TOKEN_A_ID,
            token_program_id: TOKEN_PROGRAM_ID,
            token_definition_id_out: TOKEN_B_ID,
            input_is_token_a: true,
            amount_in: 1,
            reserve_bound_a: large_reserve,
            reserve_bound_b: RESERVE_A,
        },
    );
    let _pool = resolve_pool(&pool, &effect_of(&plan, 0));
}
