use std::num::NonZeroU128;

use amm_core::{
    PoolDefinition, compute_liquidity_token_pda, compute_liquidity_token_pda_seed,
    compute_pool_pda, compute_vault_pda,
};
use nssa_core::{
    account::{Account, AccountWithMetadata, Data},
    program::{AccountPostState, ChainedCall, ProgramId},
};

#[expect(clippy::too_many_arguments, reason = "TODO: Fix later")]
#[must_use]
pub fn new_definition(
    pool: AccountWithMetadata,
    vault_a: AccountWithMetadata,
    vault_b: AccountWithMetadata,
    pool_definition_lp: AccountWithMetadata,
    user_holding_a: AccountWithMetadata,
    user_holding_b: AccountWithMetadata,
    user_holding_lp: AccountWithMetadata,
    token_a_amount: NonZeroU128,
    token_b_amount: NonZeroU128,
    amm_program_id: ProgramId,
) -> (Vec<AccountPostState>, Vec<ChainedCall>) {
    // Verify token_a and token_b are different
    let definition_token_a_id = token_core::TokenHolding::try_from(&user_holding_a.account.data)
        .expect("New definition: AMM Program expects valid Token Holding account for Token A")
        .definition_id();
    let definition_token_b_id = token_core::TokenHolding::try_from(&user_holding_b.account.data)
        .expect("New definition: AMM Program expects valid Token Holding account for Token B")
        .definition_id();

    // both instances of the same token program
    let token_program = user_holding_a.account.program_owner;

    assert_eq!(
        user_holding_b.account.program_owner, token_program,
        "User Token holdings must use the same Token Program"
    );
    assert!(
        definition_token_a_id != definition_token_b_id,
        "Cannot set up a swap for a token with itself"
    );
    assert_eq!(
        pool.account_id,
        compute_pool_pda(amm_program_id, definition_token_a_id, definition_token_b_id),
        "Pool Definition Account ID does not match PDA"
    );
    assert_eq!(
        vault_a.account_id,
        compute_vault_pda(amm_program_id, pool.account_id, definition_token_a_id),
        "Vault ID does not match PDA"
    );
    assert_eq!(
        vault_b.account_id,
        compute_vault_pda(amm_program_id, pool.account_id, definition_token_b_id),
        "Vault ID does not match PDA"
    );
    assert_eq!(
        pool_definition_lp.account_id,
        compute_liquidity_token_pda(amm_program_id, pool.account_id),
        "Liquidity pool Token Definition Account ID does not match PDA"
    );

    // TODO: return here
    // Verify that Pool Account is not active
    let pool_account_data = if pool.account == Account::default() {
        PoolDefinition::default()
    } else {
        PoolDefinition::try_from(&pool.account.data)
            .expect("AMM program expects a valid Pool account")
    };

    assert!(
        !pool_account_data.active,
        "Cannot initialize an active Pool Definition"
    );

    // LP Token minting calculation
    let initial_lp = (token_a_amount.get() * token_b_amount.get()).isqrt();

    // Chain call for liquidity token (TokenLP definition -> User LP Holding)
    let instruction = if pool.account == Account::default() {
        token_core::Instruction::NewFungibleDefinition {
            name: String::from("LP Token"),
            total_supply: initial_lp,
        }
    } else {
        token_core::Instruction::Mint {
            amount_to_mint: initial_lp,
        }
    };

    // Update pool account
    let mut pool_post = pool.account;
    let pool_post_definition = PoolDefinition {
        definition_token_a_id,
        definition_token_b_id,
        vault_a_id: vault_a.account_id,
        vault_b_id: vault_b.account_id,
        liquidity_pool_id: pool_definition_lp.account_id,
        liquidity_pool_supply: initial_lp,
        reserve_a: token_a_amount.into(),
        reserve_b: token_b_amount.into(),
        fees: 0_u128, // TODO: we assume all fees are 0 for now.
        active: true,
    };

    pool_post.data = Data::from(&pool_post_definition);
    let pool_post = AccountPostState::new_claimed_if_default(pool_post);

    let token_program_id = user_holding_a.account.program_owner;

    // Chain call for Token A (user_holding_a -> Vault_A)
    let call_token_a = ChainedCall::new(
        token_program_id,
        vec![user_holding_a.clone(), vault_a.clone()],
        &token_core::Instruction::Transfer {
            amount_to_transfer: token_a_amount.into(),
        },
    );
    // Chain call for Token B (user_holding_b -> Vault_B)
    let call_token_b = ChainedCall::new(
        token_program_id,
        vec![user_holding_b.clone(), vault_b.clone()],
        &token_core::Instruction::Transfer {
            amount_to_transfer: token_b_amount.into(),
        },
    );

    let mut pool_lp_auth = pool_definition_lp.clone();
    pool_lp_auth.is_authorized = true;

    let call_token_lp = ChainedCall::new(
        token_program_id,
        vec![pool_lp_auth, user_holding_lp.clone()],
        &instruction,
    )
    .with_pda_seeds(vec![compute_liquidity_token_pda_seed(pool.account_id)]);

    let chained_calls = vec![call_token_lp, call_token_b, call_token_a];

    let post_states = vec![
        pool_post,
        AccountPostState::new(vault_a.account),
        AccountPostState::new(vault_b.account),
        AccountPostState::new(pool_definition_lp.account),
        AccountPostState::new(user_holding_a.account),
        AccountPostState::new(user_holding_b.account),
        AccountPostState::new(user_holding_lp.account),
    ];

    (post_states, chained_calls)
}
