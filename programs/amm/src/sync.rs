use amm_core::PoolDefinition;
use nssa_core::{
    account::{AccountWithMetadata, Data},
    program::{AccountPostState, ChainedCall},
};

use crate::vault_utils::read_vault_fungible_balances;

pub fn sync_reserves(
    pool: AccountWithMetadata,
    vault_a: AccountWithMetadata,
    vault_b: AccountWithMetadata,
) -> (Vec<AccountPostState>, Vec<ChainedCall>) {
    let pool_def_data = PoolDefinition::try_from(&pool.account.data)
        .expect("Sync reserves: AMM Program expects a valid Pool Definition Account");

    assert!(pool_def_data.active, "Pool is inactive");
    assert_eq!(
        vault_a.account_id, pool_def_data.vault_a_id,
        "Vault A was not provided"
    );
    assert_eq!(
        vault_b.account_id, pool_def_data.vault_b_id,
        "Vault B was not provided"
    );

    let (vault_a_balance, vault_b_balance) = read_vault_fungible_balances(&vault_a, &vault_b);

    let _surplus_a = vault_a_balance.saturating_sub(pool_def_data.reserve_a);
    let _surplus_b = vault_b_balance.saturating_sub(pool_def_data.reserve_b);

    let mut pool_post = pool.account.clone();
    let pool_post_definition = PoolDefinition {
        reserve_a: vault_a_balance,
        reserve_b: vault_b_balance,
        ..pool_def_data
    };
    pool_post.data = Data::from(&pool_post_definition);

    (
        vec![
            AccountPostState::new(pool_post),
            AccountPostState::new(vault_a.account.clone()),
            AccountPostState::new(vault_b.account.clone()),
        ],
        Vec::new(),
    )
}
