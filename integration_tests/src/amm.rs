use amm_core::{PoolDefinition, compute_liquidity_token_pda, compute_pool_pda, compute_vault_pda};
use anyhow::Result;
use lee::AccountId;
use test_fixtures::{TestContext, public_mention};
use token_core::TokenHolding;

use crate::{create_token, get_account, new_account, wait_until};

/// Two fresh tokens, A and B, whose whole supply sits in the context's first two public accounts,
/// and the accounts of the pool they form under the built-in token program. The pool itself is
/// not created.
pub struct PoolFixture {
    pub holding_a: AccountId,
    pub holding_b: AccountId,
    pub definition_a: AccountId,
    pub definition_b: AccountId,
    pub pool_id: AccountId,
    pub vault_a: AccountId,
    pub vault_b: AccountId,
    pub lp_definition: AccountId,
}

impl PoolFixture {
    /// Creates tokens A and B with `supply` each and waits until both supplies land.
    pub async fn create_tokens(ctx: &mut TestContext, supply: u128) -> Result<Self> {
        let holding_a = ctx.existing_public_accounts()[0];
        let holding_b = ctx.existing_public_accounts()[1];
        let definition_a = new_account(ctx, false, None).await?;
        let definition_b = new_account(ctx, false, None).await?;
        create_token(
            ctx,
            public_mention(definition_a),
            public_mention(holding_a),
            "A",
            supply,
        )
        .await?;
        create_token(
            ctx,
            public_mention(definition_b),
            public_mention(holding_b),
            "B",
            supply,
        )
        .await?;
        let reader: &TestContext = ctx;
        for (holding_id, definition_id) in [(holding_a, definition_a), (holding_b, definition_b)] {
            wait_until("the token supply to land", || async {
                Ok(token_holding(reader, holding_id).await.ok()
                    == Some(TokenHolding::Fungible {
                        definition_id,
                        balance: supply,
                    }))
            })
            .await?;
        }

        let pool_id = compute_pool_pda(
            amm_program_id(),
            definition_a,
            definition_b,
            token_program_id(),
        );
        Ok(Self {
            holding_a,
            holding_b,
            definition_a,
            definition_b,
            pool_id,
            vault_a: compute_vault_pda(amm_program_id(), pool_id, definition_a),
            vault_b: compute_vault_pda(amm_program_id(), pool_id, definition_b),
            lp_definition: compute_liquidity_token_pda(amm_program_id(), pool_id),
        })
    }
}

/// The built-in token program's account.
#[must_use]
pub fn token_program_id() -> AccountId {
    programs::token_account_id()
}

/// The built-in AMM program's account.
#[must_use]
pub fn amm_program_id() -> AccountId {
    programs::amm_account_id()
}

/// A public account's token holding.
pub async fn token_holding(ctx: &TestContext, account_id: AccountId) -> Result<TokenHolding> {
    let account = get_account(ctx, account_id).await?;
    Ok(TokenHolding::try_from(
        account.data.shard(token_program_id()),
    )?)
}

/// Asserts each public holding is fungible, of the given definition and exactly the given balance.
pub async fn assert_holdings(
    ctx: &TestContext,
    step: &str,
    expected: &[(AccountId, AccountId, u128)],
) -> Result<()> {
    for &(holding_id, definition_id, balance) in expected {
        assert_eq!(
            token_holding(ctx, holding_id).await?,
            TokenHolding::Fungible {
                definition_id,
                balance
            },
            "{step}: holding {holding_id}"
        );
    }
    Ok(())
}

/// Asserts the pool is active and records exactly these reserves and LP supply.
pub async fn assert_pool_record(
    ctx: &TestContext,
    step: &str,
    pool_id: AccountId,
    (reserve_a, reserve_b, supply): (u128, u128, u128),
) -> Result<()> {
    let account = get_account(ctx, pool_id).await?;
    let pool = PoolDefinition::try_from(account.data.shard(amm_program_id()))?;
    assert!(pool.active, "{step}: the pool is inactive");
    assert_eq!(
        (pool.reserve_a, pool.reserve_b, pool.liquidity_pool_supply),
        (reserve_a, reserve_b, supply),
        "{step}: pool reserves and LP supply"
    );
    Ok(())
}
