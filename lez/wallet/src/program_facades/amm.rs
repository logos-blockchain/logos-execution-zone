use amm_core::{PoolDefinition, compute_liquidity_token_pda, compute_pool_pda, compute_vault_pda};
use common::HashType;
use lee::{AccountId, program::Program};
use lee_core::account::ShardData;

use crate::{
    AccountIdentity, ExecutionFailureKind, WalletCore,
    program_facades::{shard, token_holding},
};
pub struct Amm<'wallet>(pub &'wallet WalletCore);

/// The pool's PDA family, derived from the definitions the two user holdings carry. A pair given
/// in the opposite order to the pool's own derives the other vault and is rejected on chain.
#[expect(
    clippy::struct_field_names,
    reason = "every field is an account id, named as the pool and the instruction name it"
)]
struct Route {
    amm_program_id: AccountId,
    token_program_id: AccountId,
    definition_token_a_id: AccountId,
    definition_token_b_id: AccountId,
    pool_id: AccountId,
    vault_a_id: AccountId,
    vault_b_id: AccountId,
}

impl Route {
    async fn resolve(
        wallet: &WalletCore,
        user_holding_a: AccountId,
        user_holding_b: AccountId,
    ) -> Result<Self, ExecutionFailureKind> {
        let amm_program_id: AccountId = programs::amm().id().into();
        let token_program_id: AccountId = programs::token().id().into();

        let definition_token_a_id = token_holding(
            wallet,
            &AccountIdentity::PublicNoSign(user_holding_a),
            token_program_id,
        )
        .await?
        .definition_id();
        let definition_token_b_id = token_holding(
            wallet,
            &AccountIdentity::PublicNoSign(user_holding_b),
            token_program_id,
        )
        .await?
        .definition_id();

        let pool_id = compute_pool_pda(
            amm_program_id,
            definition_token_a_id,
            definition_token_b_id,
            token_program_id,
        );

        Ok(Self {
            amm_program_id,
            token_program_id,
            definition_token_a_id,
            definition_token_b_id,
            pool_id,
            vault_a_id: compute_vault_pda(amm_program_id, pool_id, definition_token_a_id),
            vault_b_id: compute_vault_pda(amm_program_id, pool_id, definition_token_b_id),
        })
    }

    fn liquidity_pool_id(&self) -> AccountId {
        compute_liquidity_token_pda(self.amm_program_id, self.pool_id)
    }

    async fn pool_shard(&self, wallet: &WalletCore) -> Result<ShardData, ExecutionFailureKind> {
        shard(
            wallet,
            &AccountIdentity::PublicNoSign(self.pool_id),
            self.amm_program_id,
        )
        .await
    }

    async fn pool(&self, wallet: &WalletCore) -> Result<PoolDefinition, ExecutionFailureKind> {
        PoolDefinition::try_from(&self.pool_shard(wallet).await?)
            .map_err(|_err| ExecutionFailureKind::AccountDataError(self.pool_id))
    }

    /// Returns whether the input is token A, followed by the input and output reserves.
    fn oriented_reserves(
        &self,
        pool: &PoolDefinition,
        definition_id_in: AccountId,
    ) -> Result<(bool, u128, u128), ExecutionFailureKind> {
        if definition_id_in == self.definition_token_a_id {
            Ok((true, pool.reserve_a, pool.reserve_b))
        } else if definition_id_in == self.definition_token_b_id {
            Ok((false, pool.reserve_b, pool.reserve_a))
        } else {
            Err(ExecutionFailureKind::AccountDataError(definition_id_in))
        }
    }
}

impl Amm<'_> {
    pub async fn send_new_definition(
        &self,
        user_holding_a: AccountIdentity,
        user_holding_b: AccountIdentity,
        user_holding_lp: AccountIdentity,
        balance_a: u128,
        balance_b: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let route = Route::resolve(
            self.0,
            public_id(&user_holding_a)?,
            public_id(&user_holding_b)?,
        )
        .await?;

        // The branch between creating the LP definition and minting more of it.
        let pool_is_empty = route.pool_shard(self.0).await?.is_empty();

        let instruction = amm_core::Instruction::NewDefinition {
            token_a_amount: balance_a,
            token_b_amount: balance_b,
            token_program_id: route.token_program_id,
            definition_token_a_id: route.definition_token_a_id,
            definition_token_b_id: route.definition_token_b_id,
            pool_is_empty,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_pub_tx(
                vec![
                    AccountIdentity::PublicNoSign(route.pool_id)
                        .select_program_shard(route.amm_program_id),
                    AccountIdentity::PublicNoSign(route.vault_a_id)
                        .select_program_shard(route.token_program_id),
                    AccountIdentity::PublicNoSign(route.vault_b_id)
                        .select_program_shard(route.token_program_id),
                    AccountIdentity::PublicNoSign(route.liquidity_pool_id())
                        .select_program_shard(route.token_program_id),
                    user_holding_a.select_program_shard(route.token_program_id),
                    user_holding_b.select_program_shard(route.token_program_id),
                    user_holding_lp.select_program_shard(route.token_program_id),
                ],
                instruction_data,
                route.amm_program_id,
            )
            .await
    }

    pub async fn send_swap_exact_input(
        &self,
        user_holding_a: AccountIdentity,
        user_holding_b: AccountIdentity,
        swap_amount_in: u128,
        min_amount_out: u128,
        token_definition_id_in: AccountId,
    ) -> Result<HashType, ExecutionFailureKind> {
        let route = Route::resolve(
            self.0,
            public_id(&user_holding_a)?,
            public_id(&user_holding_b)?,
        )
        .await?;
        let pool = route.pool(self.0).await?;
        let (input_is_token_a, reserve_in, reserve_out) =
            route.oriented_reserves(&pool, token_definition_id_in)?;

        let amount_out = amm_core::quote_exact_input(reserve_in, reserve_out, swap_amount_in)
            .ok_or_else(unpriceable)?;

        let instruction = amm_core::Instruction::SwapExactInput {
            swap_amount_in,
            min_amount_out,
            token_definition_id_in,
            token_program_id: route.token_program_id,
            token_definition_id_out: if input_is_token_a {
                route.definition_token_b_id
            } else {
                route.definition_token_a_id
            },
            input_is_token_a,
            amount_out,
            reserve_bound_a: pool.reserve_a,
            reserve_bound_b: pool.reserve_b,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        let (user_a_signing_identity, user_b_signing_identity) =
            signing_sides(user_holding_a, user_holding_b, input_is_token_a);

        self.0
            .send_pub_tx(
                vec![
                    AccountIdentity::PublicNoSign(route.pool_id)
                        .select_program_shard(route.amm_program_id),
                    AccountIdentity::PublicNoSign(route.vault_a_id)
                        .select_program_shard(route.token_program_id),
                    AccountIdentity::PublicNoSign(route.vault_b_id)
                        .select_program_shard(route.token_program_id),
                    user_a_signing_identity.select_program_shard(route.token_program_id),
                    user_b_signing_identity.select_program_shard(route.token_program_id),
                ],
                instruction_data,
                route.amm_program_id,
            )
            .await
    }

    pub async fn send_swap_exact_output(
        &self,
        user_holding_a: AccountIdentity,
        user_holding_b: AccountIdentity,
        exact_amount_out: u128,
        max_amount_in: u128,
        token_definition_id_in: AccountId,
    ) -> Result<HashType, ExecutionFailureKind> {
        let route = Route::resolve(
            self.0,
            public_id(&user_holding_a)?,
            public_id(&user_holding_b)?,
        )
        .await?;
        let pool = route.pool(self.0).await?;
        let (input_is_token_a, reserve_in, reserve_out) =
            route.oriented_reserves(&pool, token_definition_id_in)?;

        // The resolver rejects an exact-out at or above the reserve with its own guard, so a
        // proposal built from one could never settle.
        if exact_amount_out >= reserve_out {
            return Err(unpriceable());
        }
        let amount_in = amm_core::quote_exact_output(reserve_in, reserve_out, exact_amount_out)
            .ok_or_else(unpriceable)?;

        let instruction = amm_core::Instruction::SwapExactOutput {
            exact_amount_out,
            max_amount_in,
            token_definition_id_in,
            token_program_id: route.token_program_id,
            token_definition_id_out: if input_is_token_a {
                route.definition_token_b_id
            } else {
                route.definition_token_a_id
            },
            input_is_token_a,
            amount_in,
            reserve_bound_a: pool.reserve_a,
            reserve_bound_b: pool.reserve_b,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        let (user_a_signing_identity, user_b_signing_identity) =
            signing_sides(user_holding_a, user_holding_b, input_is_token_a);

        self.0
            .send_pub_tx(
                vec![
                    AccountIdentity::PublicNoSign(route.pool_id)
                        .select_program_shard(route.amm_program_id),
                    AccountIdentity::PublicNoSign(route.vault_a_id)
                        .select_program_shard(route.token_program_id),
                    AccountIdentity::PublicNoSign(route.vault_b_id)
                        .select_program_shard(route.token_program_id),
                    user_a_signing_identity.select_program_shard(route.token_program_id),
                    user_b_signing_identity.select_program_shard(route.token_program_id),
                ],
                instruction_data,
                route.amm_program_id,
            )
            .await
    }

    pub async fn send_add_liquidity(
        &self,
        user_holding_a: AccountIdentity,
        user_holding_b: AccountIdentity,
        user_holding_lp: AccountIdentity,
        min_amount_liquidity: u128,
        max_amount_to_add_token_a: u128,
        max_amount_to_add_token_b: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let route = Route::resolve(
            self.0,
            public_id(&user_holding_a)?,
            public_id(&user_holding_b)?,
        )
        .await?;
        let pool = route.pool(self.0).await?;

        let ideal_a =
            amm_core::ideal_deposit(pool.reserve_a, pool.reserve_b, max_amount_to_add_token_b)
                .ok_or_else(unpriceable)?;
        let ideal_b =
            amm_core::ideal_deposit(pool.reserve_b, pool.reserve_a, max_amount_to_add_token_a)
                .ok_or_else(unpriceable)?;
        let amount_to_add_token_a = ideal_a.min(max_amount_to_add_token_a);
        let amount_to_add_token_b = ideal_b.min(max_amount_to_add_token_b);
        let amount_liquidity = amm_core::liquidity_minted(
            pool.liquidity_pool_supply,
            amount_to_add_token_a,
            amount_to_add_token_b,
            pool.reserve_a,
            pool.reserve_b,
        )
        .ok_or_else(unpriceable)?;

        let instruction = amm_core::Instruction::AddLiquidity {
            min_amount_liquidity,
            max_amount_to_add_token_a,
            max_amount_to_add_token_b,
            token_program_id: route.token_program_id,
            definition_token_a_id: route.definition_token_a_id,
            definition_token_b_id: route.definition_token_b_id,
            amount_to_add_token_a,
            amount_to_add_token_b,
            amount_liquidity,
            reserve_bound_a: pool.reserve_a,
            reserve_bound_b: pool.reserve_b,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_pub_tx(
                vec![
                    AccountIdentity::PublicNoSign(route.pool_id)
                        .select_program_shard(route.amm_program_id),
                    AccountIdentity::PublicNoSign(route.vault_a_id)
                        .select_program_shard(route.token_program_id),
                    AccountIdentity::PublicNoSign(route.vault_b_id)
                        .select_program_shard(route.token_program_id),
                    AccountIdentity::PublicNoSign(route.liquidity_pool_id())
                        .select_program_shard(route.token_program_id),
                    user_holding_a.select_program_shard(route.token_program_id),
                    user_holding_b.select_program_shard(route.token_program_id),
                    user_holding_lp.select_program_shard(route.token_program_id),
                ],
                instruction_data,
                route.amm_program_id,
            )
            .await
    }

    pub async fn send_remove_liquidity(
        &self,
        user_holding_a: AccountId,
        user_holding_b: AccountId,
        user_holding_lp: AccountIdentity,
        remove_liquidity_amount: u128,
        min_amount_to_remove_token_a: u128,
        min_amount_to_remove_token_b: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let route = Route::resolve(self.0, user_holding_a, user_holding_b).await?;
        let pool = route.pool(self.0).await?;

        let amount_to_remove_token_a = amm_core::withdrawal_share(
            pool.reserve_a,
            remove_liquidity_amount,
            pool.liquidity_pool_supply,
        )
        .ok_or_else(unpriceable)?;
        let amount_to_remove_token_b = amm_core::withdrawal_share(
            pool.reserve_b,
            remove_liquidity_amount,
            pool.liquidity_pool_supply,
        )
        .ok_or_else(unpriceable)?;
        let amount_liquidity_burned = amm_core::withdrawal_share(
            pool.liquidity_pool_supply,
            remove_liquidity_amount,
            pool.liquidity_pool_supply,
        )
        .ok_or_else(unpriceable)?;

        let instruction = amm_core::Instruction::RemoveLiquidity {
            remove_liquidity_amount,
            min_amount_to_remove_token_a,
            min_amount_to_remove_token_b,
            token_program_id: route.token_program_id,
            definition_token_a_id: route.definition_token_a_id,
            definition_token_b_id: route.definition_token_b_id,
            amount_to_remove_token_a,
            amount_to_remove_token_b,
            amount_liquidity_burned,
            // The pool requires the real supply to be at least this, the holding guard requires
            // the burner's balance to be at most the same.
            liquidity_supply_bound: pool.liquidity_pool_supply,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_pub_tx(
                vec![
                    AccountIdentity::PublicNoSign(route.pool_id)
                        .select_program_shard(route.amm_program_id),
                    AccountIdentity::PublicNoSign(route.vault_a_id)
                        .select_program_shard(route.token_program_id),
                    AccountIdentity::PublicNoSign(route.vault_b_id)
                        .select_program_shard(route.token_program_id),
                    AccountIdentity::PublicNoSign(route.liquidity_pool_id())
                        .select_program_shard(route.token_program_id),
                    AccountIdentity::PublicNoSign(user_holding_a)
                        .select_program_shard(route.token_program_id),
                    AccountIdentity::PublicNoSign(user_holding_b)
                        .select_program_shard(route.token_program_id),
                    user_holding_lp.select_program_shard(route.token_program_id),
                ],
                instruction_data,
                route.amm_program_id,
            )
            .await
    }
}

/// Only the side paying the input signs; the other keeps its address without a signature.
fn signing_sides(
    user_holding_a: AccountIdentity,
    user_holding_b: AccountIdentity,
    input_is_token_a: bool,
) -> (AccountIdentity, AccountIdentity) {
    if input_is_token_a {
        let b_id = user_holding_b.account_id();
        (user_holding_a, AccountIdentity::PublicNoSign(b_id))
    } else {
        let a_id = user_holding_a.account_id();
        (AccountIdentity::PublicNoSign(a_id), user_holding_b)
    }
}

/// The observed pool cannot price the requested trade; the pool resolver rejects the same case.
fn unpriceable() -> ExecutionFailureKind {
    ExecutionFailureKind::TransactionBuildError(lee::error::LeeError::InvalidInput(
        "The AMM pool's observed reserves cannot price this trade".to_owned(),
    ))
}

fn public_id(identity: &AccountIdentity) -> Result<AccountId, ExecutionFailureKind> {
    identity
        .public_account_id()
        .ok_or(ExecutionFailureKind::KeyNotFoundError)
}
