use amm_core::{PoolDefinition, compute_liquidity_token_pda, compute_pool_pda, compute_vault_id};
use common::HashType;
use lee::{AccountId, AccountIdData, ProgramShardSelector, program::Program};
use token_core::{HoldingKind, HoldingTarget};

use crate::{AccountIdentity, AccountMention, ExecutionFailureKind, WalletCore};

pub struct Amm<'wallet>(pub &'wallet WalletCore);

impl Amm<'_> {
    async fn pool(
        &self,
        definition_a: AccountId,
        definition_b: AccountId,
    ) -> Result<(AccountId, PoolDefinition), ExecutionFailureKind> {
        let pool_id = pool_id(definition_a, definition_b);
        let account = self
            .0
            .get_account_view(ProgramShardSelector::new(pool_id, amm_program_id()))
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;
        let definition = PoolDefinition::try_from(account.data.shard(amm_program_id()))
            .map_err(|_err| ExecutionFailureKind::AccountDataError(pool_id))?;
        Ok((pool_id, definition))
    }

    async fn ordered_pool(
        &self,
        definition_a: AccountId,
        definition_b: AccountId,
    ) -> Result<AccountId, ExecutionFailureKind> {
        let (pool_id, definition) = self.pool(definition_a, definition_b).await?;
        if (
            definition.definition_token_a_id,
            definition.definition_token_b_id,
        ) != (definition_a, definition_b)
        {
            return Err(ExecutionFailureKind::AccountDataError(pool_id));
        }
        Ok(pool_id)
    }

    async fn send(
        &self,
        accounts: Vec<AccountMention>,
        instruction: amm_core::Instruction,
    ) -> Result<HashType, ExecutionFailureKind> {
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");
        self.0
            .send_pub_tx(accounts, instruction_data, amm_program_id())
            .await
    }

    pub async fn send_new_definition(
        &self,
        user: AccountIdentity,
        definition_a: AccountId,
        definition_b: AccountId,
        balance_a: u128,
        balance_b: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let pool_id = pool_id(definition_a, definition_b);
        let (holder, rows) = accounts(&user, pool_id, definition_a, definition_b, true);
        self.send(
            rows,
            amm_core::Instruction::NewDefinition {
                token_a_amount: balance_a,
                token_b_amount: balance_b,
                token_program_id: token_program_id(),
                user: holder,
            },
        )
        .await
    }

    pub async fn send_swap_exact_input(
        &self,
        user: AccountIdentity,
        definition_in: AccountId,
        definition_out: AccountId,
        swap_amount_in: u128,
        min_amount_out: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let (pool_id, pool) = self.pool(definition_in, definition_out).await?;
        let (holder, rows) = accounts(
            &user,
            pool_id,
            pool.definition_token_a_id,
            pool.definition_token_b_id,
            false,
        );
        self.send(
            rows,
            amm_core::Instruction::SwapExactInput {
                swap_amount_in,
                min_amount_out,
                token_definition_id_in: definition_in,
                user: holder,
            },
        )
        .await
    }

    pub async fn send_swap_exact_output(
        &self,
        user: AccountIdentity,
        definition_in: AccountId,
        definition_out: AccountId,
        exact_amount_out: u128,
        max_amount_in: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let (pool_id, pool) = self.pool(definition_in, definition_out).await?;
        let (holder, rows) = accounts(
            &user,
            pool_id,
            pool.definition_token_a_id,
            pool.definition_token_b_id,
            false,
        );
        self.send(
            rows,
            amm_core::Instruction::SwapExactOutput {
                exact_amount_out,
                max_amount_in,
                token_definition_id_in: definition_in,
                user: holder,
            },
        )
        .await
    }

    pub async fn send_add_liquidity(
        &self,
        user: AccountIdentity,
        definition_a: AccountId,
        definition_b: AccountId,
        min_amount_liquidity: u128,
        max_amount_to_add_token_a: u128,
        max_amount_to_add_token_b: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let pool_id = self.ordered_pool(definition_a, definition_b).await?;
        let (holder, rows) = accounts(&user, pool_id, definition_a, definition_b, true);
        self.send(
            rows,
            amm_core::Instruction::AddLiquidity {
                min_amount_liquidity,
                max_amount_to_add_token_a,
                max_amount_to_add_token_b,
                user: holder,
            },
        )
        .await
    }

    pub async fn send_remove_liquidity(
        &self,
        user: AccountIdentity,
        definition_a: AccountId,
        definition_b: AccountId,
        remove_liquidity_amount: u128,
        min_amount_to_remove_token_a: u128,
        min_amount_to_remove_token_b: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let pool_id = self.ordered_pool(definition_a, definition_b).await?;
        let (holder, rows) = accounts(&user, pool_id, definition_a, definition_b, true);
        self.send(
            rows,
            amm_core::Instruction::RemoveLiquidity {
                remove_liquidity_amount,
                min_amount_to_remove_token_a,
                min_amount_to_remove_token_b,
                user: holder,
            },
        )
        .await
    }
}

fn amm_program_id() -> AccountId {
    programs::amm().id().into()
}

fn token_program_id() -> AccountId {
    programs::token().id().into()
}

fn pool_id(definition_a: AccountId, definition_b: AccountId) -> AccountId {
    compute_pool_pda(
        amm_program_id(),
        definition_a,
        definition_b,
        token_program_id(),
    )
}

fn accounts(
    user: &AccountIdentity,
    pool_id: AccountId,
    definition_a: AccountId,
    definition_b: AccountId,
    with_liquidity: bool,
) -> (HoldingTarget, Vec<AccountMention>) {
    let (amm_program_id, token_program_id) = (amm_program_id(), token_program_id());
    let holder = HoldingTarget {
        owner_id: user.account_id(),
        account_id_data: AccountIdData::public(),
    };
    let token_row = |id| AccountIdentity::PublicNoSign(id).select_program_shard(token_program_id);
    let vault = |definition| token_row(compute_vault_id(token_program_id, pool_id, definition));
    let holding = |definition| {
        token_row(token_core::holding_id(
            &holder,
            token_program_id,
            definition,
            HoldingKind::Fungible,
        ))
    };
    let pool = AccountIdentity::PublicNoSign(pool_id).select_program_shard(amm_program_id);
    let liquidity = compute_liquidity_token_pda(amm_program_id, pool_id);
    let rows = if with_liquidity {
        vec![
            pool,
            vault(definition_a),
            vault(definition_b),
            token_row(liquidity),
            holding(definition_a),
            holding(definition_b),
            holding(liquidity),
            user.clone().balance(),
        ]
    } else {
        vec![
            pool,
            vault(definition_a),
            vault(definition_b),
            holding(definition_a),
            holding(definition_b),
            user.clone().balance(),
        ]
    };
    (holder, rows)
}
