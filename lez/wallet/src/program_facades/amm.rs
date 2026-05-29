use amm_core::{compute_liquidity_token_pda, compute_pool_pda, compute_vault_pda};
use common::HashType;
use lee::{AccountId, program::Program};
use token_core::TokenHolding;

use crate::{AccountIdentity, ExecutionFailureKind, WalletCore};
pub struct Amm<'wallet>(pub &'wallet WalletCore);

impl Amm<'_> {
    pub async fn send_new_definition(
        &self,
        user_holding_a: AccountIdentity,
        user_holding_b: AccountIdentity,
        user_holding_lp: AccountIdentity,
        balance_a: u128,
        balance_b: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let a_id = user_holding_a
            .public_account_id()
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;
        let b_id = user_holding_b
            .public_account_id()
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;

        let program = Program::amm();
        let amm_program_id = Program::amm().id();
        let user_a_acc = self
            .0
            .get_account_public(a_id)
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;
        let user_b_acc = self
            .0
            .get_account_public(b_id)
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let definition_token_a_id = TokenHolding::try_from(&user_a_acc.data)
            .map_err(|_err| ExecutionFailureKind::AccountDataError(a_id))?
            .definition_id();
        let definition_token_b_id = TokenHolding::try_from(&user_b_acc.data)
            .map_err(|_err| ExecutionFailureKind::AccountDataError(b_id))?
            .definition_id();

        let amm_pool =
            compute_pool_pda(amm_program_id, definition_token_a_id, definition_token_b_id);
        let vault_holding_a = compute_vault_pda(amm_program_id, amm_pool, definition_token_a_id);
        let vault_holding_b = compute_vault_pda(amm_program_id, amm_pool, definition_token_b_id);
        let pool_lp = compute_liquidity_token_pda(amm_program_id, amm_pool);
        let instruction = amm_core::Instruction::NewDefinition {
            token_a_amount: balance_a,
            token_b_amount: balance_b,
            amm_program_id,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_pub_tx(
                vec![
                    AccountIdentity::PublicNoSign(amm_pool),
                    AccountIdentity::PublicNoSign(vault_holding_a),
                    AccountIdentity::PublicNoSign(vault_holding_b),
                    AccountIdentity::PublicNoSign(pool_lp),
                    user_holding_a,
                    user_holding_b,
                    user_holding_lp,
                ],
                instruction_data,
                &program.into(),
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
        let a_id = user_holding_a
            .public_account_id()
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;
        let b_id = user_holding_b
            .public_account_id()
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;

        let program = Program::amm();
        let amm_program_id = Program::amm().id();
        let user_a_acc = self
            .0
            .get_account_public(a_id)
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;
        let user_b_acc = self
            .0
            .get_account_public(b_id)
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let definition_token_a_id = TokenHolding::try_from(&user_a_acc.data)
            .map_err(|_err| ExecutionFailureKind::AccountDataError(a_id))?
            .definition_id();
        let definition_token_b_id = TokenHolding::try_from(&user_b_acc.data)
            .map_err(|_err| ExecutionFailureKind::AccountDataError(b_id))?
            .definition_id();

        let amm_pool =
            compute_pool_pda(amm_program_id, definition_token_a_id, definition_token_b_id);
        let vault_holding_a = compute_vault_pda(amm_program_id, amm_pool, definition_token_a_id);
        let vault_holding_b = compute_vault_pda(amm_program_id, amm_pool, definition_token_b_id);
        let instruction = amm_core::Instruction::SwapExactInput {
            swap_amount_in,
            min_amount_out,
            token_definition_id_in,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        if (token_definition_id_in != definition_token_a_id)
            && (token_definition_id_in != definition_token_b_id)
        {
            return Err(ExecutionFailureKind::AccountDataError(
                token_definition_id_in,
            ));
        }

        let user_a_signing_identity = if token_definition_id_in == definition_token_a_id {
            user_holding_a
        } else {
            AccountIdentity::PublicNoSign(a_id)
        };

        let user_b_signing_identity = if token_definition_id_in == definition_token_b_id {
            user_holding_b
        } else {
            AccountIdentity::PublicNoSign(b_id)
        };

        self.0
            .send_pub_tx(
                vec![
                    AccountIdentity::PublicNoSign(amm_pool),
                    AccountIdentity::PublicNoSign(vault_holding_a),
                    AccountIdentity::PublicNoSign(vault_holding_b),
                    user_a_signing_identity,
                    user_b_signing_identity,
                ],
                instruction_data,
                &program.into(),
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
        let a_id = user_holding_a
            .public_account_id()
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;
        let b_id = user_holding_b
            .public_account_id()
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;

        let program = Program::amm();
        let amm_program_id = Program::amm().id();
        let user_a_acc = self
            .0
            .get_account_public(a_id)
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;
        let user_b_acc = self
            .0
            .get_account_public(b_id)
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let definition_token_a_id = TokenHolding::try_from(&user_a_acc.data)
            .map_err(|_err| ExecutionFailureKind::AccountDataError(a_id))?
            .definition_id();
        let definition_token_b_id = TokenHolding::try_from(&user_b_acc.data)
            .map_err(|_err| ExecutionFailureKind::AccountDataError(b_id))?
            .definition_id();

        let amm_pool =
            compute_pool_pda(amm_program_id, definition_token_a_id, definition_token_b_id);
        let vault_holding_a = compute_vault_pda(amm_program_id, amm_pool, definition_token_a_id);
        let vault_holding_b = compute_vault_pda(amm_program_id, amm_pool, definition_token_b_id);
        let instruction = amm_core::Instruction::SwapExactOutput {
            exact_amount_out,
            max_amount_in,
            token_definition_id_in,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        if (token_definition_id_in != definition_token_a_id)
            && (token_definition_id_in != definition_token_b_id)
        {
            return Err(ExecutionFailureKind::AccountDataError(
                token_definition_id_in,
            ));
        }

        let user_a_signing_identity = if token_definition_id_in == definition_token_a_id {
            user_holding_a
        } else {
            AccountIdentity::PublicNoSign(a_id)
        };

        let user_b_signing_identity = if token_definition_id_in == definition_token_b_id {
            user_holding_b
        } else {
            AccountIdentity::PublicNoSign(b_id)
        };

        self.0
            .send_pub_tx(
                vec![
                    AccountIdentity::PublicNoSign(amm_pool),
                    AccountIdentity::PublicNoSign(vault_holding_a),
                    AccountIdentity::PublicNoSign(vault_holding_b),
                    user_a_signing_identity,
                    user_b_signing_identity,
                ],
                instruction_data,
                &program.into(),
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
        let a_id = user_holding_a
            .public_account_id()
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;
        let b_id = user_holding_b
            .public_account_id()
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;

        let program = Program::amm();
        let amm_program_id = Program::amm().id();
        let user_a_acc = self
            .0
            .get_account_public(a_id)
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;
        let user_b_acc = self
            .0
            .get_account_public(b_id)
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let definition_token_a_id = TokenHolding::try_from(&user_a_acc.data)
            .map_err(|_err| ExecutionFailureKind::AccountDataError(a_id))?
            .definition_id();
        let definition_token_b_id = TokenHolding::try_from(&user_b_acc.data)
            .map_err(|_err| ExecutionFailureKind::AccountDataError(b_id))?
            .definition_id();

        let amm_pool =
            compute_pool_pda(amm_program_id, definition_token_a_id, definition_token_b_id);
        let vault_holding_a = compute_vault_pda(amm_program_id, amm_pool, definition_token_a_id);
        let vault_holding_b = compute_vault_pda(amm_program_id, amm_pool, definition_token_b_id);
        let pool_lp = compute_liquidity_token_pda(amm_program_id, amm_pool);
        let instruction = amm_core::Instruction::AddLiquidity {
            min_amount_liquidity,
            max_amount_to_add_token_a,
            max_amount_to_add_token_b,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_pub_tx(
                vec![
                    AccountIdentity::PublicNoSign(amm_pool),
                    AccountIdentity::PublicNoSign(vault_holding_a),
                    AccountIdentity::PublicNoSign(vault_holding_b),
                    AccountIdentity::PublicNoSign(pool_lp),
                    user_holding_a,
                    user_holding_b,
                    user_holding_lp,
                ],
                instruction_data,
                &program.into(),
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
        let program = Program::amm();
        let amm_program_id = Program::amm().id();
        let user_a_acc = self
            .0
            .get_account_public(user_holding_a)
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;
        let user_b_acc = self
            .0
            .get_account_public(user_holding_b)
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let definition_token_a_id = TokenHolding::try_from(&user_a_acc.data)
            .map_err(|_err| ExecutionFailureKind::AccountDataError(user_holding_a))?
            .definition_id();
        let definition_token_b_id = TokenHolding::try_from(&user_b_acc.data)
            .map_err(|_err| ExecutionFailureKind::AccountDataError(user_holding_b))?
            .definition_id();

        let amm_pool =
            compute_pool_pda(amm_program_id, definition_token_a_id, definition_token_b_id);
        let vault_holding_a = compute_vault_pda(amm_program_id, amm_pool, definition_token_a_id);
        let vault_holding_b = compute_vault_pda(amm_program_id, amm_pool, definition_token_b_id);
        let pool_lp = compute_liquidity_token_pda(amm_program_id, amm_pool);
        let instruction = amm_core::Instruction::RemoveLiquidity {
            remove_liquidity_amount,
            min_amount_to_remove_token_a,
            min_amount_to_remove_token_b,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_pub_tx(
                vec![
                    AccountIdentity::PublicNoSign(amm_pool),
                    AccountIdentity::PublicNoSign(vault_holding_a),
                    AccountIdentity::PublicNoSign(vault_holding_b),
                    AccountIdentity::PublicNoSign(pool_lp),
                    AccountIdentity::PublicNoSign(user_holding_a),
                    AccountIdentity::PublicNoSign(user_holding_b),
                    user_holding_lp,
                ],
                instruction_data,
                &program.into(),
            )
            .await
    }
}
