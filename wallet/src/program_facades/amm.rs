use amm_core::{compute_liquidity_token_pda, compute_pool_pda, compute_vault_pda};
use common::{HashType, transaction::NSSATransaction};
use nssa::{AccountId, program::Program};
use sequencer_service_rpc::RpcClient as _;
use token_core::TokenHolding;

use crate::{ExecutionFailureKind, WalletCore};
pub struct Amm<'wallet>(pub &'wallet WalletCore);

impl Amm<'_> {
    pub async fn send_new_definition(
        &self,
        user_holding_a: AccountId,
        user_holding_b: AccountId,
        user_holding_lp: AccountId,
        balance_a: u128,
        balance_b: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let program = Program::amm();
        let amm_program_id = Program::amm().id();
        let instruction = amm_core::Instruction::NewDefinition {
            token_a_amount: balance_a,
            token_b_amount: balance_b,
            amm_program_id,
        };

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

        let account_ids = vec![
            amm_pool,
            vault_holding_a,
            vault_holding_b,
            pool_lp,
            user_holding_a,
            user_holding_b,
            user_holding_lp,
        ];

        let nonces = self
            .0
            .get_accounts_nonces(vec![user_holding_a, user_holding_b])
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let signing_key_a = self
            .0
            .storage
            .user_data
            .get_pub_account_signing_key(user_holding_a)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;

        let signing_key_b = self
            .0
            .storage
            .user_data
            .get_pub_account_signing_key(user_holding_b)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;

        let message = nssa::public_transaction::Message::try_new(
            program.id(),
            account_ids,
            nonces,
            instruction,
        )
        .unwrap();

        let witness_set = nssa::public_transaction::WitnessSet::for_message(
            &message,
            &[signing_key_a, signing_key_b],
        );

        let tx = nssa::PublicTransaction::new(message, witness_set);

        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
    }

    pub async fn send_swap(
        &self,
        user_holding_a: AccountId,
        user_holding_b: AccountId,
        swap_amount_in: u128,
        min_amount_out: u128,
        token_definition_id_in: AccountId,
    ) -> Result<HashType, ExecutionFailureKind> {
        let instruction = amm_core::Instruction::Swap {
            swap_amount_in,
            min_amount_out,
            token_definition_id_in,
        };
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

        let account_ids = vec![
            amm_pool,
            vault_holding_a,
            vault_holding_b,
            user_holding_a,
            user_holding_b,
        ];

        let account_id_auth;

        // Checking, which account are associated with TokenDefinition
        let token_holder_acc_a = self
            .0
            .get_account_public(user_holding_a)
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;
        let token_holder_acc_b = self
            .0
            .get_account_public(user_holding_b)
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let token_holder_a = TokenHolding::try_from(&token_holder_acc_a.data)
            .map_err(|_err| ExecutionFailureKind::AccountDataError(user_holding_a))?;
        let token_holder_b = TokenHolding::try_from(&token_holder_acc_b.data)
            .map_err(|_err| ExecutionFailureKind::AccountDataError(user_holding_b))?;

        if token_holder_a.definition_id() == token_definition_id_in {
            account_id_auth = user_holding_a;
        } else if token_holder_b.definition_id() == token_definition_id_in {
            account_id_auth = user_holding_b;
        } else {
            return Err(ExecutionFailureKind::AccountDataError(
                token_definition_id_in,
            ));
        }

        let nonces = self
            .0
            .get_accounts_nonces(vec![account_id_auth])
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let signing_key = self
            .0
            .storage
            .user_data
            .get_pub_account_signing_key(account_id_auth)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;

        let message = nssa::public_transaction::Message::try_new(
            program.id(),
            account_ids,
            nonces,
            instruction,
        )
        .unwrap();

        let witness_set =
            nssa::public_transaction::WitnessSet::for_message(&message, &[signing_key]);

        let tx = nssa::PublicTransaction::new(message, witness_set);

        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
    }

    pub async fn send_add_liquidity(
        &self,
        user_holding_a: AccountId,
        user_holding_b: AccountId,
        user_holding_lp: AccountId,
        min_amount_liquidity: u128,
        max_amount_to_add_token_a: u128,
        max_amount_to_add_token_b: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let instruction = amm_core::Instruction::AddLiquidity {
            min_amount_liquidity,
            max_amount_to_add_token_a,
            max_amount_to_add_token_b,
        };
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

        let account_ids = vec![
            amm_pool,
            vault_holding_a,
            vault_holding_b,
            pool_lp,
            user_holding_a,
            user_holding_b,
            user_holding_lp,
        ];

        let nonces = self
            .0
            .get_accounts_nonces(vec![user_holding_a, user_holding_b])
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let signing_key_a = self
            .0
            .storage
            .user_data
            .get_pub_account_signing_key(user_holding_a)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;

        let signing_key_b = self
            .0
            .storage
            .user_data
            .get_pub_account_signing_key(user_holding_b)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;

        let message = nssa::public_transaction::Message::try_new(
            program.id(),
            account_ids,
            nonces,
            instruction,
        )
        .unwrap();

        let witness_set = nssa::public_transaction::WitnessSet::for_message(
            &message,
            &[signing_key_a, signing_key_b],
        );

        let tx = nssa::PublicTransaction::new(message, witness_set);

        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
    }

    pub async fn send_remove_liquidity(
        &self,
        user_holding_a: AccountId,
        user_holding_b: AccountId,
        user_holding_lp: AccountId,
        remove_liquidity_amount: u128,
        min_amount_to_remove_token_a: u128,
        min_amount_to_remove_token_b: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let instruction = amm_core::Instruction::RemoveLiquidity {
            remove_liquidity_amount,
            min_amount_to_remove_token_a,
            min_amount_to_remove_token_b,
        };
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

        let account_ids = vec![
            amm_pool,
            vault_holding_a,
            vault_holding_b,
            pool_lp,
            user_holding_a,
            user_holding_b,
            user_holding_lp,
        ];

        let nonces = self
            .0
            .get_accounts_nonces(vec![user_holding_lp])
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let signing_key_lp = self
            .0
            .storage
            .user_data
            .get_pub_account_signing_key(user_holding_lp)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;

        let message = nssa::public_transaction::Message::try_new(
            program.id(),
            account_ids,
            nonces,
            instruction,
        )
        .unwrap();

        let witness_set =
            nssa::public_transaction::WitnessSet::for_message(&message, &[signing_key_lp]);

        let tx = nssa::PublicTransaction::new(message, witness_set);

        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
    }
}
