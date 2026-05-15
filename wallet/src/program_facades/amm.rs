use amm_core::{compute_liquidity_token_pda, compute_pool_pda, compute_vault_pda};
use common::{HashType, transaction::NSSATransaction};
use nssa::{AccountId, program::Program, public_transaction::WitnessSet};
use pyo3::exceptions::PyRuntimeError;
use sequencer_service_rpc::RpcClient as _;
use token_core::TokenHolding;

use crate::{
    ExecutionFailureKind, WalletCore,
    cli::CliAccountMention,
    helperfunctions::read_pin,
    signing::SigningGroups,
};
pub struct Amm<'wallet>(pub &'wallet WalletCore);

impl Amm<'_> {
    #[expect(clippy::too_many_arguments, reason = "each parameter is distinct")]
    pub async fn send_new_definition(
        &self,
        user_holding_a: AccountId,
        user_holding_b: AccountId,
        user_holding_lp: AccountId,
        balance_a: u128,
        balance_b: u128,
        a_mention: &CliAccountMention,
        b_mention: &CliAccountMention,
        lp_mention: &CliAccountMention,
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

        let mut groups = SigningGroups::new();
        groups
            .add_sender(a_mention, user_holding_a, self.0)
            .and_then(|()| groups.add_sender(b_mention, user_holding_b, self.0))
            .and_then(|()| groups.add_recipient(lp_mention, user_holding_lp, self.0))
            .map_err(|e| ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(e.to_string())))?;

        let mut nonces = self.0.get_accounts_nonces(vec![user_holding_a, user_holding_b]).await
            .map_err(ExecutionFailureKind::SequencerError)?;

        if groups.signing_ids().contains(&user_holding_lp) {
            let lp_nonces = self.0.get_accounts_nonces(vec![user_holding_lp]).await
                .map_err(ExecutionFailureKind::SequencerError)?;
            nonces.push(lp_nonces.into_iter().next().unwrap_or(nssa_core::account::Nonce(0)));
        } else {
            println!(
                "Liquidity pool tokens receiver's account ({user_holding_lp}) private key not found in wallet. Proceeding with only liquidity provider's keys."
            );
        }

        let message = nssa::public_transaction::Message::try_new(program.id(), account_ids, nonces, instruction).unwrap();

        let pin = if groups.needs_pin() {
            read_pin()
                .map_err(|e| ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(e.to_string())))?
                .as_str()
                .to_owned()
        } else {
            String::new()
        };
        let sigs = groups.sign_all(&message.hash(), &pin)
            .map_err(|e| ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(e.to_string())))?;

        let tx = nssa::PublicTransaction::new(message, WitnessSet::from_raw_parts(sigs));

        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
    }

    #[expect(clippy::too_many_arguments, reason = "each parameter is distinct")]
    pub async fn send_swap_exact_input(
        &self,
        user_holding_a: AccountId,
        user_holding_b: AccountId,
        swap_amount_in: u128,
        min_amount_out: u128,
        token_definition_id_in: AccountId,
        a_mention: &CliAccountMention,
        b_mention: &CliAccountMention,
    ) -> Result<HashType, ExecutionFailureKind> {
        let instruction = amm_core::Instruction::SwapExactInput {
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

        let (account_id_auth, seller_mention) = if definition_token_a_id == token_definition_id_in {
            (user_holding_a, a_mention)
        } else if definition_token_b_id == token_definition_id_in {
            (user_holding_b, b_mention)
        } else {
            return Err(ExecutionFailureKind::AccountDataError(token_definition_id_in));
        };

        let mut groups = SigningGroups::new();
        groups
            .add_sender(seller_mention, account_id_auth, self.0)
            .map_err(|e| ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(e.to_string())))?;

        let nonces = self.0.get_accounts_nonces(groups.signing_ids()).await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let message = nssa::public_transaction::Message::try_new(program.id(), account_ids, nonces, instruction).unwrap();

        let pin = if groups.needs_pin() {
            read_pin()
                .map_err(|e| ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(e.to_string())))?
                .as_str()
                .to_owned()
        } else {
            String::new()
        };
        let sigs = groups.sign_all(&message.hash(), &pin)
            .map_err(|e| ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(e.to_string())))?;

        let tx = nssa::PublicTransaction::new(message, WitnessSet::from_raw_parts(sigs));

        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
    }

    #[expect(clippy::too_many_arguments, reason = "each parameter is distinct")]
    pub async fn send_swap_exact_output(
        &self,
        user_holding_a: AccountId,
        user_holding_b: AccountId,
        exact_amount_out: u128,
        max_amount_in: u128,
        token_definition_id_in: AccountId,
        a_mention: &CliAccountMention,
        b_mention: &CliAccountMention,
    ) -> Result<HashType, ExecutionFailureKind> {
        let instruction = amm_core::Instruction::SwapExactOutput {
            exact_amount_out,
            max_amount_in,
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

        let (account_id_auth, seller_mention) = if definition_token_a_id == token_definition_id_in {
            (user_holding_a, a_mention)
        } else if definition_token_b_id == token_definition_id_in {
            (user_holding_b, b_mention)
        } else {
            return Err(ExecutionFailureKind::AccountDataError(token_definition_id_in));
        };

        let mut groups = SigningGroups::new();
        groups
            .add_sender(seller_mention, account_id_auth, self.0)
            .map_err(|e| ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(e.to_string())))?;

        let nonces = self.0.get_accounts_nonces(groups.signing_ids()).await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let message = nssa::public_transaction::Message::try_new(program.id(), account_ids, nonces, instruction).unwrap();

        let pin = if groups.needs_pin() {
            read_pin()
                .map_err(|e| ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(e.to_string())))?
                .as_str()
                .to_owned()
        } else {
            String::new()
        };
        let sigs = groups.sign_all(&message.hash(), &pin)
            .map_err(|e| ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(e.to_string())))?;

        let tx = nssa::PublicTransaction::new(message, WitnessSet::from_raw_parts(sigs));

        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
    }

    #[expect(clippy::too_many_arguments, reason = "each parameter is distinct")]
    pub async fn send_add_liquidity(
        &self,
        user_holding_a: AccountId,
        user_holding_b: AccountId,
        user_holding_lp: AccountId,
        min_amount_liquidity: u128,
        max_amount_to_add_token_a: u128,
        max_amount_to_add_token_b: u128,
        a_mention: &CliAccountMention,
        b_mention: &CliAccountMention,
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

        let mut groups = SigningGroups::new();
        groups
            .add_sender(a_mention, user_holding_a, self.0)
            .and_then(|()| groups.add_sender(b_mention, user_holding_b, self.0))
            .map_err(|e| ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(e.to_string())))?;

        let nonces = self.0.get_accounts_nonces(groups.signing_ids()).await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let message = nssa::public_transaction::Message::try_new(program.id(), account_ids, nonces, instruction).unwrap();

        let pin = if groups.needs_pin() {
            read_pin()
                .map_err(|e| ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(e.to_string())))?
                .as_str()
                .to_owned()
        } else {
            String::new()
        };
        let sigs = groups.sign_all(&message.hash(), &pin)
            .map_err(|e| ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(e.to_string())))?;

        let tx = nssa::PublicTransaction::new(message, WitnessSet::from_raw_parts(sigs));

        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
    }

    #[expect(clippy::too_many_arguments, reason = "each parameter is distinct")]
    pub async fn send_remove_liquidity(
        &self,
        user_holding_a: AccountId,
        user_holding_b: AccountId,
        user_holding_lp: AccountId,
        remove_liquidity_amount: u128,
        min_amount_to_remove_token_a: u128,
        min_amount_to_remove_token_b: u128,
        lp_mention: &CliAccountMention,
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

        let mut groups = SigningGroups::new();
        groups
            .add_sender(lp_mention, user_holding_lp, self.0)
            .map_err(|e| ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(e.to_string())))?;

        let nonces = self.0.get_accounts_nonces(groups.signing_ids()).await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let message = nssa::public_transaction::Message::try_new(program.id(), account_ids, nonces, instruction).unwrap();

        let pin = if groups.needs_pin() {
            read_pin()
                .map_err(|e| ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(e.to_string())))?
                .as_str()
                .to_owned()
        } else {
            String::new()
        };
        let sigs = groups.sign_all(&message.hash(), &pin)
            .map_err(|e| ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(e.to_string())))?;

        let tx = nssa::PublicTransaction::new(message, WitnessSet::from_raw_parts(sigs));

        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
    }
}
