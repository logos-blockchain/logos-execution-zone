use amm_core::{compute_liquidity_token_pda, compute_pool_pda, compute_vault_pda};
use common::{HashType, transaction::NSSATransaction};
use nssa::{AccountId, program::Program};
use sequencer_service_rpc::RpcClient as _;
use token_core::TokenHolding;

use crate::{ExecutionFailureKind, WalletCore};
pub struct Amm<'wallet>(pub &'wallet WalletCore);

impl Amm<'_> {
    #[expect(
        clippy::too_many_arguments,
        reason = "each parameter is distinct; grouping into a struct would add unnecessary indirection"
    )]
    pub async fn send_new_definition(
        &self,
        user_holding_a: AccountId,
        user_holding_b: AccountId,
        user_holding_lp: AccountId,
        balance_a: u128,
        balance_b: u128,
        key_path_a: Option<&str>,
        key_path_b: Option<&str>,
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

        // Check if LP has a stored key to determine if LP nonce is needed — before message creation
        let lp_sk = self
            .0
            .storage
            .user_data
            .get_pub_account_signing_key(user_holding_lp);

        let mut nonces = self
            .0
            .get_accounts_nonces(vec![user_holding_a, user_holding_b])
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        if lp_sk.is_some() {
            let lp_nonces = self
                .0
                .get_accounts_nonces(vec![user_holding_lp])
                .await
                .map_err(ExecutionFailureKind::SequencerError)?;
            nonces.extend(lp_nonces);
        } else {
            println!(
                "Liquidity pool tokens receiver's account ({user_holding_lp}) private key not found in wallet. Proceeding with only liquidity provider's keys."
            );
        }

        let message = nssa::public_transaction::Message::try_new(
            program.id(),
            account_ids,
            nonces,
            instruction,
        )
        .unwrap();

        let msg_hash = message.hash();
        let pin = if key_path_a.is_some() || key_path_b.is_some() {
            Some(crate::helperfunctions::read_pin().map_err(|e| {
                ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<
                    pyo3::exceptions::PyRuntimeError,
                    _,
                >(e.to_string()))
            })?)
        } else {
            None
        };

        let (sig_a, pk_a) = if let Some(kp) = key_path_a {
            keycard_wallet::KeycardWallet::sign_message_for_path_with_connect(
                pin.as_ref().unwrap(),
                kp,
                &msg_hash,
            )?
        } else {
            let sk = self
                .0
                .storage
                .user_data
                .get_pub_account_signing_key(user_holding_a)
                .ok_or(ExecutionFailureKind::KeyNotFoundError)?;
            (
                nssa::Signature::new(sk, &msg_hash),
                nssa::PublicKey::new_from_private_key(sk),
            )
        };

        let (sig_b, pk_b) = if let Some(kp) = key_path_b {
            keycard_wallet::KeycardWallet::sign_message_for_path_with_connect(
                pin.as_ref().unwrap(),
                kp,
                &msg_hash,
            )?
        } else {
            let sk = self
                .0
                .storage
                .user_data
                .get_pub_account_signing_key(user_holding_b)
                .ok_or(ExecutionFailureKind::KeyNotFoundError)?;
            (
                nssa::Signature::new(sk, &msg_hash),
                nssa::PublicKey::new_from_private_key(sk),
            )
        };

        let mut sigs = vec![sig_a, sig_b];
        let mut pks = vec![pk_a, pk_b];

        if let Some(sk_lp) = lp_sk {
            sigs.push(nssa::Signature::new(sk_lp, &msg_hash));
            pks.push(nssa::PublicKey::new_from_private_key(sk_lp));
        }

        let witness_set = nssa::public_transaction::WitnessSet::from_list(&message, &sigs, &pks)
            .map_err(ExecutionFailureKind::TransactionBuildError)?;

        let tx = nssa::PublicTransaction::new(message, witness_set);

        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
    }

    #[expect(clippy::too_many_arguments, reason = "To fix later")]
    pub async fn send_swap_exact_input(
        &self,
        user_holding_a: AccountId,
        user_holding_b: AccountId,
        swap_amount_in: u128,
        min_amount_out: u128,
        token_definition_id_in: AccountId,
        user_holding_a_key_path: Option<&str>,
        user_holding_b_key_path: Option<&str>,
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

        let account_id_auth = if definition_token_a_id == token_definition_id_in {
            user_holding_a
        } else if definition_token_b_id == token_definition_id_in {
            user_holding_b
        } else {
            return Err(ExecutionFailureKind::AccountDataError(
                token_definition_id_in,
            ));
        };

        let nonces = self
            .0
            .get_accounts_nonces(vec![account_id_auth])
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let message = nssa::public_transaction::Message::try_new(
            program.id(),
            account_ids,
            nonces,
            instruction,
        )
        .unwrap();

        let msg_hash = message.hash();
        let witness_set = if let (Some(kp_a), Some(kp_b)) =
            (user_holding_a_key_path, user_holding_b_key_path)
        {
            let pin = crate::helperfunctions::read_pin().map_err(|e| {
                ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<
                    pyo3::exceptions::PyRuntimeError,
                    _,
                >(e.to_string()))
            })?;
            let (sig1, pk1) = keycard_wallet::KeycardWallet::sign_message_for_path_with_connect(
                &pin, kp_a, &msg_hash,
            )?;
            let (sig2, pk2) = keycard_wallet::KeycardWallet::sign_message_for_path_with_connect(
                &pin, kp_b, &msg_hash,
            )?;
            nssa::public_transaction::WitnessSet::from_list(&message, &[sig1, sig2], &[pk1, pk2])
                .map_err(ExecutionFailureKind::TransactionBuildError)?
        } else {
            let signing_key = self
                .0
                .storage
                .user_data
                .get_pub_account_signing_key(account_id_auth)
                .ok_or(ExecutionFailureKind::KeyNotFoundError)?;
            nssa::public_transaction::WitnessSet::for_message(&message, &[signing_key])
        };

        let tx = nssa::PublicTransaction::new(message, witness_set);

        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
    }

    #[expect(clippy::too_many_arguments, reason = "To fix later")]
    pub async fn send_swap_exact_output(
        &self,
        user_holding_a: AccountId,
        user_holding_b: AccountId,
        exact_amount_out: u128,
        max_amount_in: u128,
        token_definition_id_in: AccountId,
        user_holding_a_key_path: Option<&str>,
        user_holding_b_key_path: Option<&str>,
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

        let account_id_auth = if definition_token_a_id == token_definition_id_in {
            user_holding_a
        } else if definition_token_b_id == token_definition_id_in {
            user_holding_b
        } else {
            return Err(ExecutionFailureKind::AccountDataError(
                token_definition_id_in,
            ));
        };

        let nonces = self
            .0
            .get_accounts_nonces(vec![account_id_auth])
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let message = nssa::public_transaction::Message::try_new(
            program.id(),
            account_ids,
            nonces,
            instruction,
        )
        .unwrap();

        let msg_hash = message.hash();
        let witness_set = if let (Some(kp_a), Some(kp_b)) =
            (user_holding_a_key_path, user_holding_b_key_path)
        {
            let pin = crate::helperfunctions::read_pin().map_err(|e| {
                ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<
                    pyo3::exceptions::PyRuntimeError,
                    _,
                >(e.to_string()))
            })?;
            let (sig_1, pk_1) = keycard_wallet::KeycardWallet::sign_message_for_path_with_connect(
                &pin, kp_a, &msg_hash,
            )?;
            let (sig_2, pk_2) = keycard_wallet::KeycardWallet::sign_message_for_path_with_connect(
                &pin, kp_b, &msg_hash,
            )?;
            nssa::public_transaction::WitnessSet::from_list(
                &message,
                &[sig_1, sig_2],
                &[pk_1, pk_2],
            )
            .map_err(ExecutionFailureKind::TransactionBuildError)?
        } else {
            let signing_key = self
                .0
                .storage
                .user_data
                .get_pub_account_signing_key(account_id_auth)
                .ok_or(ExecutionFailureKind::KeyNotFoundError)?;
            nssa::public_transaction::WitnessSet::for_message(&message, &[signing_key])
        };

        let tx = nssa::PublicTransaction::new(message, witness_set);

        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "each parameter is distinct; grouping into a struct would add unnecessary indirection"
    )]
    pub async fn send_add_liquidity(
        &self,
        user_holding_a: AccountId,
        user_holding_b: AccountId,
        user_holding_lp: AccountId,
        min_amount_liquidity: u128,
        max_amount_to_add_token_a: u128,
        max_amount_to_add_token_b: u128,
        key_path_a: Option<&str>,
        key_path_b: Option<&str>,
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

        let message = nssa::public_transaction::Message::try_new(
            program.id(),
            account_ids,
            nonces,
            instruction,
        )
        .unwrap();

        let msg_hash = message.hash();
        let pin = if key_path_a.is_some() || key_path_b.is_some() {
            Some(crate::helperfunctions::read_pin().map_err(|e| {
                ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<
                    pyo3::exceptions::PyRuntimeError,
                    _,
                >(e.to_string()))
            })?)
        } else {
            None
        };

        let (sig_a, pk_a) = if let Some(kp) = key_path_a {
            keycard_wallet::KeycardWallet::sign_message_for_path_with_connect(
                pin.as_ref().unwrap(),
                kp,
                &msg_hash,
            )?
        } else {
            let sk = self
                .0
                .storage
                .user_data
                .get_pub_account_signing_key(user_holding_a)
                .ok_or(ExecutionFailureKind::KeyNotFoundError)?;
            (
                nssa::Signature::new(sk, &msg_hash),
                nssa::PublicKey::new_from_private_key(sk),
            )
        };

        let (sig_b, pk_b) = if let Some(kp) = key_path_b {
            keycard_wallet::KeycardWallet::sign_message_for_path_with_connect(
                pin.as_ref().unwrap(),
                kp,
                &msg_hash,
            )?
        } else {
            let sk = self
                .0
                .storage
                .user_data
                .get_pub_account_signing_key(user_holding_b)
                .ok_or(ExecutionFailureKind::KeyNotFoundError)?;
            (
                nssa::Signature::new(sk, &msg_hash),
                nssa::PublicKey::new_from_private_key(sk),
            )
        };

        let witness_set = nssa::public_transaction::WitnessSet::from_list(
            &message,
            &[sig_a, sig_b],
            &[pk_a, pk_b],
        )
        .map_err(ExecutionFailureKind::TransactionBuildError)?;

        let tx = nssa::PublicTransaction::new(message, witness_set);

        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "each parameter is distinct; grouping into a struct would add unnecessary indirection"
    )]
    pub async fn send_remove_liquidity(
        &self,
        user_holding_a: AccountId,
        user_holding_b: AccountId,
        user_holding_lp: AccountId,
        remove_liquidity_amount: u128,
        min_amount_to_remove_token_a: u128,
        min_amount_to_remove_token_b: u128,
        key_path_lp: Option<&str>,
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

        let message = nssa::public_transaction::Message::try_new(
            program.id(),
            account_ids,
            nonces,
            instruction,
        )
        .unwrap();

        let msg_hash = message.hash();
        let witness_set = if let Some(kp) = key_path_lp {
            let pin = crate::helperfunctions::read_pin().map_err(|e| {
                ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<
                    pyo3::exceptions::PyRuntimeError,
                    _,
                >(e.to_string()))
            })?;
            let (sig, pk) = keycard_wallet::KeycardWallet::sign_message_for_path_with_connect(
                &pin, kp, &msg_hash,
            )?;
            nssa::public_transaction::WitnessSet::from_list(&message, &[sig], &[pk])
                .map_err(ExecutionFailureKind::TransactionBuildError)?
        } else {
            let signing_key_lp = self
                .0
                .storage
                .user_data
                .get_pub_account_signing_key(user_holding_lp)
                .ok_or(ExecutionFailureKind::KeyNotFoundError)?;
            nssa::public_transaction::WitnessSet::for_message(&message, &[signing_key_lp])
        };

        let tx = nssa::PublicTransaction::new(message, witness_set);

        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
    }
}
