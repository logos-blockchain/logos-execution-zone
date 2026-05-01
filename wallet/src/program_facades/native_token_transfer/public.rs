use common::{HashType, transaction::NSSATransaction};
use keycard_wallet::KeycardWallet;
use nssa::{
    AccountId, PublicTransaction,
    program::Program,
    public_transaction::{Message, WitnessSet},
};
use pyo3::exceptions::PyRuntimeError;
use sequencer_service_rpc::RpcClient as _;

use super::NativeTokenTransfer;
use crate::ExecutionFailureKind;

impl NativeTokenTransfer<'_> {
    pub async fn send_public_transfer(
        &self,
        from: AccountId,
        to: AccountId,
        balance_to_move: u128,
        from_key_path: Option<&str>,
        to_key_path: Option<&str>,
    ) -> Result<HashType, ExecutionFailureKind> {
        let balance = self
            .0
            .get_account_balance(from)
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        if balance < balance_to_move {
            return Err(ExecutionFailureKind::InsufficientFundsError);
        }

        let account_ids = vec![from, to];
        let program_id = Program::authenticated_transfer_program().id();

        let nonces = self
            .0
            .get_accounts_nonces(account_ids.clone())
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let message = Message::try_new(program_id, account_ids, nonces, balance_to_move)
            .map_err(ExecutionFailureKind::TransactionBuildError)?;

        let witness_set = if let Some(from_key_path) = from_key_path {
            let pin = crate::helperfunctions::read_pin().map_err(|e| {
                ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(
                    e.to_string(),
                ))
            })?;
            let msg_hash = message.hash_message();
            let (from_sig, from_pk) =
                KeycardWallet::sign_message_for_path_with_connect(&pin, from_key_path, &msg_hash)?;
            if let Some(to_key_path) = to_key_path {
                let (to_sig, to_pk) = KeycardWallet::sign_message_for_path_with_connect(
                    &pin,
                    to_key_path,
                    &msg_hash,
                )?;
                WitnessSet::from_list(&message, &[from_sig, to_sig], &[from_pk, to_pk])
                    .map_err(ExecutionFailureKind::TransactionBuildError)?
            } else {
                WitnessSet::from_list(&message, &[from_sig], &[from_pk])
                    .map_err(ExecutionFailureKind::TransactionBuildError)?
            }
        } else {
            self.0.sign_public_message(&message, &message.account_ids)?
        };

        let tx = PublicTransaction::new(message, witness_set);

        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
    }

    pub async fn register_account(
        &self,
        from: AccountId,
        key_path: Option<&str>,
    ) -> Result<HashType, ExecutionFailureKind> {
        let nonces = self
            .0
            .get_accounts_nonces(vec![from])
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let instruction: u128 = 0;
        let account_ids = vec![from];
        let program_id = Program::authenticated_transfer_program().id();
        let message = Message::try_new(program_id, account_ids, nonces, instruction)
            .map_err(ExecutionFailureKind::TransactionBuildError)?;

        let witness_set = if let Some(key_path) = key_path {
            let pin = crate::helperfunctions::read_pin().map_err(|e| {
                ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(
                    e.to_string(),
                ))
            })?;
            let (signature, pub_key) = KeycardWallet::sign_message_for_path_with_connect(
                &pin,
                key_path,
                &message.hash_message(),
            )?;
            WitnessSet::from_list(&message, &[signature], &[pub_key])
                .map_err(ExecutionFailureKind::TransactionBuildError)?
        } else {
            let signing_key = self.0.storage.user_data.get_pub_account_signing_key(from);

            let Some(signing_key) = signing_key else {
                return Err(ExecutionFailureKind::KeyNotFoundError);
            };

            WitnessSet::for_message(&message, &[signing_key])
        };

        let tx = PublicTransaction::new(message, witness_set);

        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
    }
}
