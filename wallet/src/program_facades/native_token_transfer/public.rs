use authenticated_transfer_core::Instruction as AuthTransferInstruction;
use common::{HashType, transaction::NSSATransaction};
use nssa::{
    AccountId, PublicTransaction,
    program::Program,
    public_transaction::{Message, WitnessSet},
};
use pyo3::exceptions::PyRuntimeError;
use sequencer_service_rpc::RpcClient as _;

use super::NativeTokenTransfer;
use crate::{
    ExecutionFailureKind, cli::CliAccountMention, helperfunctions::read_pin, signing::SigningGroups,
};

impl NativeTokenTransfer<'_> {
    pub async fn send_public_transfer(
        &self,
        from: AccountId,
        to: AccountId,
        balance_to_move: u128,
        from_mention: &CliAccountMention,
        to_mention: &CliAccountMention,
    ) -> Result<HashType, ExecutionFailureKind> {
        let mut groups = SigningGroups::new();
        groups
            .add_sender(from_mention, from, self.0)
            .and_then(|()| groups.add_recipient(to_mention, to, self.0))
            .map_err(|e| {
                ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(
                    e.to_string(),
                ))
            })?;

        let program_id = Program::authenticated_transfer_program().id();
        let nonces = self
            .0
            .get_accounts_nonces(groups.signing_ids())
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let message = Message::try_new(
            program_id,
            vec![from, to],
            nonces,
            AuthTransferInstruction::Transfer {
                amount: balance_to_move,
            },
        )
        .map_err(ExecutionFailureKind::TransactionBuildError)?;

        let pin = if groups.needs_pin() {
            read_pin()
                .map_err(|e| {
                    ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(
                        e.to_string(),
                    ))
                })?
                .as_str()
                .to_owned()
        } else {
            String::new()
        };

        let sigs = groups.sign_all(&message.hash(), &pin).map_err(|e| {
            ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(e.to_string()))
        })?;

        let tx = PublicTransaction::new(message, WitnessSet::from_raw_parts(sigs));
        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
    }

    pub async fn register_account(
        &self,
        from: AccountId,
        account_mention: &CliAccountMention,
    ) -> Result<HashType, ExecutionFailureKind> {
        let nonces = self
            .0
            .get_accounts_nonces(vec![from])
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let account_ids = vec![from];
        let program_id = Program::authenticated_transfer_program().id();
        let message = Message::try_new(
            program_id,
            account_ids,
            nonces,
            AuthTransferInstruction::Initialize,
        )
        .map_err(ExecutionFailureKind::TransactionBuildError)?;

        let mut groups = SigningGroups::new();
        groups
            .add_sender(account_mention, from, self.0)
            .map_err(|e| {
                ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(
                    e.to_string(),
                ))
            })?;

        let pin = if groups.needs_pin() {
            read_pin()
                .map_err(|e| {
                    ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(
                        e.to_string(),
                    ))
                })?
                .as_str()
                .to_owned()
        } else {
            String::new()
        };

        let sigs = groups.sign_all(&message.hash(), &pin).map_err(|e| {
            ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(e.to_string()))
        })?;

        let tx = PublicTransaction::new(message, WitnessSet::from_raw_parts(sigs));
        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
    }
}
