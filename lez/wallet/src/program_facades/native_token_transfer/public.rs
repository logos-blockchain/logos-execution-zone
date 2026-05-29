use authenticated_transfer_core::Instruction as AuthTransferInstruction;
use common::{HashType, transaction::LeeTransaction};
use lee::{
    AccountId, PublicTransaction,
    program::Program,
    public_transaction::{Message, WitnessSet},
};
use pyo3::exceptions::PyRuntimeError;
use sequencer_service_rpc::RpcClient as _;

use super::NativeTokenTransfer;
use crate::{
    AccountIdentity, ExecutionFailureKind,
    program_facades::native_token_transfer::auth_transfer_preparation,
};

impl NativeTokenTransfer<'_> {
    pub async fn send_public_transfer(
        &self,
        from: AccountIdentity,
        to: AccountIdentity,
        balance_to_move: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let (instruction_data, program, tx_pre_check) = auth_transfer_preparation(balance_to_move);

        self.0
            .send_pub_tx_with_pre_check(
                vec![from, to],
                instruction_data,
                &program.into(),
                tx_pre_check,
            )
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
            .send_transaction(LeeTransaction::Public(tx))
            .await?)
    }

    pub async fn register_account(
        &self,
        account: AccountIdentity,
    ) -> Result<HashType, ExecutionFailureKind> {
        let program = Program::authenticated_transfer_program();
        let instruction_data = Program::serialize_instruction(AuthTransferInstruction::Initialize)?;

        self.0
            .send_pub_tx(vec![account], instruction_data, &program.into())
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
            .send_transaction(LeeTransaction::Public(tx))
            .await?)
    }
}
