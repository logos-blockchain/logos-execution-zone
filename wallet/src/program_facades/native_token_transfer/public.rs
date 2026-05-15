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
    ExecutionFailureKind,
    cli::CliAccountMention,
    helperfunctions::read_pin,
    signing::KeycardSessionContext,
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
        let balance = self
            .0
            .get_account_balance(from)
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        if balance < balance_to_move {
            return Err(ExecutionFailureKind::InsufficientFundsError);
        }

        let from_signer = from_mention
            .to_signer(self.0)
            .map_err(|e| ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(e.to_string())))?;
        let to_signer = to_mention
            .to_recipient_signer(self.0)
            .map_err(|e| ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(e.to_string())))?;

        let account_ids = vec![from, to];
        let signing_ids: Vec<AccountId> = if to_signer.needs_signature() {
            vec![from, to]
        } else {
            vec![from]
        };

        let program_id = Program::authenticated_transfer_program().id();
        let nonces = self
            .0
            .get_accounts_nonces(signing_ids)
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let message = Message::try_new(
            program_id,
            account_ids,
            nonces,
            AuthTransferInstruction::Transfer { amount: balance_to_move },
        )
        .map_err(ExecutionFailureKind::TransactionBuildError)?;

        let pin = if from_mention.is_keycard() || to_mention.is_keycard() {
            read_pin()
                .map_err(|e| ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(e.to_string())))?
                .as_str()
                .to_owned()
        } else {
            String::new()
        };

        let witness_set = pyo3::Python::with_gil(|py| -> pyo3::PyResult<WitnessSet> {
            let mut ctx = KeycardSessionContext::new(&pin);
            let hash = message.hash();

            let (from_sig, from_pk) = from_signer
                .sign(self.0, &mut ctx, py, &hash)
                .expect("from signer always produces a signature")
                .map_err(|e| pyo3::PyErr::new::<PyRuntimeError, _>(e.to_string()))?;

            let sigs_and_keys = match to_signer
                .sign(self.0, &mut ctx, py, &hash)
                .transpose()
                .map_err(|e| pyo3::PyErr::new::<PyRuntimeError, _>(e.to_string()))?
            {
                Some((to_sig, to_pk)) => vec![(from_sig, from_pk), (to_sig, to_pk)],
                None => vec![(from_sig, from_pk)],
            };

            ctx.close(py);
            Ok(WitnessSet::from_raw_parts(sigs_and_keys))
        })
        .map_err(ExecutionFailureKind::KeycardError)?;

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

        let signer = account_mention
            .to_signer(self.0)
            .map_err(|e| ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(e.to_string())))?;

        let pin = if account_mention.is_keycard() {
            read_pin()
                .map_err(|e| ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(e.to_string())))?
                .as_str()
                .to_owned()
        } else {
            String::new()
        };

        let witness_set = pyo3::Python::with_gil(|py| -> pyo3::PyResult<WitnessSet> {
            let mut ctx = KeycardSessionContext::new(&pin);
            let hash = message.hash();

            let (sig, pk) = signer
                .sign(self.0, &mut ctx, py, &hash)
                .expect("account signer always produces a signature")
                .map_err(|e| pyo3::PyErr::new::<PyRuntimeError, _>(e.to_string()))?;

            ctx.close(py);
            Ok(WitnessSet::from_raw_parts(vec![(sig, pk)]))
        })
        .map_err(ExecutionFailureKind::KeycardError)?;

        let tx = PublicTransaction::new(message, witness_set);
        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
    }
}
