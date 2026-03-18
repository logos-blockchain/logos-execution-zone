use common::{error::ExecutionFailureKind, rpc_primitives::requests::SendTxResponse};
use nssa::{
    AccountId, PublicTransaction,
    program::Program,
    public_transaction::{Message, WitnessSet},
};

use super::NativeTokenTransfer;

impl NativeTokenTransfer<'_> {
    pub async fn send_public_transfer(
        &self,
        from: AccountId,
        to: AccountId,
        balance_to_move: u128,
    ) -> Result<SendTxResponse, ExecutionFailureKind> {
        let balance = self
            .0
            .get_account_balance(from)
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        if balance >= balance_to_move {
            let nonces = self
                .0
                .get_accounts_nonces(vec![from])
                .await
                .map_err(ExecutionFailureKind::SequencerError)?;

            let account_ids = vec![from, to];
            let program_id = Program::authenticated_transfer_program().id();
            let message =
                Message::try_new(program_id, account_ids, nonces, balance_to_move).unwrap();

            let signing_key = self.0.storage.user_data.get_pub_account_signing_key(from);

            let Some(signing_key) = signing_key else {
                return Err(ExecutionFailureKind::KeyNotFoundError);
            };

            let witness_set = WitnessSet::for_message(&message, &[signing_key]);

            let tx = PublicTransaction::new(message, witness_set);

            Ok(self.0.sequencer_client.send_tx_public(tx).await?)
        } else {
            Err(ExecutionFailureKind::InsufficientFundsError)
        }
    }

    pub async fn register_account(
        &self,
        from: AccountId,
    ) -> Result<SendTxResponse, ExecutionFailureKind> {
        let nonces = self
            .0
            .get_accounts_nonces(vec![from])
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let instruction: u128 = 0;
        let account_ids = vec![from];
        let program_id = Program::authenticated_transfer_program().id();
        let message = Message::try_new(program_id, account_ids, nonces, instruction).unwrap();

        let signing_key = self.0.storage.user_data.get_pub_account_signing_key(from);

        let Some(signing_key) = signing_key else {
            return Err(ExecutionFailureKind::KeyNotFoundError);
        };

        let witness_set = WitnessSet::for_message(&message, &[signing_key]);

        let tx = PublicTransaction::new(message, witness_set);

        Ok(self.0.sequencer_client.send_tx_public(tx).await?)
    }
}
