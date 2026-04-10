use authenticated_transfer_core::Instruction as AuthTransferInstruction;
use common::{HashType, transaction::NSSATransaction};
use nssa::{
    AccountId, PublicTransaction,
    program::Program,
    public_transaction::{Message, WitnessSet},
};
use sequencer_service_rpc::RpcClient as _;

use super::NativeTokenTransfer;
use crate::ExecutionFailureKind;

impl NativeTokenTransfer<'_> {
    pub async fn send_public_transfer(
        &self,
        from: AccountId,
        to: AccountId,
        balance_to_move: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let balance = self
            .0
            .get_account_balance(from)
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        if balance >= balance_to_move {
            let account_ids = vec![from, to];
            let program_id = Program::authenticated_transfer_program().id();

            let mut nonces = self
                .0
                .get_accounts_nonces(vec![from])
                .await
                .map_err(ExecutionFailureKind::SequencerError)?;

            let mut private_keys = Vec::new();
            let from_signing_key = self.0.storage.key_chain().pub_account_signing_key(from);
            let Some(from_signing_key) = from_signing_key else {
                return Err(ExecutionFailureKind::KeyNotFoundError);
            };
            private_keys.push(from_signing_key);

            let to_signing_key = self.0.storage.key_chain().pub_account_signing_key(to);
            if let Some(to_signing_key) = to_signing_key {
                private_keys.push(to_signing_key);
                let to_nonces = self
                    .0
                    .get_accounts_nonces(vec![to])
                    .await
                    .map_err(ExecutionFailureKind::SequencerError)?;
                nonces.extend(to_nonces);
            } else {
                println!(
                    "Receiver's account ({to}) private key not found in wallet. Proceeding with only sender's key."
                );
            }

            let message = Message::try_new(
                program_id,
                account_ids,
                nonces,
                AuthTransferInstruction::Transfer {
                    amount: balance_to_move,
                },
            )
            .unwrap();
            let witness_set = WitnessSet::for_message(&message, &private_keys);

            let tx = PublicTransaction::new(message, witness_set);

            Ok(self
                .0
                .sequencer_client
                .send_transaction(NSSATransaction::Public(tx))
                .await?)
        } else {
            Err(ExecutionFailureKind::InsufficientFundsError)
        }
    }

    pub async fn register_account(
        &self,
        from: AccountId,
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
        .unwrap();

        let signing_key = self.0.storage.key_chain().pub_account_signing_key(from);

        let Some(signing_key) = signing_key else {
            return Err(ExecutionFailureKind::KeyNotFoundError);
        };

        let witness_set = WitnessSet::for_message(&message, &[signing_key]);

        let tx = PublicTransaction::new(message, witness_set);

        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
    }
}
