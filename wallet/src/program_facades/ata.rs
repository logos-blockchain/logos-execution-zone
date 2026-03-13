use ata_core::get_associated_token_account_id;
use common::{error::ExecutionFailureKind, rpc_primitives::requests::SendTxResponse};
use nssa::{AccountId, program::Program};

use crate::WalletCore;

pub struct Ata<'w>(pub &'w WalletCore);

impl Ata<'_> {
    pub async fn send_create(
        &self,
        owner_id: AccountId,
        definition_id: AccountId,
    ) -> Result<SendTxResponse, ExecutionFailureKind> {
        let program = Program::ata();
        let ata_program_id = program.id();
        let ata_id = get_associated_token_account_id(&ata_program_id, owner_id, definition_id);

        let account_ids = vec![owner_id, definition_id, ata_id];

        let nonces = self
            .0
            .get_accounts_nonces(vec![owner_id])
            .await
            .map_err(|_| ExecutionFailureKind::SequencerError)?;

        let signing_key = self
            .0
            .storage
            .user_data
            .get_pub_account_signing_key(owner_id)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;

        let instruction = ata_core::Instruction::Create { ata_program_id };

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

        Ok(self.0.sequencer_client.send_tx_public(tx).await?)
    }

    pub async fn send_transfer(
        &self,
        owner_id: AccountId,
        definition_id: AccountId,
        recipient_id: AccountId,
        amount: u128,
    ) -> Result<SendTxResponse, ExecutionFailureKind> {
        let program = Program::ata();
        let ata_program_id = program.id();
        let sender_ata_id =
            get_associated_token_account_id(&ata_program_id, owner_id, definition_id);

        let account_ids = vec![owner_id, sender_ata_id, recipient_id];

        let nonces = self
            .0
            .get_accounts_nonces(vec![owner_id])
            .await
            .map_err(|_| ExecutionFailureKind::SequencerError)?;

        let signing_key = self
            .0
            .storage
            .user_data
            .get_pub_account_signing_key(owner_id)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;

        let instruction = ata_core::Instruction::Transfer {
            ata_program_id,
            amount,
        };

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

        Ok(self.0.sequencer_client.send_tx_public(tx).await?)
    }

    pub async fn send_burn(
        &self,
        owner_id: AccountId,
        definition_id: AccountId,
        amount: u128,
    ) -> Result<SendTxResponse, ExecutionFailureKind> {
        let program = Program::ata();
        let ata_program_id = program.id();
        let holder_ata_id =
            get_associated_token_account_id(&ata_program_id, owner_id, definition_id);

        let account_ids = vec![owner_id, holder_ata_id, definition_id];

        let nonces = self
            .0
            .get_accounts_nonces(vec![owner_id])
            .await
            .map_err(|_| ExecutionFailureKind::SequencerError)?;

        let signing_key = self
            .0
            .storage
            .user_data
            .get_pub_account_signing_key(owner_id)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;

        let instruction = ata_core::Instruction::Burn {
            ata_program_id,
            amount,
        };

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

        Ok(self.0.sequencer_client.send_tx_public(tx).await?)
    }
}
