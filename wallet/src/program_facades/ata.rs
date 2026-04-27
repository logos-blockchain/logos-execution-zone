use std::collections::HashMap;

use ata_core::{compute_ata_seed, get_associated_token_account_id};
use common::{HashType, transaction::NSSATransaction};
use nssa::{
    AccountId, privacy_preserving_transaction::circuit::ProgramWithDependencies, program::Program,
};
use nssa_core::SharedSecretKey;
use sequencer_service_rpc::RpcClient as _;

use crate::{ExecutionFailureKind, PrivacyPreservingAccount, WalletCore};

pub struct Ata<'wallet>(pub &'wallet WalletCore);

impl Ata<'_> {
    pub async fn send_create(
        &self,
        owner_id: AccountId,
        definition_id: AccountId,
    ) -> Result<HashType, ExecutionFailureKind> {
        let program = Program::ata();
        let ata_program_id = program.id();
        let ata_id = get_associated_token_account_id(
            &ata_program_id,
            &compute_ata_seed(owner_id, definition_id),
        );

        let account_ids = vec![owner_id, definition_id, ata_id];

        let nonces = self
            .0
            .get_accounts_nonces(vec![owner_id])
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let Some(signing_key) = self
            .0
            .storage
            .user_data
            .get_pub_account_signing_key(owner_id)
        else {
            return Err(ExecutionFailureKind::KeyNotFoundError);
        };

        let instruction = ata_core::Instruction::Create { ata_program_id };

        let message = nssa::public_transaction::Message::try_new(
            program.id(),
            account_ids,
            nonces,
            instruction,
        )?;

        let witness_set =
            nssa::public_transaction::WitnessSet::for_message(&message, &[signing_key]);

        let tx = nssa::PublicTransaction::new(message, witness_set);

        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
    }

    pub async fn send_transfer(
        &self,
        owner_id: AccountId,
        definition_id: AccountId,
        recipient_id: AccountId,
        amount: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let program = Program::ata();
        let ata_program_id = program.id();
        let sender_ata_id = get_associated_token_account_id(
            &ata_program_id,
            &compute_ata_seed(owner_id, definition_id),
        );

        let account_ids = vec![owner_id, sender_ata_id, recipient_id];

        let nonces = self
            .0
            .get_accounts_nonces(vec![owner_id])
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let Some(signing_key) = self
            .0
            .storage
            .user_data
            .get_pub_account_signing_key(owner_id)
        else {
            return Err(ExecutionFailureKind::KeyNotFoundError);
        };

        let instruction = ata_core::Instruction::Transfer {
            ata_program_id,
            amount,
        };

        let message = nssa::public_transaction::Message::try_new(
            program.id(),
            account_ids,
            nonces,
            instruction,
        )?;

        let witness_set =
            nssa::public_transaction::WitnessSet::for_message(&message, &[signing_key]);

        let tx = nssa::PublicTransaction::new(message, witness_set);

        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
    }

    pub async fn send_burn(
        &self,
        owner_id: AccountId,
        definition_id: AccountId,
        amount: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let program = Program::ata();
        let ata_program_id = program.id();
        let holder_ata_id = get_associated_token_account_id(
            &ata_program_id,
            &compute_ata_seed(owner_id, definition_id),
        );

        let account_ids = vec![owner_id, holder_ata_id, definition_id];

        let nonces = self
            .0
            .get_accounts_nonces(vec![owner_id])
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let Some(signing_key) = self
            .0
            .storage
            .user_data
            .get_pub_account_signing_key(owner_id)
        else {
            return Err(ExecutionFailureKind::KeyNotFoundError);
        };

        let instruction = ata_core::Instruction::Burn {
            ata_program_id,
            amount,
        };

        let message = nssa::public_transaction::Message::try_new(
            program.id(),
            account_ids,
            nonces,
            instruction,
        )?;

        let witness_set =
            nssa::public_transaction::WitnessSet::for_message(&message, &[signing_key]);

        let tx = nssa::PublicTransaction::new(message, witness_set);

        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
    }

    pub async fn send_create_private_owner(
        &self,
        owner_id: AccountId,
        definition_id: AccountId,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let ata_program_id = Program::ata().id();
        let ata_id = get_associated_token_account_id(
            &ata_program_id,
            &compute_ata_seed(owner_id, definition_id),
        );

        let instruction = ata_core::Instruction::Create { ata_program_id };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        let accounts = vec![
            PrivacyPreservingAccount::PrivateOwned(owner_id),
            PrivacyPreservingAccount::Public(definition_id),
            PrivacyPreservingAccount::Public(ata_id),
        ];

        self.0
            .send_privacy_preserving_tx(accounts, instruction_data, &ata_with_token_dependency())
            .await
            .map(|(hash, mut secrets)| {
                let secret = secrets.pop().expect("expected owner's secret");
                (hash, secret)
            })
    }

    pub async fn send_transfer_private_owner(
        &self,
        owner_id: AccountId,
        definition_id: AccountId,
        recipient_id: AccountId,
        amount: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let ata_program_id = Program::ata().id();
        let sender_ata_id = get_associated_token_account_id(
            &ata_program_id,
            &compute_ata_seed(owner_id, definition_id),
        );

        let instruction = ata_core::Instruction::Transfer {
            ata_program_id,
            amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        let accounts = vec![
            PrivacyPreservingAccount::PrivateOwned(owner_id),
            PrivacyPreservingAccount::Public(sender_ata_id),
            PrivacyPreservingAccount::Public(recipient_id),
        ];

        self.0
            .send_privacy_preserving_tx(accounts, instruction_data, &ata_with_token_dependency())
            .await
            .map(|(hash, mut secrets)| {
                let secret = secrets.pop().expect("expected owner's secret");
                (hash, secret)
            })
    }

    pub async fn send_burn_private_owner(
        &self,
        owner_id: AccountId,
        definition_id: AccountId,
        amount: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let ata_program_id = Program::ata().id();
        let holder_ata_id = get_associated_token_account_id(
            &ata_program_id,
            &compute_ata_seed(owner_id, definition_id),
        );

        let instruction = ata_core::Instruction::Burn {
            ata_program_id,
            amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        let accounts = vec![
            PrivacyPreservingAccount::PrivateOwned(owner_id),
            PrivacyPreservingAccount::Public(holder_ata_id),
            PrivacyPreservingAccount::Public(definition_id),
        ];

        self.0
            .send_privacy_preserving_tx(accounts, instruction_data, &ata_with_token_dependency())
            .await
            .map(|(hash, mut secrets)| {
                let secret = secrets.pop().expect("expected owner's secret");
                (hash, secret)
            })
    }
}

fn ata_with_token_dependency() -> ProgramWithDependencies {
    let token = Program::token();
    let mut deps = HashMap::new();
    deps.insert(token.id(), token);
    ProgramWithDependencies::new(Program::ata(), deps)
}
