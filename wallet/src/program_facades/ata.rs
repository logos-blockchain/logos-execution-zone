use std::collections::HashMap;

use ata_core::{compute_ata_seed, get_associated_token_account_id};
use common::{HashType, transaction::NSSATransaction};
use nssa::{
    AccountId, privacy_preserving_transaction::circuit::ProgramWithDependencies, program::Program,
    public_transaction::WitnessSet,
};
use nssa_core::SharedSecretKey;
use pyo3::exceptions::PyRuntimeError;
use sequencer_service_rpc::RpcClient as _;

use crate::{
    ExecutionFailureKind, PrivacyPreservingAccount, WalletCore,
    cli::CliAccountMention,
    helperfunctions::read_pin,
    signing::SigningGroups,
};

pub struct Ata<'wallet>(pub &'wallet WalletCore);

impl Ata<'_> {
    pub async fn send_create(
        &self,
        owner_id: AccountId,
        definition_id: AccountId,
        owner_mention: &CliAccountMention,
    ) -> Result<HashType, ExecutionFailureKind> {
        let program = Program::ata();
        let ata_program_id = program.id();
        let ata_id = get_associated_token_account_id(
            &ata_program_id,
            &compute_ata_seed(owner_id, definition_id),
        );

        let account_ids = vec![owner_id, definition_id, ata_id];
        let instruction = ata_core::Instruction::Create { ata_program_id };

        let mut groups = SigningGroups::new();
        groups
            .add_sender(owner_mention, owner_id, self.0)
            .map_err(|e| ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(e.to_string())))?;

        let nonces = self.0.get_accounts_nonces(groups.signing_ids()).await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let message = nssa::public_transaction::Message::try_new(program.id(), account_ids, nonces, instruction)?;

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
        Ok(self.0.sequencer_client.send_transaction(NSSATransaction::Public(tx)).await?)
    }

    pub async fn send_transfer(
        &self,
        owner_id: AccountId,
        definition_id: AccountId,
        recipient_id: AccountId,
        amount: u128,
        owner_mention: &CliAccountMention,
    ) -> Result<HashType, ExecutionFailureKind> {
        let program = Program::ata();
        let ata_program_id = program.id();
        let sender_ata_id = get_associated_token_account_id(
            &ata_program_id,
            &compute_ata_seed(owner_id, definition_id),
        );

        let account_ids = vec![owner_id, sender_ata_id, recipient_id];
        let instruction = ata_core::Instruction::Transfer { ata_program_id, amount };

        let mut groups = SigningGroups::new();
        groups
            .add_sender(owner_mention, owner_id, self.0)
            .map_err(|e| ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(e.to_string())))?;

        let nonces = self.0.get_accounts_nonces(groups.signing_ids()).await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let message = nssa::public_transaction::Message::try_new(program.id(), account_ids, nonces, instruction)?;

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
        Ok(self.0.sequencer_client.send_transaction(NSSATransaction::Public(tx)).await?)
    }

    pub async fn send_burn(
        &self,
        owner_id: AccountId,
        definition_id: AccountId,
        amount: u128,
        owner_mention: &CliAccountMention,
    ) -> Result<HashType, ExecutionFailureKind> {
        let program = Program::ata();
        let ata_program_id = program.id();
        let holder_ata_id = get_associated_token_account_id(
            &ata_program_id,
            &compute_ata_seed(owner_id, definition_id),
        );

        let account_ids = vec![owner_id, holder_ata_id, definition_id];
        let instruction = ata_core::Instruction::Burn { ata_program_id, amount };

        let mut groups = SigningGroups::new();
        groups
            .add_sender(owner_mention, owner_id, self.0)
            .map_err(|e| ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<PyRuntimeError, _>(e.to_string())))?;

        let nonces = self.0.get_accounts_nonces(groups.signing_ids()).await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let message = nssa::public_transaction::Message::try_new(program.id(), account_ids, nonces, instruction)?;

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
        Ok(self.0.sequencer_client.send_transaction(NSSATransaction::Public(tx)).await?)
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
            self.0
                .resolve_private_account(owner_id)
                .ok_or(ExecutionFailureKind::KeyNotFoundError)?,
            PrivacyPreservingAccount::Public(definition_id),
            PrivacyPreservingAccount::Public(ata_id),
        ];

        self.0
            .send_privacy_preserving_tx(accounts, instruction_data, &ata_with_token_dependency(), &None)
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
            self.0
                .resolve_private_account(owner_id)
                .ok_or(ExecutionFailureKind::KeyNotFoundError)?,
            PrivacyPreservingAccount::Public(sender_ata_id),
            PrivacyPreservingAccount::Public(recipient_id),
        ];

        self.0
            .send_privacy_preserving_tx(accounts, instruction_data, &ata_with_token_dependency(), &None)
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
            self.0
                .resolve_private_account(owner_id)
                .ok_or(ExecutionFailureKind::KeyNotFoundError)?,
            PrivacyPreservingAccount::Public(holder_ata_id),
            PrivacyPreservingAccount::Public(definition_id),
        ];

        self.0
            .send_privacy_preserving_tx(accounts, instruction_data, &ata_with_token_dependency(), &None)
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
