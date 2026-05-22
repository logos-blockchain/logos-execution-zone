use std::collections::HashMap;

use ata_core::{compute_ata_seed, get_associated_token_account_id};
use common::HashType;
use nssa::{
    AccountId, privacy_preserving_transaction::circuit::ProgramWithDependencies, program::Program,
};
use nssa_core::SharedSecretKey;

use crate::{
    ExecutionFailureKind, PrivacyPreservingAccount, WalletCore, cli::CliAccountMention,
    signing::SigningGroup,
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

        let mut groups = SigningGroup::new();
        groups
            .add_required(owner_mention, owner_id, self.0)
            .map_err(ExecutionFailureKind::from_anyhow)?;
        self.0
            .send_public_tx(&program, account_ids, instruction, groups)
            .await
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
        let instruction = ata_core::Instruction::Transfer {
            ata_program_id,
            amount,
        };

        let mut groups = SigningGroup::new();
        groups
            .add_required(owner_mention, owner_id, self.0)
            .map_err(ExecutionFailureKind::from_anyhow)?;
        self.0
            .send_public_tx(&program, account_ids, instruction, groups)
            .await
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
        let instruction = ata_core::Instruction::Burn {
            ata_program_id,
            amount,
        };

        let mut groups = SigningGroup::new();
        groups
            .add_required(owner_mention, owner_id, self.0)
            .map_err(ExecutionFailureKind::from_anyhow)?;
        self.0
            .send_public_tx(&program, account_ids, instruction, groups)
            .await
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
            .send_privacy_preserving_tx(
                accounts,
                instruction_data,
                &ata_with_token_dependency(),
                None,
            )
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
            .send_privacy_preserving_tx(
                accounts,
                instruction_data,
                &ata_with_token_dependency(),
                None,
            )
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
            .send_privacy_preserving_tx(
                accounts,
                instruction_data,
                &ata_with_token_dependency(),
                None,
            )
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
