use std::collections::HashMap;

use ata_core::{compute_ata_seed, get_associated_token_account_id};
use common::HashType;
use nssa::{
    AccountId, privacy_preserving_transaction::circuit::ProgramWithDependencies, program::Program,
};
use nssa_core::SharedSecretKey;

use crate::{AccountIdentity, ExecutionFailureKind, WalletCore, cli::CliAccountMention};

pub struct Ata<'wallet>(pub &'wallet WalletCore);

impl Ata<'_> {
    pub async fn send_create(
        &self,
        owner_id: AccountId,
        definition_id: AccountId,
        _owner_mention: &CliAccountMention,
    ) -> Result<HashType, ExecutionFailureKind> {
        let program = Program::ata();
        let ata_program_id = program.id();
        let ata_id = get_associated_token_account_id(
            &ata_program_id,
            &compute_ata_seed(owner_id, definition_id),
        );
        let instruction = ata_core::Instruction::Create { ata_program_id };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_pub_tx(
                vec![
                    AccountIdentity::Public(owner_id),
                    AccountIdentity::PublicNoSign(definition_id),
                    AccountIdentity::PublicNoSign(ata_id),
                ],
                instruction_data,
                &program.into(),
            )
            .await
    }

    pub async fn send_transfer(
        &self,
        owner_id: AccountId,
        definition_id: AccountId,
        recipient_id: AccountId,
        amount: u128,
        _owner_mention: &CliAccountMention,
    ) -> Result<HashType, ExecutionFailureKind> {
        let program = Program::ata();
        let ata_program_id = program.id();
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

        self.0
            .send_pub_tx(
                vec![
                    AccountIdentity::Public(owner_id),
                    AccountIdentity::PublicNoSign(sender_ata_id),
                    AccountIdentity::PublicNoSign(recipient_id),
                ],
                instruction_data,
                &program.into(),
            )
            .await
    }

    pub async fn send_burn(
        &self,
        owner_id: AccountId,
        definition_id: AccountId,
        amount: u128,
        _owner_mention: &CliAccountMention,
    ) -> Result<HashType, ExecutionFailureKind> {
        let program = Program::ata();
        let ata_program_id = program.id();
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

        self.0
            .send_pub_tx(
                vec![
                    AccountIdentity::Public(owner_id),
                    AccountIdentity::PublicNoSign(holder_ata_id),
                    AccountIdentity::PublicNoSign(definition_id),
                ],
                instruction_data,
                &program.into(),
            )
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
            AccountIdentity::Public(definition_id),
            AccountIdentity::Public(ata_id),
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
            AccountIdentity::Public(sender_ata_id),
            AccountIdentity::Public(recipient_id),
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
            AccountIdentity::Public(holder_ata_id),
            AccountIdentity::Public(definition_id),
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
