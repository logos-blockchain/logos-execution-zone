use std::collections::HashMap;

use associated_token_account_core::{compute_ata_seed, get_associated_token_account_id};
use common::HashType;
use lee::{
    AccountId, privacy_preserving_transaction::circuit::ProgramWithDependencies, program::Program,
};
use lee_core::SharedSecretKey;

use crate::{AccountIdentity, ExecutionFailureKind, WalletCore};

pub struct Ata<'wallet>(pub &'wallet WalletCore);

impl Ata<'_> {
    pub async fn send_create(
        &self,
        owner: AccountIdentity,
        definition_id: AccountId,
    ) -> Result<HashType, ExecutionFailureKind> {
        let owner_id = owner
            .public_account_id()
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;

        let ata_program_id: AccountId = programs::ata().id().into();
        let token_program_id: AccountId = programs::token().id().into();
        let ata_id = get_associated_token_account_id(
            &ata_program_id,
            &compute_ata_seed(owner_id, definition_id, token_program_id),
        );
        let instruction = associated_token_account_core::Instruction::Create { token_program_id };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_pub_tx(
                vec![
                    owner.balance_only(),
                    AccountIdentity::PublicNoSign(definition_id)
                        .select_program_shard(token_program_id),
                    AccountIdentity::PublicNoSign(ata_id).select_program_shard(token_program_id),
                ],
                instruction_data,
                ata_program_id,
            )
            .await
    }

    pub async fn send_transfer(
        &self,
        owner: AccountIdentity,
        definition_id: AccountId,
        recipient_id: AccountId,
        amount: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let owner_id = owner
            .public_account_id()
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;

        let ata_program_id: AccountId = programs::ata().id().into();
        let token_program_id: AccountId = programs::token().id().into();
        let sender_ata_id = get_associated_token_account_id(
            &ata_program_id,
            &compute_ata_seed(owner_id, definition_id, token_program_id),
        );
        let instruction = associated_token_account_core::Instruction::Transfer {
            token_program_id,
            amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_pub_tx(
                vec![
                    owner.balance_only(),
                    AccountIdentity::PublicNoSign(sender_ata_id)
                        .select_program_shard(token_program_id),
                    AccountIdentity::PublicNoSign(recipient_id)
                        .select_program_shard(token_program_id),
                ],
                instruction_data,
                ata_program_id,
            )
            .await
    }

    pub async fn send_burn(
        &self,
        owner: AccountIdentity,
        definition_id: AccountId,
        amount: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let owner_id = owner
            .public_account_id()
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;

        let ata_program_id: AccountId = programs::ata().id().into();
        let token_program_id: AccountId = programs::token().id().into();
        let holder_ata_id = get_associated_token_account_id(
            &ata_program_id,
            &compute_ata_seed(owner_id, definition_id, token_program_id),
        );
        let instruction = associated_token_account_core::Instruction::Burn {
            token_program_id,
            amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_pub_tx(
                vec![
                    owner.balance_only(),
                    AccountIdentity::PublicNoSign(holder_ata_id)
                        .select_program_shard(token_program_id),
                    AccountIdentity::PublicNoSign(definition_id)
                        .select_program_shard(token_program_id),
                ],
                instruction_data,
                ata_program_id,
            )
            .await
    }

    pub async fn send_create_private_owner(
        &self,
        owner_id: AccountId,
        definition_id: AccountId,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let ata_program_id: AccountId = programs::ata().id().into();
        let token_program_id: AccountId = programs::token().id().into();
        let ata_id = get_associated_token_account_id(
            &ata_program_id,
            &compute_ata_seed(owner_id, definition_id, token_program_id),
        );

        let instruction = associated_token_account_core::Instruction::Create { token_program_id };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        let accounts = vec![
            self.0
                .resolve_private_account(owner_id)
                .ok_or(ExecutionFailureKind::KeyNotFoundError)?
                .balance_only(),
            AccountIdentity::Public(definition_id).select_program_shard(token_program_id),
            AccountIdentity::Public(ata_id).select_program_shard(token_program_id),
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
        let ata_program_id: AccountId = programs::ata().id().into();
        let token_program_id: AccountId = programs::token().id().into();
        let sender_ata_id = get_associated_token_account_id(
            &ata_program_id,
            &compute_ata_seed(owner_id, definition_id, token_program_id),
        );

        let instruction = associated_token_account_core::Instruction::Transfer {
            token_program_id,
            amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        let accounts = vec![
            self.0
                .resolve_private_account(owner_id)
                .ok_or(ExecutionFailureKind::KeyNotFoundError)?
                .balance_only(),
            AccountIdentity::Public(sender_ata_id).select_program_shard(token_program_id),
            AccountIdentity::Public(recipient_id).select_program_shard(token_program_id),
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
        let ata_program_id: AccountId = programs::ata().id().into();
        let token_program_id: AccountId = programs::token().id().into();
        let holder_ata_id = get_associated_token_account_id(
            &ata_program_id,
            &compute_ata_seed(owner_id, definition_id, token_program_id),
        );

        let instruction = associated_token_account_core::Instruction::Burn {
            token_program_id,
            amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        let accounts = vec![
            self.0
                .resolve_private_account(owner_id)
                .ok_or(ExecutionFailureKind::KeyNotFoundError)?
                .balance_only(),
            AccountIdentity::Public(holder_ata_id).select_program_shard(token_program_id),
            AccountIdentity::Public(definition_id).select_program_shard(token_program_id),
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
    let token = programs::token();
    let mut deps = HashMap::new();
    deps.insert(token.id().into(), token);
    let ata = programs::ata();
    let ata_id = ata.id().into();
    ProgramWithDependencies::new(ata, ata_id, deps)
}
