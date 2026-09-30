use std::collections::HashMap;

use associated_token_account_core::{
    AtaContents, compute_ata_seed, get_associated_token_account_id,
};
use common::HashType;
use lee::{
    AccountId, privacy_preserving_transaction::circuit::ProgramWithDependencies, program::Program,
};
use lee_core::SharedSecretKey;
use token_core::{TokenDefinition, TokenDescriptor, TokenKind};

use crate::{
    AccountIdentity, ExecutionFailureKind, WalletCore,
    program_facades::{shard, token_holding},
};

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

        let ata_program_id = programs::ata_account_id();
        let token_program_id = programs::token_account_id();
        let ata_id = get_associated_token_account_id(
            &ata_program_id,
            &compute_ata_seed(owner_id, definition_id, token_program_id),
        );
        let (kind, contents) =
            create_proposal(self.0, definition_id, ata_id, token_program_id).await?;
        let instruction = associated_token_account_core::Instruction::Create {
            token_program_id,
            kind,
            contents,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_pub_tx(
                vec![
                    owner.balance(),
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

        let ata_program_id = programs::ata_account_id();
        let token_program_id = programs::token_account_id();
        let sender_ata_id = get_associated_token_account_id(
            &ata_program_id,
            &compute_ata_seed(owner_id, definition_id, token_program_id),
        );
        let instruction = associated_token_account_core::Instruction::Transfer {
            token_program_id,
            descriptor: TokenDescriptor {
                definition_id,
                kind: holding_kind(self.0, sender_ata_id, token_program_id).await?,
            },
            amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_pub_tx(
                vec![
                    owner.balance(),
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

        let ata_program_id = programs::ata_account_id();
        let token_program_id = programs::token_account_id();
        let holder_ata_id = get_associated_token_account_id(
            &ata_program_id,
            &compute_ata_seed(owner_id, definition_id, token_program_id),
        );
        let instruction = associated_token_account_core::Instruction::Burn {
            token_program_id,
            kind: holding_kind(self.0, holder_ata_id, token_program_id).await?,
            amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_pub_tx(
                vec![
                    owner.balance(),
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
        let ata_program_id = programs::ata_account_id();
        let token_program_id = programs::token_account_id();
        let ata_id = get_associated_token_account_id(
            &ata_program_id,
            &compute_ata_seed(owner_id, definition_id, token_program_id),
        );

        let (kind, contents) =
            create_proposal(self.0, definition_id, ata_id, token_program_id).await?;
        let instruction = associated_token_account_core::Instruction::Create {
            token_program_id,
            kind,
            contents,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        let accounts = vec![
            self.0
                .resolve_private_account(owner_id)
                .ok_or(ExecutionFailureKind::KeyNotFoundError)?
                .balance(),
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
        let ata_program_id = programs::ata_account_id();
        let token_program_id = programs::token_account_id();
        let sender_ata_id = get_associated_token_account_id(
            &ata_program_id,
            &compute_ata_seed(owner_id, definition_id, token_program_id),
        );

        let instruction = associated_token_account_core::Instruction::Transfer {
            token_program_id,
            descriptor: TokenDescriptor {
                definition_id,
                kind: holding_kind(self.0, sender_ata_id, token_program_id).await?,
            },
            amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        let accounts = vec![
            self.0
                .resolve_private_account(owner_id)
                .ok_or(ExecutionFailureKind::KeyNotFoundError)?
                .balance(),
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
        let ata_program_id = programs::ata_account_id();
        let token_program_id = programs::token_account_id();
        let holder_ata_id = get_associated_token_account_id(
            &ata_program_id,
            &compute_ata_seed(owner_id, definition_id, token_program_id),
        );

        let instruction = associated_token_account_core::Instruction::Burn {
            token_program_id,
            kind: holding_kind(self.0, holder_ata_id, token_program_id).await?,
            amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        let accounts = vec![
            self.0
                .resolve_private_account(owner_id)
                .ok_or(ExecutionFailureKind::KeyNotFoundError)?
                .balance(),
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

async fn holding_kind(
    wallet: &WalletCore,
    account_id: AccountId,
    token_program_id: AccountId,
) -> Result<TokenKind, ExecutionFailureKind> {
    Ok(token_holding(
        wallet,
        &AccountIdentity::PublicNoSign(account_id),
        token_program_id,
    )
    .await?
    .kind())
}

async fn create_proposal(
    wallet: &WalletCore,
    definition_id: AccountId,
    ata_id: AccountId,
    token_program_id: AccountId,
) -> Result<(TokenKind, AtaContents), ExecutionFailureKind> {
    let definition_shard = shard(
        wallet,
        &AccountIdentity::PublicNoSign(definition_id),
        token_program_id,
    )
    .await?;
    let definition = TokenDefinition::try_from(&definition_shard)
        .map_err(|_err| ExecutionFailureKind::AccountDataError(definition_id))?;
    let kind = TokenKind::from_definition(&definition);

    let ata_shard = shard(
        wallet,
        &AccountIdentity::PublicNoSign(ata_id),
        token_program_id,
    )
    .await?;
    let contents = associated_token_account_core::classify(
        &ata_shard,
        &TokenDescriptor {
            definition_id,
            kind,
        },
    );

    Ok((kind, contents))
}

fn ata_with_token_dependency() -> ProgramWithDependencies {
    let token = programs::token();
    let mut deps = HashMap::new();
    deps.insert(programs::token_account_id(), token);
    let ata = programs::ata();
    let ata_id = programs::ata_account_id();
    ProgramWithDependencies::new(ata, ata_id, deps)
}
