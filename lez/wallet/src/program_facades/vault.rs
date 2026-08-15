use std::collections::HashMap;

use common::HashType;
use lee::{
    AccountId, privacy_preserving_transaction::circuit::ProgramWithDependencies, program::Program,
};
use lee_core::SharedSecretKey;

use crate::{AccountIdentity, ExecutionFailureKind, WalletCore};

pub struct Vault<'wallet>(pub &'wallet WalletCore);

impl Vault<'_> {
    pub async fn send_transfer(
        &self,
        sender_id: AccountId,
        recipient_id: AccountId,
        amount: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let vault_program_id = programs::vault().id();
        let recipient_vault_id =
            vault_core::compute_vault_account_id(vault_program_id, recipient_id);

        let instruction = vault_core::Instruction::Transfer {
            recipient_id,
            amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_pub_tx(
                vec![
                    AccountIdentity::Public(sender_id),
                    AccountIdentity::PublicNoSign(recipient_vault_id),
                ],
                instruction_data,
                vault_program_id,
            )
            .await
    }

    pub async fn send_transfer_private_sender(
        &self,
        sender_id: AccountId,
        recipient_id: AccountId,
        amount: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let vault_program_id = programs::vault().id();
        let recipient_vault_id =
            vault_core::compute_vault_account_id(vault_program_id, recipient_id);
        let instruction = vault_core::Instruction::Transfer {
            recipient_id,
            amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_privacy_preserving_tx(
                vec![
                    self.0
                        .resolve_private_account(sender_id)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?,
                    AccountIdentity::Public(recipient_vault_id),
                ],
                instruction_data,
                &vault_with_auth_dependency(),
            )
            .await
            .map(|(hash, mut secrets)| {
                let secret = secrets.pop().expect("expected sender's secret");
                (hash, secret)
            })
    }

    pub async fn send_claim(
        &self,
        owner_id: AccountId,
        amount: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let vault_program_id = programs::vault().id();
        let owner_vault_id = vault_core::compute_vault_account_id(vault_program_id, owner_id);

        let instruction = vault_core::Instruction::Claim { amount };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_pub_tx(
                vec![
                    AccountIdentity::Public(owner_id),
                    AccountIdentity::PublicNoSign(owner_vault_id),
                ],
                instruction_data,
                vault_program_id,
            )
            .await
    }

    pub async fn send_claim_private_owner(
        &self,
        owner_id: AccountId,
        amount: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let vault_program_id = programs::vault().id();
        let owner_vault_id = vault_core::compute_vault_account_id(vault_program_id, owner_id);

        let instruction = vault_core::Instruction::Claim { amount };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_privacy_preserving_tx(
                vec![
                    self.0
                        .resolve_private_account(owner_id)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?,
                    AccountIdentity::Public(owner_vault_id),
                ],
                instruction_data,
                &vault_with_auth_dependency(),
            )
            .await
            .map(|(hash, mut secrets)| {
                let secret = secrets.pop().expect("expected owner's secret");
                (hash, secret)
            })
    }
}

fn vault_with_auth_dependency() -> ProgramWithDependencies {
    let auth_transfer = programs::authenticated_transfer();
    let mut deps = HashMap::new();
    deps.insert(auth_transfer.id().into(), auth_transfer);
    ProgramWithDependencies::new(programs::vault(), deps)
}
