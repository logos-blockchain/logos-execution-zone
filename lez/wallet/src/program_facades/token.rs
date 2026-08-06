use common::HashType;
use lee::{AccountId, program::Program};
use lee_core::{
    Identifier, NullifierPublicKey, PrivateAccountKind, SharedSecretKey,
    encryption::ViewingPublicKey, program::PdaSeed,
};
use rand::{RngCore as _, rngs::OsRng};
use token_core::{Instruction, TokenHolding};

use crate::{AccountIdentity, ExecutionFailureKind, WalletCore};

pub struct Token<'wallet>(pub &'wallet WalletCore);

impl Token<'_> {
    pub async fn send_new_definition(
        &self,
        definition: AccountIdentity,
        supply: AccountIdentity,
        name: String,
        total_supply: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let instruction = Instruction::NewFungibleDefinition { name, total_supply };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_pub_tx(
                vec![definition, supply],
                instruction_data,
                programs::token().id(),
            )
            .await
    }

    pub async fn send_new_definition_private_owned_supply(
        &self,
        definition_account_id: AccountId,
        supply_account_id: AccountId,
        name: String,
        total_supply: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let instruction = Instruction::NewFungibleDefinition { name, total_supply };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_privacy_preserving_tx(
                vec![
                    AccountIdentity::Public(definition_account_id),
                    self.0
                        .resolve_private_account(supply_account_id)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?,
                ],
                instruction_data,
                &programs::token().into(),
            )
            .await
            .map(|(resp, secrets)| {
                let first = secrets
                    .into_iter()
                    .next()
                    .expect("expected supply's secret");
                (resp, first)
            })
    }

    pub async fn send_new_definition_private_owned_definiton(
        &self,
        definition_account_id: AccountId,
        supply_account_id: AccountId,
        name: String,
        total_supply: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let instruction = Instruction::NewFungibleDefinition { name, total_supply };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_privacy_preserving_tx(
                vec![
                    self.0
                        .resolve_private_account(definition_account_id)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?,
                    AccountIdentity::Public(supply_account_id),
                ],
                instruction_data,
                &programs::token().into(),
            )
            .await
            .map(|(resp, secrets)| {
                let first = secrets
                    .into_iter()
                    .next()
                    .expect("expected definition's secret");
                (resp, first)
            })
    }

    pub async fn send_new_definition_private_owned_definiton_and_supply(
        &self,
        definition_account_id: AccountId,
        supply_account_id: AccountId,
        name: String,
        total_supply: u128,
    ) -> Result<(HashType, [SharedSecretKey; 2]), ExecutionFailureKind> {
        let instruction = Instruction::NewFungibleDefinition { name, total_supply };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_privacy_preserving_tx(
                vec![
                    self.0
                        .resolve_private_account(definition_account_id)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?,
                    self.0
                        .resolve_private_account(supply_account_id)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?,
                ],
                instruction_data,
                &programs::token().into(),
            )
            .await
            .map(|(resp, secrets)| {
                let mut iter = secrets.into_iter();
                let first = iter.next().expect("expected definition's secret");
                let second = iter.next().expect("expected supply's secret");
                (resp, [first, second])
            })
    }

    pub async fn send_initialize_account(
        &self,
        definition: AccountIdentity,
        holding: AccountIdentity,
    ) -> Result<HashType, ExecutionFailureKind> {
        let instruction_data = Program::serialize_instruction(Instruction::InitializeAccount)
            .expect("Instruction should serialize");

        self.0
            .send_pub_tx(
                vec![definition, holding],
                instruction_data,
                programs::token().id(),
            )
            .await
    }

    pub async fn send_transfer_transaction(
        &self,
        sender: AccountIdentity,
        recipient: AccountIdentity,
        amount: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let instruction = Instruction::Transfer {
            amount_to_transfer: amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_pub_tx(
                vec![sender, recipient],
                instruction_data,
                programs::token().id(),
            )
            .await
    }

    pub async fn send_transfer_transaction_private_owned_account(
        &self,
        sender_account_id: AccountId,
        recipient_account_id: AccountId,
        amount: u128,
    ) -> Result<(HashType, [SharedSecretKey; 2]), ExecutionFailureKind> {
        let instruction = Instruction::Transfer {
            amount_to_transfer: amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_privacy_preserving_tx(
                vec![
                    self.0
                        .resolve_private_account(sender_account_id)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?,
                    self.0
                        .resolve_private_account(recipient_account_id)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?,
                ],
                instruction_data,
                &programs::token().into(),
            )
            .await
            .map(|(resp, secrets)| {
                let mut iter = secrets.into_iter();
                let first = iter.next().expect("expected sender's secret");
                let second = iter.next().expect("expected recipient's secret");
                (resp, [first, second])
            })
    }

    pub async fn send_transfer_transaction_private_foreign_account(
        &self,
        sender_account_id: AccountId,
        recipient_npk: NullifierPublicKey,
        recipient_vpk: ViewingPublicKey,
        recipient_identifier: Identifier,
        amount: u128,
    ) -> Result<(HashType, [SharedSecretKey; 2]), ExecutionFailureKind> {
        let (definition_id, sender_seed) = {
            let sender = self
                .0
                .storage()
                .key_chain()
                .private_account(sender_account_id)
                .ok_or(ExecutionFailureKind::KeyNotFoundError)?;
            let definition_id = TokenHolding::try_from(&sender.account.data)
                .map_err(|_err| ExecutionFailureKind::AccountDataError(sender_account_id))?
                .definition_id();
            let sender_seed = match sender.kind {
                PrivateAccountKind::Pda { seed, .. } => Some(*seed),
                PrivateAccountKind::Regular(_) => None,
            };
            (definition_id, sender_seed)
        };

        let mut recipient_seed = [0; 32];
        OsRng.fill_bytes(&mut recipient_seed);
        let recipient_seed = PdaSeed::new(recipient_seed);
        let recipient_id = AccountId::for_private_pda(
            &programs::ata().id(),
            &recipient_seed,
            &recipient_npk,
            &recipient_vpk,
            recipient_identifier,
        );

        let instruction = associated_token_account_core::Instruction::TransferPrivate {
            recipient_seed,
            senders: vec![(sender_seed, amount)],
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_privacy_preserving_tx(
                vec![
                    AccountIdentity::PublicNoSign(definition_id),
                    self.0
                        .resolve_private_account(sender_account_id)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?,
                    AccountIdentity::PrivatePdaForeign {
                        account_id: recipient_id,
                        npk: recipient_npk,
                        vpk: recipient_vpk,
                        identifier: recipient_identifier,
                    },
                ],
                instruction_data,
                &super::ata::ata_with_token_dependency(),
            )
            .await
            .map(|(resp, secrets)| {
                let mut iter = secrets.into_iter();
                let first = iter.next().expect("expected sender's secret");
                let second = iter.next().expect("expected recipient's secret");
                (resp, [first, second])
            })
    }

    pub async fn send_transfer_transaction_deshielded(
        &self,
        sender_account_id: AccountId,
        recipient_account_id: AccountId,
        amount: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let instruction = Instruction::Transfer {
            amount_to_transfer: amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_privacy_preserving_tx(
                vec![
                    self.0
                        .resolve_private_account(sender_account_id)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?,
                    AccountIdentity::Public(recipient_account_id),
                ],
                instruction_data,
                &programs::token().into(),
            )
            .await
            .map(|(resp, secrets)| {
                let first = secrets
                    .into_iter()
                    .next()
                    .expect("expected sender's secret");
                (resp, first)
            })
    }

    pub async fn send_transfer_transaction_shielded_owned_account(
        &self,
        sender: AccountIdentity,
        recipient_account_id: AccountId,
        amount: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let instruction = Instruction::Transfer {
            amount_to_transfer: amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");
        self.0
            .send_privacy_preserving_tx(
                vec![
                    sender,
                    self.0
                        .resolve_private_account(recipient_account_id)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?,
                ],
                instruction_data,
                &programs::token().into(),
            )
            .await
            .map(|(resp, secrets)| {
                let first = secrets
                    .into_iter()
                    .next()
                    .expect("expected recipient's secret");
                (resp, first)
            })
    }

    pub async fn send_transfer_transaction_shielded_foreign_account(
        &self,
        sender: AccountIdentity,
        recipient_npk: NullifierPublicKey,
        recipient_vpk: ViewingPublicKey,
        recipient_identifier: Identifier,
        amount: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let instruction = Instruction::Transfer {
            amount_to_transfer: amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");
        self.0
            .send_privacy_preserving_tx(
                vec![
                    sender,
                    AccountIdentity::PrivateForeign {
                        npk: recipient_npk,
                        vpk: recipient_vpk,
                        identifier: recipient_identifier,
                    },
                ],
                instruction_data,
                &programs::token().into(),
            )
            .await
            .map(|(resp, secrets)| {
                let first = secrets
                    .into_iter()
                    .next()
                    .expect("expected recipient's secret");
                (resp, first)
            })
    }

    pub async fn send_burn_transaction(
        &self,
        definition_account_id: AccountId,
        holder: AccountIdentity,
        amount: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let instruction = Instruction::Burn {
            amount_to_burn: amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_pub_tx(
                vec![AccountIdentity::PublicNoSign(definition_account_id), holder],
                instruction_data,
                programs::token().id(),
            )
            .await
    }

    pub async fn send_burn_transaction_private_owned_account(
        &self,
        definition_account_id: AccountId,
        holder_account_id: AccountId,
        amount: u128,
    ) -> Result<(HashType, [SharedSecretKey; 2]), ExecutionFailureKind> {
        let instruction = Instruction::Burn {
            amount_to_burn: amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_privacy_preserving_tx(
                vec![
                    self.0
                        .resolve_private_account(definition_account_id)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?,
                    self.0
                        .resolve_private_account(holder_account_id)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?,
                ],
                instruction_data,
                &programs::token().into(),
            )
            .await
            .map(|(resp, secrets)| {
                let mut iter = secrets.into_iter();
                let first = iter.next().expect("expected definition's secret");
                let second = iter.next().expect("expected holder's secret");
                (resp, [first, second])
            })
    }

    pub async fn send_burn_transaction_deshielded_owned_account(
        &self,
        definition_account_id: AccountId,
        holder_account_id: AccountId,
        amount: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let instruction = Instruction::Burn {
            amount_to_burn: amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_privacy_preserving_tx(
                vec![
                    self.0
                        .resolve_private_account(definition_account_id)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?,
                    AccountIdentity::Public(holder_account_id),
                ],
                instruction_data,
                &programs::token().into(),
            )
            .await
            .map(|(resp, secrets)| {
                let first = secrets
                    .into_iter()
                    .next()
                    .expect("expected definition's secret");
                (resp, first)
            })
    }

    pub async fn send_burn_transaction_shielded(
        &self,
        definition_account_id: AccountId,
        holder_account_id: AccountId,
        amount: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let instruction = Instruction::Burn {
            amount_to_burn: amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_privacy_preserving_tx(
                vec![
                    AccountIdentity::Public(definition_account_id),
                    self.0
                        .resolve_private_account(holder_account_id)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?,
                ],
                instruction_data,
                &programs::token().into(),
            )
            .await
            .map(|(resp, secrets)| {
                let first = secrets
                    .into_iter()
                    .next()
                    .expect("expected holder's secret");
                (resp, first)
            })
    }

    pub async fn send_mint_transaction(
        &self,
        definition: AccountIdentity,
        holder: AccountIdentity,
        amount: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let instruction = Instruction::Mint {
            amount_to_mint: amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_pub_tx(
                vec![definition, holder],
                instruction_data,
                programs::token().id(),
            )
            .await
    }

    pub async fn send_mint_transaction_private_owned_account(
        &self,
        definition_account_id: AccountId,
        holder_account_id: AccountId,
        amount: u128,
    ) -> Result<(HashType, [SharedSecretKey; 2]), ExecutionFailureKind> {
        let instruction = Instruction::Mint {
            amount_to_mint: amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_privacy_preserving_tx(
                vec![
                    self.0
                        .resolve_private_account(definition_account_id)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?,
                    self.0
                        .resolve_private_account(holder_account_id)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?,
                ],
                instruction_data,
                &programs::token().into(),
            )
            .await
            .map(|(resp, secrets)| {
                let mut iter = secrets.into_iter();
                let first = iter.next().expect("expected definition's secret");
                let second = iter.next().expect("expected holder's secret");
                (resp, [first, second])
            })
    }

    pub async fn send_mint_transaction_private_foreign_account(
        &self,
        definition_account_id: AccountId,
        holder_npk: NullifierPublicKey,
        holder_vpk: ViewingPublicKey,
        holder_identifier: Identifier,
        amount: u128,
    ) -> Result<(HashType, [SharedSecretKey; 2]), ExecutionFailureKind> {
        let instruction = Instruction::Mint {
            amount_to_mint: amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_privacy_preserving_tx(
                vec![
                    self.0
                        .resolve_private_account(definition_account_id)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?,
                    AccountIdentity::PrivateForeign {
                        npk: holder_npk,
                        vpk: holder_vpk,
                        identifier: holder_identifier,
                    },
                ],
                instruction_data,
                &programs::token().into(),
            )
            .await
            .map(|(resp, secrets)| {
                let mut iter = secrets.into_iter();
                let first = iter.next().expect("expected definition's secret");
                let second = iter.next().expect("expected holder's secret");
                (resp, [first, second])
            })
    }

    pub async fn send_mint_transaction_deshielded(
        &self,
        definition_account_id: AccountId,
        holder_account_id: AccountId,
        amount: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let instruction = Instruction::Mint {
            amount_to_mint: amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_privacy_preserving_tx(
                vec![
                    self.0
                        .resolve_private_account(definition_account_id)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?,
                    AccountIdentity::Public(holder_account_id),
                ],
                instruction_data,
                &programs::token().into(),
            )
            .await
            .map(|(resp, secrets)| {
                let first = secrets
                    .into_iter()
                    .next()
                    .expect("expected definition's secret");
                (resp, first)
            })
    }

    pub async fn send_mint_transaction_shielded_owned_account(
        &self,
        definition_account_id: AccountId,
        holder_account_id: AccountId,
        amount: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let instruction = Instruction::Mint {
            amount_to_mint: amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_privacy_preserving_tx(
                vec![
                    AccountIdentity::Public(definition_account_id),
                    self.0
                        .resolve_private_account(holder_account_id)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?,
                ],
                instruction_data,
                &programs::token().into(),
            )
            .await
            .map(|(resp, secrets)| {
                let first = secrets
                    .into_iter()
                    .next()
                    .expect("expected holder's secret");
                (resp, first)
            })
    }

    pub async fn send_mint_transaction_shielded_foreign_account(
        &self,
        definition_account_id: AccountId,
        holder_npk: NullifierPublicKey,
        holder_vpk: ViewingPublicKey,
        holder_identifier: Identifier,
        amount: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let instruction = Instruction::Mint {
            amount_to_mint: amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_privacy_preserving_tx(
                vec![
                    AccountIdentity::Public(definition_account_id),
                    AccountIdentity::PrivateForeign {
                        npk: holder_npk,
                        vpk: holder_vpk,
                        identifier: holder_identifier,
                    },
                ],
                instruction_data,
                &programs::token().into(),
            )
            .await
            .map(|(resp, secrets)| {
                let first = secrets
                    .into_iter()
                    .next()
                    .expect("expected holder's secret");
                (resp, first)
            })
    }
}
