use common::HashType;
use nssa::{AccountId, program::Program};
use nssa_core::{Identifier, NullifierPublicKey, SharedSecretKey, encryption::ViewingPublicKey};
use token_core::Instruction;

use crate::{AccountIdentity, ExecutionFailureKind, WalletCore, cli::CliAccountMention};

pub struct Token<'wallet>(pub &'wallet WalletCore);

impl Token<'_> {
    pub async fn send_new_definition(
        &self,
        definition_account_id: AccountId,
        supply_account_id: AccountId,
        name: String,
        total_supply: u128,
        definition_mention: &CliAccountMention,
        supply_mention: &CliAccountMention,
    ) -> Result<HashType, ExecutionFailureKind> {
        let definition_identity = definition_mention.key_path().map_or(
            AccountIdentity::Public(definition_account_id),
            |key_path| AccountIdentity::PublicKeycard {
                account_id: definition_account_id,
                key_path: key_path.to_owned(),
            },
        );

        let supply_identity = supply_mention.key_path().map_or(
            AccountIdentity::Public(supply_account_id),
            |key_path| AccountIdentity::PublicKeycard {
                account_id: supply_account_id,
                key_path: key_path.to_owned(),
            },
        );

        let program = Program::token();
        let instruction = Instruction::NewFungibleDefinition { name, total_supply };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_pub_tx(
                vec![definition_identity, supply_identity],
                instruction_data,
                &program.into(),
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
                &Program::token().into(),
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
                &Program::token().into(),
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
                &Program::token().into(),
            )
            .await
            .map(|(resp, secrets)| {
                let mut iter = secrets.into_iter();
                let first = iter.next().expect("expected definition's secret");
                let second = iter.next().expect("expected supply's secret");
                (resp, [first, second])
            })
    }

    pub async fn send_transfer_transaction(
        &self,
        sender_account_id: AccountId,
        recipient_account_id: AccountId,
        amount: u128,
        sender_mention: &CliAccountMention,
        recipient_mention: &CliAccountMention,
    ) -> Result<HashType, ExecutionFailureKind> {
        let sender_identity = sender_mention.key_path().map_or(
            AccountIdentity::Public(sender_account_id),
            |key_path| AccountIdentity::PublicKeycard {
                account_id: sender_account_id,
                key_path: key_path.to_owned(),
            },
        );

        let recipient_identity = recipient_mention.key_path().map_or(
            AccountIdentity::Public(recipient_account_id),
            |key_path| AccountIdentity::PublicKeycard {
                account_id: recipient_account_id,
                key_path: key_path.to_owned(),
            },
        );

        let program = Program::token();
        let instruction = Instruction::Transfer {
            amount_to_transfer: amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_pub_tx(
                vec![sender_identity, recipient_identity],
                instruction_data,
                &program.into(),
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
                &Program::token().into(),
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
                    AccountIdentity::PrivateForeign {
                        npk: recipient_npk,
                        vpk: recipient_vpk,
                        identifier: recipient_identifier,
                    },
                ],
                instruction_data,
                &Program::token().into(),
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
                &Program::token().into(),
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
        sender_account_id: AccountId,
        recipient_account_id: AccountId,
        amount: u128,
        sender_mention: &CliAccountMention,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let sender_identity = sender_mention.key_path().map_or(
            AccountIdentity::Public(sender_account_id),
            |key_path| AccountIdentity::PublicKeycard {
                account_id: sender_account_id,
                key_path: key_path.to_owned(),
            },
        );

        let instruction = Instruction::Transfer {
            amount_to_transfer: amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");
        self.0
            .send_privacy_preserving_tx(
                vec![
                    sender_identity,
                    self.0
                        .resolve_private_account(recipient_account_id)
                        .ok_or(ExecutionFailureKind::KeyNotFoundError)?,
                ],
                instruction_data,
                &Program::token().into(),
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
        sender_account_id: AccountId,
        recipient_npk: NullifierPublicKey,
        recipient_vpk: ViewingPublicKey,
        recipient_identifier: Identifier,
        amount: u128,
        sender_mention: &CliAccountMention,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let sender_identity = sender_mention.key_path().map_or(
            AccountIdentity::Public(sender_account_id),
            |key_path| AccountIdentity::PublicKeycard {
                account_id: sender_account_id,
                key_path: key_path.to_owned(),
            },
        );

        let instruction = Instruction::Transfer {
            amount_to_transfer: amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");
        self.0
            .send_privacy_preserving_tx(
                vec![
                    sender_identity,
                    AccountIdentity::PrivateForeign {
                        npk: recipient_npk,
                        vpk: recipient_vpk,
                        identifier: recipient_identifier,
                    },
                ],
                instruction_data,
                &Program::token().into(),
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
        holder_account_id: AccountId,
        amount: u128,
        holder_mention: &CliAccountMention,
    ) -> Result<HashType, ExecutionFailureKind> {
        let holder_identity = holder_mention.key_path().map_or(
            AccountIdentity::Public(holder_account_id),
            |key_path| AccountIdentity::PublicKeycard {
                account_id: holder_account_id,
                key_path: key_path.to_owned(),
            },
        );

        let program = Program::token();
        let instruction = Instruction::Burn {
            amount_to_burn: amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_pub_tx(
                vec![
                    AccountIdentity::PublicNoSign(definition_account_id),
                    holder_identity,
                ],
                instruction_data,
                &program.into(),
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
                &Program::token().into(),
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
                &Program::token().into(),
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
                &Program::token().into(),
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
        definition_account_id: AccountId,
        holder_account_id: AccountId,
        amount: u128,
        definition_mention: &CliAccountMention,
        holder_mention: &CliAccountMention,
    ) -> Result<HashType, ExecutionFailureKind> {
        let definition_identity = definition_mention.key_path().map_or(
            AccountIdentity::Public(definition_account_id),
            |key_path| AccountIdentity::PublicKeycard {
                account_id: definition_account_id,
                key_path: key_path.to_owned(),
            },
        );

        let holder_identity = holder_mention.key_path().map_or(
            AccountIdentity::Public(holder_account_id),
            |key_path| AccountIdentity::PublicKeycard {
                account_id: holder_account_id,
                key_path: key_path.to_owned(),
            },
        );

        let program = Program::token();
        let instruction = Instruction::Mint {
            amount_to_mint: amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_pub_tx(
                vec![definition_identity, holder_identity],
                instruction_data,
                &program.into(),
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
                &Program::token().into(),
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
                &Program::token().into(),
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
                &Program::token().into(),
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
                &Program::token().into(),
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
                &Program::token().into(),
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
