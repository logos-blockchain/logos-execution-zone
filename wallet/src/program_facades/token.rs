use common::{HashType, transaction::NSSATransaction};
use nssa::{AccountId, program::Program};
use nssa_core::{NullifierPublicKey, SharedSecretKey, encryption::ViewingPublicKey};
use sequencer_service_rpc::RpcClient as _;
use token_core::Instruction;

use crate::{ExecutionFailureKind, PrivacyPreservingAccount, WalletCore};

pub struct Token<'wallet>(pub &'wallet WalletCore);

impl Token<'_> {
    pub async fn send_new_definition(
        &self,
        definition_account_id: AccountId,
        supply_account_id: AccountId,
        name: String,
        total_supply: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let account_ids = vec![definition_account_id, supply_account_id];
        let program_id = nssa::program::Program::token().id();
        let instruction = Instruction::NewFungibleDefinition { name, total_supply };
        let nonces = self
            .0
            .get_accounts_nonces(account_ids.clone())
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;
        let message = nssa::public_transaction::Message::try_new(
            program_id,
            account_ids,
            nonces,
            instruction,
        )
        .unwrap();

        let def_private_key = self
            .0
            .storage
            .user_data
            .get_pub_account_signing_key(definition_account_id)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;
        let supply_private_key = self
            .0
            .storage
            .user_data
            .get_pub_account_signing_key(supply_account_id)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;

        let witness_set = nssa::public_transaction::WitnessSet::for_message(
            &message,
            &[def_private_key, supply_private_key],
        );

        let tx = nssa::PublicTransaction::new(message, witness_set);

        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
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
                    PrivacyPreservingAccount::Public(definition_account_id),
                    PrivacyPreservingAccount::PrivateOwned(supply_account_id),
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
                    PrivacyPreservingAccount::PrivateOwned(definition_account_id),
                    PrivacyPreservingAccount::Public(supply_account_id),
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
                    PrivacyPreservingAccount::PrivateOwned(definition_account_id),
                    PrivacyPreservingAccount::PrivateOwned(supply_account_id),
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
    ) -> Result<HashType, ExecutionFailureKind> {
        let account_ids = vec![sender_account_id, recipient_account_id];
        let program_id = nssa::program::Program::token().id();
        let instruction = Instruction::Transfer {
            amount_to_transfer: amount,
        };
        let mut nonces = self
            .0
            .get_accounts_nonces(vec![sender_account_id])
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let mut private_keys = Vec::new();
        let sender_sk = self
            .0
            .storage
            .user_data
            .get_pub_account_signing_key(sender_account_id)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;
        private_keys.push(sender_sk);

        if let Some(recipient_sk) = self
            .0
            .storage
            .user_data
            .get_pub_account_signing_key(recipient_account_id)
        {
            private_keys.push(recipient_sk);
            let recipient_nonces = self
                .0
                .get_accounts_nonces(vec![recipient_account_id])
                .await
                .map_err(ExecutionFailureKind::SequencerError)?;
            nonces.extend(recipient_nonces);
        } else {
            println!(
                "Receiver's account ({recipient_account_id}) private key not found in wallet. Proceeding with only sender's key."
            );
        }

        let message = nssa::public_transaction::Message::try_new(
            program_id,
            account_ids,
            nonces,
            instruction,
        )
        .unwrap();
        let witness_set =
            nssa::public_transaction::WitnessSet::for_message(&message, &private_keys);

        let tx = nssa::PublicTransaction::new(message, witness_set);

        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
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
                    PrivacyPreservingAccount::PrivateOwned(sender_account_id),
                    PrivacyPreservingAccount::PrivateOwned(recipient_account_id),
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
                    PrivacyPreservingAccount::PrivateOwned(sender_account_id),
                    PrivacyPreservingAccount::PrivateForeign {
                        npk: recipient_npk,
                        vpk: recipient_vpk,
                        identifier: 0,
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
                    PrivacyPreservingAccount::PrivateOwned(sender_account_id),
                    PrivacyPreservingAccount::Public(recipient_account_id),
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
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let instruction = Instruction::Transfer {
            amount_to_transfer: amount,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_privacy_preserving_tx(
                vec![
                    PrivacyPreservingAccount::Public(sender_account_id),
                    PrivacyPreservingAccount::PrivateOwned(recipient_account_id),
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
                    PrivacyPreservingAccount::Public(sender_account_id),
                    PrivacyPreservingAccount::PrivateForeign {
                        npk: recipient_npk,
                        vpk: recipient_vpk,
                        identifier: 0,
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
    ) -> Result<HashType, ExecutionFailureKind> {
        let account_ids = vec![definition_account_id, holder_account_id];
        let instruction = Instruction::Burn {
            amount_to_burn: amount,
        };

        let nonces = self
            .0
            .get_accounts_nonces(vec![holder_account_id])
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;
        let message = nssa::public_transaction::Message::try_new(
            Program::token().id(),
            account_ids,
            nonces,
            instruction,
        )
        .expect("Instruction should serialize");

        let signing_key = self
            .0
            .storage
            .user_data
            .get_pub_account_signing_key(holder_account_id)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;
        let witness_set =
            nssa::public_transaction::WitnessSet::for_message(&message, &[signing_key]);

        let tx = nssa::PublicTransaction::new(message, witness_set);

        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
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
                    PrivacyPreservingAccount::PrivateOwned(definition_account_id),
                    PrivacyPreservingAccount::PrivateOwned(holder_account_id),
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
                    PrivacyPreservingAccount::PrivateOwned(definition_account_id),
                    PrivacyPreservingAccount::Public(holder_account_id),
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
                    PrivacyPreservingAccount::Public(definition_account_id),
                    PrivacyPreservingAccount::PrivateOwned(holder_account_id),
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
    ) -> Result<HashType, ExecutionFailureKind> {
        let account_ids = vec![definition_account_id, holder_account_id];
        let instruction = Instruction::Mint {
            amount_to_mint: amount,
        };

        let mut nonces = self
            .0
            .get_accounts_nonces(vec![definition_account_id])
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let mut private_keys = Vec::new();
        let definition_sk = self
            .0
            .storage
            .user_data
            .get_pub_account_signing_key(definition_account_id)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;
        private_keys.push(definition_sk);

        if let Some(holder_sk) = self
            .0
            .storage
            .user_data
            .get_pub_account_signing_key(holder_account_id)
        {
            private_keys.push(holder_sk);
            let recipient_nonces = self
                .0
                .get_accounts_nonces(vec![holder_account_id])
                .await
                .map_err(ExecutionFailureKind::SequencerError)?;
            nonces.extend(recipient_nonces);
        } else {
            println!(
                "Holder's account ({holder_account_id}) private key not found in wallet. Proceeding with only definition's key."
            );
        }

        let message = nssa::public_transaction::Message::try_new(
            Program::token().id(),
            account_ids,
            nonces,
            instruction,
        )
        .unwrap();
        let witness_set =
            nssa::public_transaction::WitnessSet::for_message(&message, &private_keys);

        let tx = nssa::PublicTransaction::new(message, witness_set);

        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
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
                    PrivacyPreservingAccount::PrivateOwned(definition_account_id),
                    PrivacyPreservingAccount::PrivateOwned(holder_account_id),
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
                    PrivacyPreservingAccount::PrivateOwned(definition_account_id),
                    PrivacyPreservingAccount::PrivateForeign {
                        npk: holder_npk,
                        vpk: holder_vpk,
                        identifier: 0,
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
                    PrivacyPreservingAccount::PrivateOwned(definition_account_id),
                    PrivacyPreservingAccount::Public(holder_account_id),
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
                    PrivacyPreservingAccount::Public(definition_account_id),
                    PrivacyPreservingAccount::PrivateOwned(holder_account_id),
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
                    PrivacyPreservingAccount::Public(definition_account_id),
                    PrivacyPreservingAccount::PrivateForeign {
                        npk: holder_npk,
                        vpk: holder_vpk,
                        identifier: 0,
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
