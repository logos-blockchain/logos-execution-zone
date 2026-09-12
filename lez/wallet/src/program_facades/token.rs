use common::HashType;
use lee::{AccountId, program::Program};
use lee_core::{
    PrivateAccountKind,
    account::{Account, ProgramShardSelector, ShardData},
};
use token_core::{HoldingKind, HoldingTarget, Instruction, TokenHolding};

use crate::{
    AccDecodeData, AccountIdentity, AccountMention, ExecutionFailureKind, WalletCore,
    storage::key_chain::UserKeyChain,
};

pub(crate) struct HoldingOwnerCandidate<'wallet> {
    pub owner_id: AccountId,
    pub identifier: lee_core::Identifier,
    pub key_chain: &'wallet key_protocol::key_management::KeyChain,
}

pub struct Token<'wallet>(pub &'wallet mut WalletCore);

type SentTransaction = (HashType, Vec<AccDecodeData>);

impl Token<'_> {
    fn holding_target(
        &self,
        owner: &AccountIdentity,
    ) -> Result<HoldingTarget, ExecutionFailureKind> {
        if matches!(
            owner,
            AccountIdentity::PrivateShared { .. } | AccountIdentity::PrivatePdaShared { .. }
        ) {
            return Err(ExecutionFailureKind::TransactionBuildError(
                lee::error::LeeError::InvalidInput(
                    "Shared accounts are not supported as token holding owners".to_owned(),
                ),
            ));
        }
        Ok(HoldingTarget {
            owner_id: owner.account_id(),
            account_id_data: self.0.account_id_data(owner)?,
        })
    }

    pub fn holding_id(
        &self,
        owner: &AccountIdentity,
        definition_id: AccountId,
    ) -> Result<AccountId, ExecutionFailureKind> {
        let target = self.holding_target(owner)?;
        Ok(token_core::holding_id(
            &target,
            token_program_id(),
            definition_id,
            HoldingKind::Fungible,
        ))
    }

    pub async fn holding(
        &self,
        owner: &AccountIdentity,
        definition_id: AccountId,
    ) -> Result<Option<TokenHolding>, ExecutionFailureKind> {
        let token_program_id = token_program_id();
        let holding_id = self.holding_id(owner, definition_id)?;
        let decode = |shard: &ShardData| {
            (!shard.is_empty())
                .then(|| TokenHolding::try_from(shard))
                .transpose()
                .map_err(|_err| ExecutionFailureKind::AccountDataError(holding_id))
        };

        if owner.is_public() {
            let account = self
                .0
                .get_account_view(ProgramShardSelector::new(holding_id, token_program_id))
                .await
                .map_err(ExecutionFailureKind::SequencerError)?;
            decode(account.data.shard(token_program_id))
        } else if let Some(account) = self.0.storage.key_chain().private_account(holding_id) {
            decode(account.account.data.shard(token_program_id))
        } else {
            Ok(None)
        }
    }

    fn prepare_holding(
        &mut self,
        owner: &AccountIdentity,
        definition_id: AccountId,
    ) -> Result<(HoldingTarget, AccountMention), ExecutionFailureKind> {
        let token_program_id = token_program_id();
        let target = self.holding_target(owner)?;
        let holding_id = token_core::holding_id(
            &target,
            token_program_id,
            definition_id,
            HoldingKind::Fungible,
        );
        let Some((npk, vpk, identifier)) = target.account_id_data.private_parts() else {
            let mention =
                AccountIdentity::PublicNoSign(holding_id).select_program_shard(token_program_id);
            return Ok((target, mention));
        };
        let kind = PrivateAccountKind::Pda {
            account_id: token_program_id,
            seed: token_core::holding_seed(target.owner_id, definition_id, HoldingKind::Fungible),
            identifier,
        };
        let identity = if matches!(owner, AccountIdentity::PrivateOwned(_)) {
            let key_chain = self.0.storage.key_chain_mut();
            if key_chain.private_account(holding_id).is_none() {
                key_chain
                    .insert_private_account(holding_id, kind, Account::default())
                    .map_err(|_err| ExecutionFailureKind::KeyNotFoundError)?;
            }
            AccountIdentity::PrivateOwned(holding_id)
        } else {
            AccountIdentity::PrivateForeign {
                npk: *npk,
                vpk: vpk.clone(),
                kind,
            }
        };
        Ok((target, identity.select_program_shard(token_program_id)))
    }

    async fn send(
        &self,
        accounts: Vec<AccountMention>,
        instruction: Instruction,
    ) -> Result<SentTransaction, ExecutionFailureKind> {
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");
        if !accounts.iter().any(|mention| mention.identity.is_private()) {
            let tx_hash = self
                .0
                .send_pub_tx(accounts, instruction_data, token_program_id())
                .await?;
            return Ok((tx_hash, vec![]));
        }
        let tracked: Vec<Option<AccountId>> = accounts
            .iter()
            .filter(|mention| mention.identity.is_private())
            .map(|mention| {
                (!matches!(mention.identity, AccountIdentity::PrivateForeign { .. }))
                    .then(|| mention.identity.account_id())
            })
            .collect();
        let (tx_hash, secrets) = self
            .0
            .send_privacy_preserving_tx(accounts, instruction_data, &programs::token().into())
            .await?;
        let decode = secrets
            .into_iter()
            .zip(tracked)
            .filter_map(|(secret, account_id)| Some(AccDecodeData::Decode(secret, account_id?)))
            .collect();
        Ok((tx_hash, decode))
    }

    pub async fn send_new_definition(
        &mut self,
        definition: AccountIdentity,
        holder: AccountIdentity,
        name: String,
        total_supply: u128,
    ) -> Result<SentTransaction, ExecutionFailureKind> {
        let (holder, holding) = self.prepare_holding(&holder, definition.account_id())?;
        self.send(
            vec![definition.select_program_shard(token_program_id()), holding],
            Instruction::NewFungibleDefinition {
                name,
                total_supply,
                holder,
            },
        )
        .await
    }

    pub async fn send_initialize(
        &mut self,
        definition: AccountIdentity,
        holder: AccountIdentity,
    ) -> Result<SentTransaction, ExecutionFailureKind> {
        let (holder, holding) = self.prepare_holding(&holder, definition.account_id())?;
        self.send(
            vec![definition.select_program_shard(token_program_id()), holding],
            Instruction::InitializeAccount { holder },
        )
        .await
    }

    pub async fn send_transfer(
        &mut self,
        sender: AccountIdentity,
        recipient: AccountIdentity,
        definition_id: AccountId,
        amount: u128,
    ) -> Result<SentTransaction, ExecutionFailureKind> {
        let (sender_holder, sender_holding) = self.prepare_holding(&sender, definition_id)?;
        let (recipient_holder, recipient_holding) =
            self.prepare_holding(&recipient, definition_id)?;
        self.send(
            vec![sender_holding, recipient_holding, sender.balance()],
            Instruction::Transfer {
                sender: sender_holder,
                recipient: recipient_holder,
                amount_to_transfer: amount,
            },
        )
        .await
    }

    pub async fn send_burn(
        &mut self,
        definition: AccountIdentity,
        holder: AccountIdentity,
        amount: u128,
    ) -> Result<SentTransaction, ExecutionFailureKind> {
        let token_program_id = token_program_id();
        let (holder_descriptor, holding) =
            self.prepare_holding(&holder, definition.account_id())?;
        let accounts = if definition.account_id() == holder.account_id() {
            vec![holder.select_program_shard(token_program_id), holding]
        } else {
            vec![
                definition.select_program_shard(token_program_id),
                holding,
                holder.balance(),
            ]
        };
        self.send(
            accounts,
            Instruction::Burn {
                holder: holder_descriptor,
                amount_to_burn: amount,
            },
        )
        .await
    }

    pub async fn send_mint(
        &mut self,
        definition: AccountIdentity,
        holder: AccountIdentity,
        amount: u128,
    ) -> Result<SentTransaction, ExecutionFailureKind> {
        let (holder, holding) = self.prepare_holding(&holder, definition.account_id())?;
        self.send(
            vec![definition.select_program_shard(token_program_id()), holding],
            Instruction::Mint {
                holder,
                amount_to_mint: amount,
            },
        )
        .await
    }
}

pub(crate) fn missing_holding_owners(key_chain: &UserKeyChain) -> Vec<HoldingOwnerCandidate<'_>> {
    let token_program_id = token_program_id();
    let derive = |found: &crate::storage::key_chain::FoundPrivateAccount<'_>| {
        AccountId::for_private_account(
            &found.key_chain.nullifier_public_key,
            &found.key_chain.viewing_public_key,
            found.kind,
        )
    };
    let mut registered: std::collections::HashSet<AccountId> = key_chain
        .private_accounts()
        .map(|found| derive(&found))
        .collect();
    let mut candidates = Vec::new();

    for holding in key_chain.private_accounts() {
        let PrivateAccountKind::Pda {
            account_id: authority,
            seed,
            identifier,
        } = holding.kind
        else {
            continue;
        };
        if *authority != token_program_id {
            continue;
        }
        let Ok(token_holding) =
            TokenHolding::try_from(holding.account.data.shard(token_program_id))
        else {
            continue;
        };

        let owner_id = AccountId::for_private_account(
            &holding.key_chain.nullifier_public_key,
            &holding.key_chain.viewing_public_key,
            &PrivateAccountKind::Regular(*identifier),
        );
        if token_core::holding_seed(
            owner_id,
            token_holding.definition_id(),
            token_holding.kind(),
        ) != *seed
        {
            continue;
        }

        if registered.insert(owner_id) {
            candidates.push(HoldingOwnerCandidate {
                owner_id,
                identifier: *identifier,
                key_chain: holding.key_chain,
            });
        }
    }

    candidates
}

fn token_program_id() -> AccountId {
    programs::token().id().into()
}
