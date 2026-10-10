use common::HashType;
use lee::{privacy_preserving_transaction::circuit::ProgramCatalog, program::Program};
use lee_core::SharedSecretKey;
use token_core::{Message, NewTokenDefinition, TokenDescriptor, TokenHolding};

use crate::{
    AccountIdentity, AccountMention, CastDelivery, ExecutionFailureKind, WalletCore,
    program_facades::{CreditDelivery, credit_destination, token_holding},
};

pub struct Token<'wallet>(pub &'wallet WalletCore);

impl Token<'_> {
    async fn holding(
        &self,
        holder: &AccountIdentity,
    ) -> Result<TokenHolding, ExecutionFailureKind> {
        token_holding(self.0, holder, programs::token_account_id()).await
    }

    pub async fn create(
        &self,
        definition: AccountIdentity,
        supply: AccountIdentity,
        name: String,
        total_supply: u128,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let holding = supply.account_id();
        self.credit(
            definition,
            supply,
            CreditDelivery::Automatic,
            &Message::NewDefinition {
                definition: NewTokenDefinition::Fungible { name, total_supply },
                holding,
                metadata: None,
            },
        )
        .await
    }

    pub async fn transfer(
        &self,
        sender: AccountIdentity,
        recipient: AccountIdentity,
        amount: u128,
        delivery: CreditDelivery,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let holding = self.holding(&sender).await?;
        let to = recipient.account_id();
        self.credit(
            sender,
            recipient,
            delivery,
            &Message::Transfer {
                to,
                descriptor: TokenDescriptor {
                    definition_id: holding.definition_id(),
                    kind: holding.kind(),
                },
                amount,
                notify: None,
            },
        )
        .await
    }

    pub async fn mint(
        &self,
        definition: AccountIdentity,
        holder: AccountIdentity,
        amount: u128,
        delivery: CreditDelivery,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let to = holder.account_id();
        self.credit(definition, holder, delivery, &Message::Mint { to, amount })
            .await
    }

    // The holder's actor is the root; its burn reduces the definition's supply by a Call, so the
    // definition takes part.
    pub async fn burn(
        &self,
        holder: AccountIdentity,
        definition: AccountIdentity,
        amount: u128,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let token_program_id = programs::token_account_id();
        let definition_id = definition.account_id();
        let kind = self.holding(&holder).await?.kind();
        self.send(
            vec![
                holder.select_program_actor_state(token_program_id),
                definition.select_program_actor_state(token_program_id),
            ],
            &Message::Burn {
                descriptor: TokenDescriptor {
                    definition_id,
                    kind,
                },
                amount,
                definition: definition_id,
            },
            CastDelivery::default(),
        )
        .await
    }

    // `root`'s actor runs `message`, which credits `recipient` by Cast.
    async fn credit(
        &self,
        root: AccountIdentity,
        recipient: AccountIdentity,
        delivery: CreditDelivery,
        message: &Message,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let token_program_id = programs::token_account_id();
        let (declared, casts) =
            credit_destination(self.0, &root, recipient, token_program_id, delivery)?;
        let mut accounts = vec![root.select_program_actor_state(token_program_id)];
        accounts.extend(declared);
        self.send(accounts, message, casts).await
    }

    async fn send(
        &self,
        accounts: Vec<AccountMention>,
        message: &Message,
        casts: CastDelivery,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let token_program_id = programs::token_account_id();
        self.0
            .send_tx(
                accounts,
                0,
                Program::serialize_message(message).expect("Message should serialize"),
                &ProgramCatalog::from([(token_program_id, programs::token())]),
                None,
                casts,
            )
            .await
    }
}
