use associated_token_account_core::{Message, ata_of};
use common::HashType;
use lee::{AccountId, privacy_preserving_transaction::circuit::ProgramCatalog, program::Program};
use lee_core::SharedSecretKey;
use token_core::{TokenDefinition, TokenDescriptor, TokenKind};

use crate::{
    AccountIdentity, AccountMention, ExecutionFailureKind, WalletCore,
    program_facades::{actor_state, token_holding},
};

pub struct Ata<'wallet>(pub &'wallet WalletCore);

// One ATA operation: the owner's actor under the ATA program is the root, followed by the token
// actors it reaches.
struct AtaCall {
    accounts: Vec<AccountMention>,
    message: Vec<u8>,
}

impl Ata<'_> {
    pub async fn send_create(
        &self,
        owner: AccountIdentity,
        definition_id: AccountId,
    ) -> Result<HashType, ExecutionFailureKind> {
        let call = self.create(owner, definition_id).await?;
        self.0.send_pub_tx(call.accounts, 0, call.message).await
    }

    pub async fn send_transfer(
        &self,
        owner: AccountIdentity,
        definition_id: AccountId,
        recipient_id: AccountId,
        amount: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let call = self
            .transfer(owner, definition_id, recipient_id, amount)
            .await?;
        self.0.send_pub_tx(call.accounts, 0, call.message).await
    }

    pub async fn send_burn(
        &self,
        owner: AccountIdentity,
        definition_id: AccountId,
        amount: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let call = self.burn(owner, definition_id, amount).await?;
        self.0.send_pub_tx(call.accounts, 0, call.message).await
    }

    pub async fn send_create_private_owner(
        &self,
        owner_id: AccountId,
        definition_id: AccountId,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let owner = self.private_owner(owner_id)?;
        self.send_private(self.create(owner, definition_id).await?)
            .await
    }

    pub async fn send_transfer_private_owner(
        &self,
        owner_id: AccountId,
        definition_id: AccountId,
        recipient_id: AccountId,
        amount: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let owner = self.private_owner(owner_id)?;
        self.send_private(
            self.transfer(owner, definition_id, recipient_id, amount)
                .await?,
        )
        .await
    }

    pub async fn send_burn_private_owner(
        &self,
        owner_id: AccountId,
        definition_id: AccountId,
        amount: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let owner = self.private_owner(owner_id)?;
        self.send_private(self.burn(owner, definition_id, amount).await?)
            .await
    }

    fn private_owner(&self, owner_id: AccountId) -> Result<AccountIdentity, ExecutionFailureKind> {
        self.0
            .resolve_private_account(owner_id)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)
    }

    async fn send_private(
        &self,
        call: AtaCall,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        self.0
            .send_privacy_preserving_tx(
                call.accounts,
                0,
                call.message,
                &ata_with_token_dependency(),
            )
            .await
            .map(|(hash, mut secrets)| {
                let secret = secrets.pop().expect("expected owner's secret");
                (hash, secret)
            })
    }

    async fn create(
        &self,
        owner: AccountIdentity,
        definition_id: AccountId,
    ) -> Result<AtaCall, ExecutionFailureKind> {
        let token_program_id = programs::token_account_id();
        let kind = definition_kind(self.0, definition_id, token_program_id).await?;
        let (owner_mention, ata) = owner_and_ata(owner, definition_id);
        Ok(AtaCall {
            accounts: vec![
                owner_mention,
                ata,
                AccountIdentity::PublicNoSign(definition_id)
                    .select_program_actor_state(token_program_id),
            ],
            message: serialize(&Message::Create {
                token_program_id,
                definition_id,
                kind,
            }),
        })
    }

    async fn transfer(
        &self,
        owner: AccountIdentity,
        definition_id: AccountId,
        recipient_id: AccountId,
        amount: u128,
    ) -> Result<AtaCall, ExecutionFailureKind> {
        let token_program_id = programs::token_account_id();
        let (owner_mention, ata) = owner_and_ata(owner, definition_id);
        let kind = holding_kind(self.0, ata.identity.account_id(), token_program_id).await?;
        let recipient = AccountIdentity::PublicNoSign(recipient_id)
            .select_program_actor_state(token_program_id);
        let accounts = vec![owner_mention, ata, recipient];
        let descriptor = TokenDescriptor {
            definition_id,
            kind,
        };
        let message = serialize(&Message::Transfer {
            token_program_id,
            to: recipient_id,
            descriptor,
            amount,
        });
        Ok(AtaCall { accounts, message })
    }

    async fn burn(
        &self,
        owner: AccountIdentity,
        definition_id: AccountId,
        amount: u128,
    ) -> Result<AtaCall, ExecutionFailureKind> {
        let token_program_id = programs::token_account_id();
        let (owner_mention, ata) = owner_and_ata(owner, definition_id);
        let kind = holding_kind(self.0, ata.identity.account_id(), token_program_id).await?;
        let descriptor = TokenDescriptor {
            definition_id,
            kind,
        };
        let accounts = vec![
            owner_mention,
            ata,
            AccountIdentity::PublicNoSign(definition_id)
                .select_program_actor_state(token_program_id),
        ];
        Ok(AtaCall {
            accounts,
            message: serialize(&Message::Burn {
                token_program_id,
                descriptor,
                amount,
            }),
        })
    }
}

// The owner's actor under the ATA program and the owner's ATA holding under the token program.
fn owner_and_ata(
    owner: AccountIdentity,
    definition_id: AccountId,
) -> (AccountMention, AccountMention) {
    let token_program_id = programs::token_account_id();
    let (ata_id, _) = ata_of(
        programs::ata_account_id(),
        owner.account_id(),
        definition_id,
        token_program_id,
    );
    (
        owner.select_program_actor_state(programs::ata_account_id()),
        AccountIdentity::PublicNoSign(ata_id).select_program_actor_state(token_program_id),
    )
}

fn serialize(message: &Message) -> Vec<u8> {
    Program::serialize_message(message).expect("Message should serialize")
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

async fn definition_kind(
    wallet: &WalletCore,
    definition_id: AccountId,
    token_program_id: AccountId,
) -> Result<TokenKind, ExecutionFailureKind> {
    let definition_actor_state = actor_state(
        wallet,
        &AccountIdentity::PublicNoSign(definition_id),
        token_program_id,
    )
    .await?;
    let definition = TokenDefinition::try_from(&definition_actor_state)
        .map_err(|_err| ExecutionFailureKind::AccountDataError(definition_id))?;
    Ok(TokenKind::from_definition(&definition))
}

fn ata_with_token_dependency() -> ProgramCatalog {
    ProgramCatalog::from([
        (programs::ata_account_id(), programs::ata()),
        (programs::token_account_id(), programs::token()),
    ])
}
