use associated_token_account_core::{Message, ata_of};
use common::HashType;
use lee::{AccountId, privacy_preserving_transaction::circuit::ProgramCatalog, program::Program};
use lee_core::SharedSecretKey;
use token_core::{TokenDefinition, TokenDescriptor, TokenKind};

use crate::{
    AccountIdentity, AccountMention, CastDelivery, ExecutionFailureKind, WalletCore,
    program_facades::{actor_state, token_holding},
};

pub struct Ata<'wallet>(pub &'wallet WalletCore);

// Each ATA operation runs the owner's actor under the ATA program as the root, followed by the
// token actors it reaches.
impl Ata<'_> {
    pub async fn create(
        &self,
        owner: AccountIdentity,
        definition_id: AccountId,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let token_program_id = programs::token_account_id();
        let kind = definition_kind(self.0, definition_id, token_program_id).await?;
        let (owner_mention, ata) = owner_and_ata(owner, definition_id);
        self.send(
            vec![
                owner_mention,
                ata,
                AccountIdentity::PublicNoSign(definition_id)
                    .select_program_actor_state(token_program_id),
            ],
            &Message::Create {
                token_program_id,
                definition_id,
                kind,
            },
        )
        .await
    }

    pub async fn transfer(
        &self,
        owner: AccountIdentity,
        definition_id: AccountId,
        recipient_id: AccountId,
        amount: u128,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let token_program_id = programs::token_account_id();
        let (owner_mention, ata) = owner_and_ata(owner, definition_id);
        let kind = holding_kind(self.0, ata.identity.account_id(), token_program_id).await?;
        self.send(
            vec![
                owner_mention,
                ata,
                AccountIdentity::PublicNoSign(recipient_id)
                    .select_program_actor_state(token_program_id),
            ],
            &Message::Transfer {
                token_program_id,
                to: recipient_id,
                descriptor: TokenDescriptor {
                    definition_id,
                    kind,
                },
                amount,
            },
        )
        .await
    }

    pub async fn burn(
        &self,
        owner: AccountIdentity,
        definition_id: AccountId,
        amount: u128,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let token_program_id = programs::token_account_id();
        let (owner_mention, ata) = owner_and_ata(owner, definition_id);
        let kind = holding_kind(self.0, ata.identity.account_id(), token_program_id).await?;
        self.send(
            vec![
                owner_mention,
                ata,
                AccountIdentity::PublicNoSign(definition_id)
                    .select_program_actor_state(token_program_id),
            ],
            &Message::Burn {
                token_program_id,
                descriptor: TokenDescriptor {
                    definition_id,
                    kind,
                },
                amount,
            },
        )
        .await
    }

    async fn send(
        &self,
        accounts: Vec<AccountMention>,
        message: &Message,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        self.0
            .send_tx(
                accounts,
                0,
                Program::serialize_message(message).expect("Message should serialize"),
                &ProgramCatalog::from([
                    (programs::ata_account_id(), programs::ata()),
                    (programs::token_account_id(), programs::token()),
                ]),
                None,
                CastDelivery::default(),
            )
            .await
    }
}

// The owner's actor under the ATA program and the owner's ATA holding under the token program.
fn owner_and_ata(
    owner: AccountIdentity,
    definition_id: AccountId,
) -> (AccountMention, AccountMention) {
    let token_program_id = programs::token_account_id();
    let (_, seed) = ata_of(
        programs::ata_account_id(),
        owner.account_id(),
        definition_id,
        token_program_id,
    );
    (
        owner.select_program_actor_state(programs::ata_account_id()),
        AccountIdentity::PublicPda {
            program: programs::ata_account_id(),
            seed,
        }
        .select_program_actor_state(token_program_id),
    )
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
