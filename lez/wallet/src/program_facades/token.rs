use common::HashType;
use lee::{AccountId, privacy_preserving_transaction::circuit::ProgramCatalog, program::Program};
use lee_core::{
    Identifier, NullifierPublicKey, PrivateAccountKind, SharedSecretKey,
    encryption::ViewingPublicKey,
};
use token_core::{Delivery, Message, NewTokenDefinition, TokenDescriptor, TokenHolding};

use crate::{
    AccountIdentity, AccountMention, ExecutionFailureKind, WalletCore,
    program_facades::token_holding,
};

pub struct Token<'wallet>(pub &'wallet WalletCore);

impl Token<'_> {
    async fn holding(
        &self,
        holder: &AccountIdentity,
    ) -> Result<TokenHolding, ExecutionFailureKind> {
        token_holding(self.0, holder, programs::token_account_id()).await
    }

    async fn descriptor(
        &self,
        holder: &AccountIdentity,
    ) -> Result<TokenDescriptor, ExecutionFailureKind> {
        let holding = self.holding(holder).await?;
        Ok(TokenDescriptor {
            definition_id: holding.definition_id(),
            kind: holding.kind(),
        })
    }

    fn private(&self, account_id: AccountId) -> Result<AccountIdentity, ExecutionFailureKind> {
        self.0
            .resolve_private_account(account_id)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)
    }

    // `accounts[0]` is the root actor; `message` sees the account list to address its recipient.
    async fn send_public(
        &self,
        accounts: [AccountIdentity; 2],
        message: impl FnOnce(&[AccountMention]) -> Message,
    ) -> Result<HashType, ExecutionFailureKind> {
        let accounts = token_mentions(accounts);
        let message = message(&accounts);
        self.0.send_pub_tx(accounts, 0, serialize(&message)).await
    }

    async fn send_private(
        &self,
        accounts: [AccountIdentity; 2],
        message: impl FnOnce(&[AccountMention]) -> Message,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let accounts = token_mentions(accounts);
        let message = message(&accounts);
        self.0
            .send_privacy_preserving_tx(
                accounts,
                0,
                serialize(&message),
                &ProgramCatalog::from([(programs::token_account_id(), programs::token())]),
            )
            .await
    }

    pub async fn send_new_definition(
        &self,
        definition: AccountIdentity,
        supply: AccountIdentity,
        name: String,
        total_supply: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        self.send_public([definition, supply], new_definition(name, total_supply))
            .await
    }

    pub async fn send_new_definition_private_owned_supply(
        &self,
        definition_account_id: AccountId,
        supply_account_id: AccountId,
        name: String,
        total_supply: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        self.send_private(
            [
                AccountIdentity::Public(definition_account_id),
                self.private(supply_account_id)?,
            ],
            new_definition(name, total_supply),
        )
        .await
        .map(|(resp, secrets)| (resp, only(secrets, "expected supply's secret")))
    }

    pub async fn send_new_definition_private_owned_definiton(
        &self,
        definition_account_id: AccountId,
        supply_account_id: AccountId,
        name: String,
        total_supply: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        self.send_private(
            [
                self.private(definition_account_id)?,
                AccountIdentity::Public(supply_account_id),
            ],
            new_definition(name, total_supply),
        )
        .await
        .map(|(resp, secrets)| (resp, only(secrets, "expected definition's secret")))
    }

    pub async fn send_new_definition_private_owned_definiton_and_supply(
        &self,
        definition_account_id: AccountId,
        supply_account_id: AccountId,
        name: String,
        total_supply: u128,
    ) -> Result<(HashType, [SharedSecretKey; 2]), ExecutionFailureKind> {
        self.send_private(
            [
                self.private(definition_account_id)?,
                self.private(supply_account_id)?,
            ],
            new_definition(name, total_supply),
        )
        .await
        .map(|(resp, secrets)| {
            (
                resp,
                pair(
                    secrets,
                    "expected definition's secret",
                    "expected supply's secret",
                ),
            )
        })
    }

    pub async fn send_transfer_transaction(
        &self,
        sender: AccountIdentity,
        recipient: AccountIdentity,
        amount: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let descriptor = self.descriptor(&sender).await?;
        self.send_public([sender, recipient], transfer(descriptor, amount))
            .await
    }

    pub async fn send_transfer_transaction_private_owned_account(
        &self,
        sender_account_id: AccountId,
        recipient_account_id: AccountId,
        amount: u128,
    ) -> Result<(HashType, [SharedSecretKey; 2]), ExecutionFailureKind> {
        let sender = self.private(sender_account_id)?;
        let descriptor = self.descriptor(&sender).await?;
        self.send_private(
            [sender, self.private(recipient_account_id)?],
            transfer(descriptor, amount),
        )
        .await
        .map(|(resp, secrets)| {
            (
                resp,
                pair(
                    secrets,
                    "expected sender's secret",
                    "expected recipient's secret",
                ),
            )
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
        let sender = self.private(sender_account_id)?;
        let descriptor = self.descriptor(&sender).await?;
        self.send_private(
            [
                sender,
                foreign(recipient_npk, recipient_vpk, recipient_identifier),
            ],
            transfer(descriptor, amount),
        )
        .await
        .map(|(resp, secrets)| {
            (
                resp,
                pair(
                    secrets,
                    "expected sender's secret",
                    "expected recipient's secret",
                ),
            )
        })
    }

    pub async fn send_transfer_transaction_deshielded(
        &self,
        sender_account_id: AccountId,
        recipient_account_id: AccountId,
        amount: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let sender = self.private(sender_account_id)?;
        let descriptor = self.descriptor(&sender).await?;
        self.send_private(
            [sender, AccountIdentity::Public(recipient_account_id)],
            transfer(descriptor, amount),
        )
        .await
        .map(|(resp, secrets)| (resp, only(secrets, "expected sender's secret")))
    }

    pub async fn send_transfer_transaction_shielded_owned_account(
        &self,
        sender: AccountIdentity,
        recipient_account_id: AccountId,
        amount: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let descriptor = self.descriptor(&sender).await?;
        self.send_private(
            [sender, self.private(recipient_account_id)?],
            transfer(descriptor, amount),
        )
        .await
        .map(|(resp, secrets)| (resp, only(secrets, "expected recipient's secret")))
    }

    pub async fn send_transfer_transaction_shielded_foreign_account(
        &self,
        sender: AccountIdentity,
        recipient_npk: NullifierPublicKey,
        recipient_vpk: ViewingPublicKey,
        recipient_identifier: Identifier,
        amount: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let descriptor = self.descriptor(&sender).await?;
        self.send_private(
            [
                sender,
                foreign(recipient_npk, recipient_vpk, recipient_identifier),
            ],
            transfer(descriptor, amount),
        )
        .await
        .map(|(resp, secrets)| (resp, only(secrets, "expected recipient's secret")))
    }

    pub async fn send_cast_transfer(
        &self,
        sender: AccountIdentity,
        recipient: AccountId,
        amount: u128,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let descriptor = self.descriptor(&sender).await?;
        let token_program_id = programs::token_account_id();
        self.0
            .send_tx(
                vec![sender.select_program_shard(token_program_id)],
                0,
                serialize(&Message::Transfer {
                    to: recipient,
                    descriptor,
                    amount,
                    notify: None,
                    delivery: Delivery::Cast,
                }),
                &ProgramCatalog::from([(token_program_id, programs::token())]),
            )
            .await
    }

    pub async fn send_burn_transaction(
        &self,
        definition_account_id: AccountId,
        holder: AccountIdentity,
        amount: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        let descriptor = self.burn_descriptor(definition_account_id, &holder).await?;
        self.send_public(
            [holder, AccountIdentity::PublicNoSign(definition_account_id)],
            burn(descriptor, amount),
        )
        .await
    }

    pub async fn send_burn_transaction_private_owned_account(
        &self,
        definition_account_id: AccountId,
        holder_account_id: AccountId,
        amount: u128,
    ) -> Result<(HashType, [SharedSecretKey; 2]), ExecutionFailureKind> {
        let holder = self.private(holder_account_id)?;
        let descriptor = self.burn_descriptor(definition_account_id, &holder).await?;
        self.send_private(
            [holder, self.private(definition_account_id)?],
            burn(descriptor, amount),
        )
        .await
        .map(|(resp, secrets)| {
            let [holder_secret, definition_secret] = pair(
                secrets,
                "expected holder's secret",
                "expected definition's secret",
            );
            (resp, [definition_secret, holder_secret])
        })
    }

    pub async fn send_burn_transaction_deshielded_owned_account(
        &self,
        definition_account_id: AccountId,
        holder_account_id: AccountId,
        amount: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let holder = AccountIdentity::Public(holder_account_id);
        let descriptor = self.burn_descriptor(definition_account_id, &holder).await?;
        self.send_private(
            [holder, self.private(definition_account_id)?],
            burn(descriptor, amount),
        )
        .await
        .map(|(resp, secrets)| (resp, only(secrets, "expected definition's secret")))
    }

    pub async fn send_burn_transaction_shielded(
        &self,
        definition_account_id: AccountId,
        holder_account_id: AccountId,
        amount: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        let holder = self.private(holder_account_id)?;
        let descriptor = self.burn_descriptor(definition_account_id, &holder).await?;
        self.send_private(
            [holder, AccountIdentity::Public(definition_account_id)],
            burn(descriptor, amount),
        )
        .await
        .map(|(resp, secrets)| (resp, only(secrets, "expected holder's secret")))
    }

    pub async fn send_mint_transaction(
        &self,
        definition: AccountIdentity,
        holder: AccountIdentity,
        amount: u128,
    ) -> Result<HashType, ExecutionFailureKind> {
        self.send_public([definition, holder], mint(amount)).await
    }

    pub async fn send_mint_transaction_private_owned_account(
        &self,
        definition_account_id: AccountId,
        holder_account_id: AccountId,
        amount: u128,
    ) -> Result<(HashType, [SharedSecretKey; 2]), ExecutionFailureKind> {
        self.send_private(
            [
                self.private(definition_account_id)?,
                self.private(holder_account_id)?,
            ],
            mint(amount),
        )
        .await
        .map(|(resp, secrets)| {
            (
                resp,
                pair(
                    secrets,
                    "expected definition's secret",
                    "expected holder's secret",
                ),
            )
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
        self.send_private(
            [
                self.private(definition_account_id)?,
                foreign(holder_npk, holder_vpk, holder_identifier),
            ],
            mint(amount),
        )
        .await
        .map(|(resp, secrets)| {
            (
                resp,
                pair(
                    secrets,
                    "expected definition's secret",
                    "expected holder's secret",
                ),
            )
        })
    }

    pub async fn send_mint_transaction_deshielded(
        &self,
        definition_account_id: AccountId,
        holder_account_id: AccountId,
        amount: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        self.send_private(
            [
                self.private(definition_account_id)?,
                AccountIdentity::Public(holder_account_id),
            ],
            mint(amount),
        )
        .await
        .map(|(resp, secrets)| (resp, only(secrets, "expected definition's secret")))
    }

    pub async fn send_mint_transaction_shielded_owned_account(
        &self,
        definition_account_id: AccountId,
        holder_account_id: AccountId,
        amount: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        self.send_private(
            [
                AccountIdentity::Public(definition_account_id),
                self.private(holder_account_id)?,
            ],
            mint(amount),
        )
        .await
        .map(|(resp, secrets)| (resp, only(secrets, "expected holder's secret")))
    }

    pub async fn send_mint_transaction_shielded_foreign_account(
        &self,
        definition_account_id: AccountId,
        holder_npk: NullifierPublicKey,
        holder_vpk: ViewingPublicKey,
        holder_identifier: Identifier,
        amount: u128,
    ) -> Result<(HashType, SharedSecretKey), ExecutionFailureKind> {
        self.send_private(
            [
                AccountIdentity::Public(definition_account_id),
                foreign(holder_npk, holder_vpk, holder_identifier),
            ],
            mint(amount),
        )
        .await
        .map(|(resp, secrets)| (resp, only(secrets, "expected holder's secret")))
    }

    async fn burn_descriptor(
        &self,
        definition_account_id: AccountId,
        holder: &AccountIdentity,
    ) -> Result<TokenDescriptor, ExecutionFailureKind> {
        Ok(TokenDescriptor {
            definition_id: definition_account_id,
            kind: self.holding(holder).await?.kind(),
        })
    }
}

fn token_mentions(accounts: [AccountIdentity; 2]) -> Vec<AccountMention> {
    let token_program_id = programs::token_account_id();
    accounts
        .into_iter()
        .map(|account| account.select_program_shard(token_program_id))
        .collect()
}

fn serialize(message: &Message) -> Vec<u8> {
    Program::serialize_message(message).expect("Message should serialize")
}

const fn foreign(
    npk: NullifierPublicKey,
    vpk: ViewingPublicKey,
    identifier: Identifier,
) -> AccountIdentity {
    AccountIdentity::PrivateForeign {
        npk,
        vpk,
        kind: PrivateAccountKind::Regular(identifier),
    }
}

fn new_definition(name: String, total_supply: u128) -> impl FnOnce(&[AccountMention]) -> Message {
    move |accounts| Message::NewDefinition {
        definition: NewTokenDefinition::Fungible { name, total_supply },
        holding: accounts[1].identity.account_id(),
        metadata: None,
    }
}

fn transfer(
    descriptor: TokenDescriptor,
    amount: u128,
) -> impl FnOnce(&[AccountMention]) -> Message {
    move |accounts| Message::Transfer {
        to: accounts[1].identity.account_id(),
        descriptor,
        amount,
        notify: None,
        delivery: Delivery::Call,
    }
}

// `accounts` is `[holder, definition]`.
fn burn(descriptor: TokenDescriptor, amount: u128) -> impl FnOnce(&[AccountMention]) -> Message {
    move |accounts| Message::Burn {
        descriptor,
        amount,
        definition: accounts[1].identity.account_id(),
    }
}

fn mint(amount: u128) -> impl FnOnce(&[AccountMention]) -> Message {
    move |accounts| Message::Mint {
        to: accounts[1].identity.account_id(),
        amount,
    }
}

fn only(secrets: Vec<SharedSecretKey>, missing: &str) -> SharedSecretKey {
    secrets.into_iter().next().expect(missing)
}

fn pair(secrets: Vec<SharedSecretKey>, first: &str, second: &str) -> [SharedSecretKey; 2] {
    let mut secrets = secrets.into_iter();
    let first = secrets.next().expect(first);
    let second = secrets.next().expect(second);
    [first, second]
}
