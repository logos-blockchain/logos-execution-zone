use common::HashType;
use lee::{
    AccountId, Actor, privacy_preserving_transaction::circuit::ProgramCatalog, program::Program,
};
use lee_core::{
    SharedSecretKey,
    native_token::{Message, NATIVE_TOKEN_PROGRAM_ID, decode_balance},
};

use crate::{
    AccountIdentity, AccountMention, AsyncDelivery, ClearMessage, ExecutionFailureKind, Promotions,
    SelectedActorState, WalletCore, WalletSequencerClient,
    program_facades::{CreditDelivery, credit_destination},
};

pub struct NativeTokenTransfer<'wallet, C: WalletSequencerClient>(pub &'wallet WalletCore<C>);

impl<C: WalletSequencerClient> NativeTokenTransfer<'_, C> {
    // The sender's native actor is the root and must hold `amount`; its credit to `recipient` is an
    // async message.
    pub async fn transfer(
        &self,
        sender: AccountIdentity,
        recipient: AccountIdentity,
        amount: u128,
        delivery: CreditDelivery,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let to = recipient.account_id();
        let (declared, async_delivery) = credit_destination(
            self.0,
            &sender,
            recipient,
            NATIVE_TOKEN_PROGRAM_ID,
            delivery,
        )?;
        self.send_transfer(sender, declared, to, amount, async_delivery)
            .await
    }

    // A transfer to an address with a recovery binding on chain, its credit published clear.
    pub async fn transfer_clear(
        &self,
        sender: AccountIdentity,
        to: AccountId,
        amount: u128,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let async_delivery = AsyncDelivery {
            clear_messages: vec![ClearMessage {
                sender: Actor::native_balance(sender.account_id()),
                to: Actor::native_balance(to),
                message: Program::serialize_message(Message::Credit(amount))
                    .expect("Message should serialize"),
            }],
            promotions: Promotions {
                listed_only: true,
                ..Promotions::default()
            },
            ..AsyncDelivery::default()
        };
        self.send_transfer(sender, None, to, amount, async_delivery)
            .await
    }

    async fn send_transfer(
        &self,
        sender: AccountIdentity,
        declared: Option<AccountMention>,
        to: AccountId,
        amount: u128,
        async_delivery: AsyncDelivery,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let mut accounts = vec![sender.balance()];
        accounts.extend(declared);
        // TODO: handle large Err-variant properly
        let tx_pre_check = move |accounts: &[SelectedActorState]| {
            let from = &accounts[0];
            let balance =
                decode_balance(from.actor_state_of(NATIVE_TOKEN_PROGRAM_ID)).map_err(|_error| {
                    ExecutionFailureKind::AccountDataError(from.selector.account_id)
                })?;
            if balance >= amount {
                Ok(())
            } else {
                Err(ExecutionFailureKind::InsufficientFundsError)
            }
        };
        self.0
            .send_tx_with_pre_check(
                accounts,
                0,
                Program::serialize_message(Message::Transfer { to, amount })
                    .expect("Message should serialize"),
                &ProgramCatalog::default(),
                None,
                async_delivery,
                None,
                tx_pre_check,
            )
            .await
    }
}
