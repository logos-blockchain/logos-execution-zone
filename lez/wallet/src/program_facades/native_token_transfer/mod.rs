use common::HashType;
use lee::{privacy_preserving_transaction::circuit::ProgramCatalog, program::Program};
use lee_core::{
    SharedSecretKey,
    native_token::{Message, NATIVE_TOKEN_PROGRAM_ID, decode_balance},
};

use crate::{
    AccountIdentity, ExecutionFailureKind, SelectedActorState, WalletCore,
    program_facades::{CreditDelivery, credit_destination},
};

pub struct NativeTokenTransfer<'wallet>(pub &'wallet WalletCore);

impl NativeTokenTransfer<'_> {
    // The sender's native actor is the root and must hold `amount`; its credit to `recipient` is a
    // Cast.
    pub async fn transfer(
        &self,
        sender: AccountIdentity,
        recipient: AccountIdentity,
        amount: u128,
        delivery: CreditDelivery,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let to = recipient.account_id();
        let (declared, casts) = credit_destination(
            self.0,
            &sender,
            recipient,
            NATIVE_TOKEN_PROGRAM_ID,
            delivery,
        )?;
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
                casts,
                tx_pre_check,
            )
            .await
    }
}
