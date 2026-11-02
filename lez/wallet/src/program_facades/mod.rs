//! This module contains [`WalletCore`](crate::WalletCore) facades for interacting with various
//! on-chain programs.

use lee::{AccountId, Actor};
use lee_core::account::ActorState;

use crate::{
    AccountIdentity, AccountMention, AsyncDelivery, ExecutionFailureKind, WalletCore,
    WalletSequencerClient,
};

pub mod bridge;
pub mod native_token_transfer;
pub mod program_loader;
pub mod sequencer_stake;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreditDelivery {
    Automatic,
    DeferredPrivate,
}

// What `sender`'s credit to `recipient` at `program` adds to a transaction: the recipient's account
// when it takes part now, or the recovery binding or seal of a credit left pending.
pub(crate) fn credit_destination<C: WalletSequencerClient>(
    wallet: &WalletCore<C>,
    sender: &AccountIdentity,
    recipient: AccountIdentity,
    program: AccountId,
    delivery: CreditDelivery,
) -> Result<(Option<AccountMention>, AsyncDelivery), ExecutionFailureKind> {
    let pending = recipient.is_private()
        && (delivery == CreditDelivery::DeferredPrivate
            || matches!(recipient, AccountIdentity::PrivateForeign { .. }));
    let mention = recipient.select_program_actor_state(program);
    if !pending {
        let joins = mention.identity.account_id() != sender.account_id();
        return Ok((joins.then(|| mention.receiving()), AsyncDelivery::default()));
    }
    let (_, mut async_delivery) = if sender.is_private() {
        wallet.seal_destination(mention)?
    } else {
        wallet.async_destination(mention)?
    };
    async_delivery.promotions.listed_only = true;
    Ok((None, async_delivery))
}

pub(crate) async fn actor_state<C: WalletSequencerClient>(
    wallet: &WalletCore<C>,
    account: &AccountIdentity,
    program_account_id: AccountId,
) -> Result<ActorState, ExecutionFailureKind> {
    let account_id = account.account_id();
    if account.is_public() {
        Ok(wallet
            .get_account_view(Actor::new(account_id, program_account_id))
            .await
            .map_err(ExecutionFailureKind::SequencerError)?
            .unwrap_or_default()
            .data
            .actor_state(program_account_id)
            .clone())
    } else {
        Ok(wallet
            .private_account_state(account_id)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?
            .data
            .actor_state(program_account_id)
            .clone())
    }
}
