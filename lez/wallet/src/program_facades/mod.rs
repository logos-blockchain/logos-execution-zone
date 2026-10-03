//! This module contains [`WalletCore`](crate::WalletCore) facades for interacting with various
//! on-chain programs.

use lee::{AccountId, Actor};
use lee_core::account::ActorState;
use token_core::TokenHolding;

use crate::{AccountIdentity, ExecutionFailureKind, WalletCore};

pub mod amm;
pub mod ata;
pub mod bridge;
pub mod native_token_transfer;
pub mod program_loader;
pub mod sequencer_stake;
pub mod token;

pub(crate) async fn actor_state(
    wallet: &WalletCore,
    account: &AccountIdentity,
    program_account_id: AccountId,
) -> Result<ActorState, ExecutionFailureKind> {
    let account_id = account.account_id();
    if account.is_public() {
        Ok(wallet
            .get_account_view(Actor::new(account_id, program_account_id))
            .await
            .map_err(ExecutionFailureKind::SequencerError)?
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

pub(crate) async fn token_holding(
    wallet: &WalletCore,
    account: &AccountIdentity,
    token_program_id: AccountId,
) -> Result<TokenHolding, ExecutionFailureKind> {
    let data = actor_state(wallet, account, token_program_id).await?;
    TokenHolding::try_from(&data)
        .map_err(|_err| ExecutionFailureKind::AccountDataError(account.account_id()))
}
