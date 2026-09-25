//! This module contains [`WalletCore`](crate::WalletCore) facades for interacting with various
//! on-chain programs.

use lee::{AccountId, ProgramShardSelector};
use lee_core::account::ShardData;
use token_core::TokenHolding;

use crate::{AccountIdentity, ExecutionFailureKind, WalletCore};

pub mod amm;
pub mod ata;
pub mod bridge;
pub mod native_token_transfer;
pub mod program_loader;
pub mod token;

pub(crate) async fn shard(
    wallet: &WalletCore,
    account: &AccountIdentity,
    program_account_id: AccountId,
) -> Result<ShardData, ExecutionFailureKind> {
    let account_id = account.account_id();
    if account.is_public() {
        Ok(wallet
            .get_account_view(ProgramShardSelector::new(account_id, program_account_id))
            .await
            .map_err(ExecutionFailureKind::SequencerError)?
            .data
            .shard(program_account_id)
            .clone())
    } else {
        Ok(wallet
            .private_account_state(account_id)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?
            .data
            .shard(program_account_id)
            .clone())
    }
}

pub(crate) async fn token_holding(
    wallet: &WalletCore,
    account: &AccountIdentity,
    token_program_id: AccountId,
) -> Result<TokenHolding, ExecutionFailureKind> {
    let data = shard(wallet, account, token_program_id).await?;
    TokenHolding::try_from(&data)
        .map_err(|_err| ExecutionFailureKind::AccountDataError(account.account_id()))
}
