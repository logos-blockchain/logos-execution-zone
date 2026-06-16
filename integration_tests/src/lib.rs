//! Integration test helpers, re-exported from `test_fixtures` for backwards
//! compatibility. The actual fixtures live in the `test_fixtures` crate so that
//! non-test consumers (e.g. `integration_bench`) can depend on them without
//! pulling in the test files.

use std::time::Duration;

use anyhow::{Context as _, Result};
use key_protocol::key_management::key_tree::chain_index::ChainIndex;
use lee::AccountId;
use log::info;
pub use test_fixtures::*;
use wallet::{
    cli::{
        CliAccountMention, Command, SubcommandReturnValue,
        account::{AccountSubcommand, NewSubcommand},
        programs::native_token_transfer::AuthTransferSubcommand,
    },
    storage::key_chain::FoundPrivateAccount,
};

/// Create a private or public account at the given chain index and return its ID.
/// Pass `cci: None` to use the wallet's next available chain index.
pub async fn new_account(
    ctx: &mut TestContext,
    private: bool,
    cci: Option<ChainIndex>,
) -> Result<AccountId> {
    let subcommand = if private {
        NewSubcommand::Private { cci, label: None }
    } else {
        NewSubcommand::Public { cci, label: None }
    };
    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(subcommand)),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount { account_id } = result else {
        anyhow::bail!("Expected RegisterAccount return value");
    };
    Ok(account_id)
}

/// Send `amount` from `from` to `to` via an authenticated transfer (identifier 0).
pub async fn send(
    ctx: &mut TestContext,
    from: CliAccountMention,
    to: CliAccountMention,
    amount: u128,
) -> Result<()> {
    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from,
        to: Some(to),
        to_npk: None,
        to_vpk: None,
        to_keys: None,
        to_identifier: Some(0),
        amount,
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    Ok(())
}

/// Look up a restored private account for `account_id`, panicking with `label` if absent.
pub fn restored_private_account<'a>(
    ctx: &'a TestContext,
    account_id: AccountId,
    label: &str,
) -> FoundPrivateAccount<'a> {
    ctx.wallet()
        .storage()
        .key_chain()
        .private_account(account_id)
        .unwrap_or_else(|| panic!("{label} should be restored"))
}

/// Assert that a restored public account's signing key exists, panicking with `label` if absent.
pub fn assert_public_account_restored(ctx: &TestContext, account_id: AccountId, label: &str) {
    ctx.wallet()
        .storage()
        .key_chain()
        .pub_account_signing_key(account_id)
        .unwrap_or_else(|| panic!("{label} should be restored"));
}

/// Maximum time to wait for the indexer to catch up to the sequencer.
pub const L2_TO_L1_TIMEOUT: Duration = Duration::from_mins(7);

/// Poll the indexer until its last finalized block id reaches the sequencer's
/// current last block id or until [`L2_TO_L1_TIMEOUT`] elapses.
/// Returns the last indexer block id observed.
pub async fn wait_for_indexer_to_catch_up(ctx: &TestContext) -> Result<u64> {
    use indexer_service_rpc::RpcClient as _;

    let block_id_to_catch_up =
        sequencer_service_rpc::RpcClient::get_last_block_id(ctx.sequencer_client()).await?;
    let mut last_ind: u64 = 1;
    let inner = async {
        loop {
            let ind = ctx
                .indexer_client()
                .get_last_finalized_block_id()
                .await?
                .unwrap_or(0);
            last_ind = ind;
            if ind >= block_id_to_catch_up {
                let last_seq =
                    sequencer_service_rpc::RpcClient::get_last_block_id(ctx.sequencer_client())
                        .await?;
                info!(
                    "Indexer caught up. Indexer last block id: {ind}. Current sequencer last block id: {last_seq}"
                );
                return Ok(ind);
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    };
    tokio::time::timeout(L2_TO_L1_TIMEOUT, inner)
        .await
        .with_context(|| {
            format!(
                "Indexer failed to catch up within {L2_TO_L1_TIMEOUT:?}. Last indexer block id observed: {last_ind}, but needed to catch up to at least {block_id_to_catch_up}"
            )
        })?
}
