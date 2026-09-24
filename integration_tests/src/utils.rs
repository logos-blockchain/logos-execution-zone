use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use key_protocol::key_management::key_tree::chain_index::ChainIndex;
use lee_core::account::{AccountId, ProgramShardSelector};
use log::info;
use sequencer_core::{
    block_publisher::{Ed25519PublicKey, read_channel_state},
    config::BedrockConfig,
};
use sequencer_service_rpc::{RpcClient as _, SequencerClient};
use test_fixtures::{TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, verify_commitment_is_in_state};
use wallet::{
    cli::{
        CliAccountMention, Command, SubcommandReturnValue,
        account::{AccountSubcommand, NewSubcommand},
        programs::{
            native_token_transfer::AuthTransferSubcommand, token::TokenProgramAgnosticSubcommand,
        },
    },
    storage::key_chain::FoundPrivateAccount,
};

/// Maximum time to wait for the indexer to catch up to the sequencer.
pub const L2_TO_L1_TIMEOUT: Duration = Duration::from_mins(6);
/// Maximum time a single [`wait_until`] may poll before giving up.
const PHASE_TIMEOUT: Duration = Duration::from_secs(360);
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Polls `check` until it reports ready, failing with `what` on timeout.
pub async fn wait_until<F, Fut>(what: &str, mut check: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<bool>>,
{
    let wait = async {
        while !check().await? {
            tokio::time::sleep(POLL_INTERVAL).await;
        }
        Ok::<(), anyhow::Error>(())
    };
    tokio::time::timeout(PHASE_TIMEOUT, wait)
        .await
        .with_context(|| format!("Timed out waiting for {what}"))?
}

/// The channel's accredited keys, sorted, plus whose turn the tip was written on.
pub async fn committee(
    config: &BedrockConfig,
) -> Result<(Vec<[u8; 32]>, Option<Ed25519PublicKey>)> {
    let Some(state) = read_channel_state(config).await? else {
        return Ok((Vec::new(), None));
    };
    let turn = state
        .accredited_keys
        .get(usize::from(state.tip_sequencer))
        .copied();
    let mut keys: Vec<_> = state
        .accredited_keys
        .iter()
        .map(Ed25519PublicKey::to_bytes)
        .collect();
    keys.sort_unstable();
    Ok((keys, turn))
}

/// Asserts A and B hold byte-identical block hashes over their common prefix.
pub async fn assert_same_chain(a: &SequencerClient, b: &SequencerClient) -> Result<()> {
    let common = a
        .get_last_block_id()
        .await?
        .min(b.get_last_block_id().await?);
    for id in 1..=common {
        let block_a = a
            .get_block(id)
            .await?
            .with_context(|| format!("A is missing block {id}"))?;
        let block_b = b
            .get_block(id)
            .await?
            .with_context(|| format!("B is missing block {id}"))?;
        ensure!(
            block_a.header.hash == block_b.header.hash,
            "Chain divergence at block {id}: A {:?} vs B {:?}",
            block_a.header.hash,
            block_b.header.hash
        );
    }
    Ok(())
}

/// Create a private or public account at the given chain index and return its ID.
/// Pass `cci: None` to use the wallet's next available chain index.
pub async fn new_account(
    ctx: &mut TestContext,
    private: bool,
    cci: Option<ChainIndex>,
) -> anyhow::Result<AccountId> {
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
) -> anyhow::Result<()> {
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

/// Create a token (New) and wait for the block to be included.
pub async fn create_token(
    ctx: &mut TestContext,
    definition_account_id: CliAccountMention,
    supply_account_id: CliAccountMention,
    name: impl Into<String>,
    total_supply: u128,
) -> anyhow::Result<()> {
    let subcommand = TokenProgramAgnosticSubcommand::New {
        definition_account_id,
        supply_account_id,
        name: name.into(),
        total_supply,
    };
    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;
    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;
    Ok(())
}

/// Send tokens and wait for the block to be included.
pub async fn token_send(
    ctx: &mut TestContext,
    from: CliAccountMention,
    to: CliAccountMention,
    amount: u128,
) -> anyhow::Result<()> {
    let subcommand = TokenProgramAgnosticSubcommand::Send {
        from,
        to: Some(to),
        to_npk: None,
        to_vpk: None,
        to_keys: None,
        to_identifier: Some(0),
        amount,
    };
    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;
    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;
    Ok(())
}

/// Retrieve the native token balance for `account_id`.
pub async fn account_balance(ctx: &TestContext, account_id: AccountId) -> anyhow::Result<u128> {
    Ok(ctx
        .sequencer_client()
        .get_account_balance(account_id)
        .await?)
}

/// Fetch the full account state for `account_id` from the sequencer.
pub async fn get_account(ctx: &TestContext, account_id: AccountId) -> anyhow::Result<lee::Account> {
    Ok(ctx.sequencer_client().get_account(account_id).await?)
}

pub async fn get_account_view(
    ctx: &TestContext,
    shard_selector: ProgramShardSelector,
) -> anyhow::Result<lee::Account> {
    Ok(ctx
        .sequencer_client()
        .get_account_view(shard_selector)
        .await?)
}

/// Fetch the current commitment for `account_id` and assert it is present in the sequencer state.
pub async fn assert_private_commitment_in_state(
    ctx: &TestContext,
    account_id: AccountId,
    label: &str,
) -> anyhow::Result<()> {
    let commitment = ctx
        .wallet()
        .get_private_account_commitment(account_id)
        .with_context(|| format!("Failed to get commitment for {label}"))?;
    assert!(verify_commitment_is_in_state(commitment, ctx.sequencer_client()).await);
    Ok(())
}

/// Sync the wallet's private accounts.
pub async fn sync_private(ctx: &mut TestContext) -> anyhow::Result<()> {
    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::SyncPrivate {}),
    )
    .await?;
    Ok(())
}

/// Look up a restored private account for `account_id`, panicking with `label` if absent.
#[must_use]
pub fn restored_private_account<'ctx>(
    ctx: &'ctx TestContext,
    account_id: AccountId,
    label: &str,
) -> FoundPrivateAccount<'ctx> {
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

/// Poll the indexer until its last finalized block id reaches the sequencer's
/// current last block id or until [`L2_TO_L1_TIMEOUT`] elapses.
/// Returns the last indexer block id observed.
pub async fn wait_for_indexer_to_catch_up(ctx: &TestContext) -> anyhow::Result<u64> {
    use indexer_service_rpc::RpcClient as _;

    let block_id_to_catch_up =
        sequencer_service_rpc::RpcClient::get_last_block_id(ctx.sequencer_client()).await?;
    let mut last_ind: u64 = 0;
    // Slow or stuck: the timeout message cannot tell them apart without this.
    let mut first_ind: Option<u64> = None;
    let mut last_moved = std::time::Instant::now();
    let inner = async {
        loop {
            let ind = ctx
                .indexer_client()
                .get_last_finalized_block_id()
                .await?
                .unwrap_or(0);
            match first_ind {
                None => first_ind = Some(ind),
                Some(_) if ind > last_ind => last_moved = std::time::Instant::now(),
                Some(_) => {}
            }
            last_ind = ind;
            if ind >= block_id_to_catch_up {
                let last_seq =
                    sequencer_service_rpc::RpcClient::get_last_block_id(ctx.sequencer_client())
                        .await?;
                info!(
                    "Indexer caught up. Indexer last block id: {ind}. Current sequencer last block id: {last_seq}"
                );
                return anyhow::Ok(ind);
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    };
    match tokio::time::timeout(L2_TO_L1_TIMEOUT, inner).await {
        Ok(Ok(reached)) => Ok(reached),
        // A failing poll is as likely to be a wedged indexer as an elapsed
        // deadline, so it earns the same diagnosis.
        Ok(Err(err)) => Err(err.context(format!(
            "Indexer polling failed before catching up. Last indexer block id observed: {last_ind}, needed at least {block_id_to_catch_up}. {}",
            indexer_diagnosis(ctx).await
        ))),
        Err(_elapsed) => {
            let started_at = first_ind.unwrap_or(last_ind);
            let unchanged_for = last_moved.elapsed();
            let diagnosis = indexer_diagnosis(ctx).await;
            anyhow::bail!(
                "Indexer failed to catch up within {L2_TO_L1_TIMEOUT:?}. Last indexer block id observed: {last_ind}, but needed to catch up to at least {block_id_to_catch_up}. \
                 Height when the wait began: {started_at}, unchanged over the last {unchanged_for:?} of the wait. {diagnosis}"
            )
        }
    }
}

/// The indexer's own account of ingestion, for a wait that did not finish. Bounded
/// because a snapshot that takes a minute to arrive is already stale.
async fn indexer_diagnosis(ctx: &TestContext) -> String {
    use indexer_service_rpc::RpcClient as _;

    match tokio::time::timeout(Duration::from_secs(5), ctx.indexer_client().get_status()).await {
        Ok(Ok(status)) => format!(
            "Indexer state {:?}, last error {:?}, stall reason {:?}, cross-zone halt {:?}",
            status.state, status.last_error, status.stall_reason, status.cross_zone_halt
        ),
        Ok(Err(err)) => format!("Indexer status unavailable: {err}"),
        Err(_elapsed) => "Indexer status did not answer within 5s".to_owned(),
    }
}
