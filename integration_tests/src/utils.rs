use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use common::HashType;
use kameo::actor::ActorRef;
use key_protocol::key_management::key_tree::chain_index::ChainIndex;
use lee_core::{
    RecipientEncryption,
    account::{AccountId, Actor},
    program::MessageBody,
};
use log::info;
use sequencer_bedrock_actor::{BedrockActor, protocol::GetAccreditedKeys};
use sequencer_core::Ed25519PublicKey;
use sequencer_service_rpc::{RpcClient as _, SequencerClient};
use test_fixtures::{TestContext, private_mention, public_mention, verify_commitment_is_in_state};
use wallet::{
    cli::{
        CliAccountMention, Command, SubcommandReturnValue,
        account::{AccountSubcommand, NewSubcommand},
        pending::PendingSubcommand,
        programs::native_token_transfer::AuthTransferSubcommand,
    },
    storage::key_chain::FoundPrivateAccount,
};

/// Maximum time to wait for the indexer to catch up to the sequencer.
pub const L2_TO_L1_TIMEOUT: Duration = Duration::from_mins(6);
/// Maximum time a single [`wait_until`] may poll before giving up.
const PHASE_TIMEOUT: Duration = Duration::from_secs(360);
/// Bound on the indexer's status snapshot: it goes into an error message, so it cannot wait long.
const INDEXER_STATUS_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_secs(2);

pub fn no_seal(_body: &MessageBody) -> Result<RecipientEncryption, lee::error::LeeError> {
    Err(lee::error::LeeError::InvalidInput(
        "No durable async message is sealed".to_owned(),
    ))
}

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

/// Waits until the sequencer reports `tx_hash` in a block.
pub async fn wait_for_inclusion(ctx: &TestContext, tx_hash: HashType) -> Result<()> {
    wait_until(&format!("transaction {tx_hash} to be included"), || async {
        Ok(ctx
            .sequencer_client()
            .get_transaction(tx_hash)
            .await?
            .is_some())
    })
    .await
}

/// The channel's accredited keys, sorted, plus whose turn the tip was written on.
pub async fn committee(
    observer: &ActorRef<BedrockActor>,
) -> Result<(Vec<[u8; 32]>, Option<Ed25519PublicKey>)> {
    let Some(accredited) = observer
        .ask(GetAccreditedKeys)
        .await
        .context("Failed to read the channel's accredited keys")?
    else {
        return Ok((Vec::new(), None));
    };
    let turn = accredited.whose_turn();
    let mut keys: Vec<_> = accredited
        .keys
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

/// Send `amount` from `from` to `to` via an authenticated transfer.
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
        to_pk: None,
        amount,
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    Ok(())
}

/// A fresh private account holding `amount`, funded from the context's first public account and
/// committed on chain.
pub async fn funded_private_account(ctx: &mut TestContext, amount: u128) -> Result<AccountId> {
    let account = new_account(ctx, true, None).await?;
    let funder = ctx.existing_public_accounts()[0];
    send(
        ctx,
        public_mention(funder),
        private_mention(account),
        amount,
    )
    .await?;
    let commitment = ctx
        .wallet()
        .get_private_account_commitment(account)
        .context("the funded account is unknown to the wallet")?;
    wait_until("the funded account to be committed", || async {
        Ok(verify_commitment_is_in_state(commitment, ctx.sequencer_client()).await)
    })
    .await?;
    Ok(account)
}

/// The native balance of a private account the wallet records.
pub fn private_balance(ctx: &TestContext, account_id: AccountId) -> Result<u128> {
    Ok(restored_private_account(ctx, account_id, "private account")
        .account
        .data
        .native_balance()?)
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
    Ok(ctx
        .sequencer_client()
        .get_account(account_id)
        .await?
        .unwrap_or_default())
}

pub async fn get_account_view(
    ctx: &TestContext,
    actor_state_selector: Actor,
) -> anyhow::Result<lee::Account> {
    Ok(ctx
        .sequencer_client()
        .get_account_view(actor_state_selector)
        .await?
        .unwrap_or_default())
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
        Command::Account(AccountSubcommand::SyncPrivate {
            rescan: false,
            yes: true,
        }),
    )
    .await?;
    Ok(())
}

/// Receive every message pending for the wallet's accounts through `wallet pending receive`, which
/// waits for each receipt and stores the account it credits.
pub async fn receive_pending(ctx: &mut TestContext) -> anyhow::Result<()> {
    for pending in ctx.wallet_mut().owned_pending_messages().await? {
        wallet::cli::execute_subcommand(
            ctx.wallet_mut(),
            Command::Pending(PendingSubcommand::Receive {
                position: pending.position,
                inputs: Box::default(),
            }),
        )
        .await?;
    }
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
                // Only a forward move counts, so a flat or regressed reading reads as stuck.
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

/// The indexer's own account of ingestion, for a wait that did not finish.
async fn indexer_diagnosis(ctx: &TestContext) -> String {
    use indexer_service_rpc::RpcClient as _;

    match tokio::time::timeout(INDEXER_STATUS_TIMEOUT, ctx.indexer_client().get_status()).await {
        Ok(Ok(status)) => format!(
            "Indexer state {:?}, last error {:?}, stall reason {:?}, cross-zone halt {:?}",
            status.state, status.last_error, status.stall_reason, status.cross_zone_halt
        ),
        Ok(Err(err)) => format!("Indexer status unavailable: {err}"),
        Err(_elapsed) => format!("Indexer status did not answer within {INDEXER_STATUS_TIMEOUT:?}"),
    }
}
