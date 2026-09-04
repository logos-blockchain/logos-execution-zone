//! End-to-end tests for the sequencer's startup bootstrap/reconstruction from
//! Bedrock (verify-and-reconstruct). Each test drives a real Bedrock node and one
//! or more sequencer instances sharing the same channel, exercising how a
//! sequencer reconciles its local store against what the channel serves.

#![expect(
    clippy::tests_outside_test_module,
    reason = "Integration tests live at crate root and don't care about these lints"
)]

use std::{path::Path, time::Duration};

use anyhow::{Context as _, Result, bail};
use indexer_service_rpc::RpcClient as _;
use lee::{AccountId, PrivateKey, PublicKey};
use sequencer_core::config::GenesisAction;
use sequencer_service_rpc::{RpcClient as _, SequencerClient};
use test_fixtures::{
    config::{SequencerPartialConfig, UrlProtocol, addr_to_url},
    indexer_client::IndexerClient,
    setup::{SequencerSetup, sequencer_client, setup_bedrock_node, setup_indexer},
};
use tokio::test;

/// Finalization can lag several minutes under CI load; give the bootstrap and
/// reconstruction waits generous headroom so runner-speed variance does not flake.
const FINALIZE_TIMEOUT: Duration = Duration::from_mins(12);

/// Block cadence for the tests: short so we don't wait long for local production.
fn fast_blocks() -> SequencerPartialConfig {
    SequencerPartialConfig {
        block_create_timeout: Duration::from_secs(2),
        ..SequencerPartialConfig::default()
    }
}

/// Block cadence for a sequencer we don't want producing during the inspection
/// window, so its post-reconstruction tip stays put while we read it.
fn slow_blocks() -> SequencerPartialConfig {
    SequencerPartialConfig {
        block_create_timeout: Duration::from_secs(30),
        ..SequencerPartialConfig::default()
    }
}

/// Polls the indexer's last finalized block id until it reaches `target`. The
/// indexer reads finalized channel history, so this is our oracle for "block
/// `target` is finalized on Bedrock" — exactly what a reconstructing sequencer
/// can read back.
async fn wait_for_finalized(
    indexer: &IndexerClient,
    target: u64,
    timeout: Duration,
) -> Result<u64> {
    let poll = async {
        loop {
            let finalized = indexer
                .get_last_finalized_block_id()
                .await
                .context("Failed to read indexer last finalized block id")?
                .unwrap_or(0);
            if finalized >= target {
                return Ok::<_, anyhow::Error>(finalized);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    };
    tokio::time::timeout(timeout, poll)
        .await
        .with_context(|| format!("Timed out waiting for indexer to finalize block {target}"))?
}

/// Polls the sequencer's last block id until it reaches `target` or `timeout` elapses.
async fn wait_for_block_id(
    client: &SequencerClient,
    target: u64,
    timeout: Duration,
) -> Result<u64> {
    let poll = async {
        loop {
            let id = client
                .get_last_block_id()
                .await
                .context("Failed to read sequencer last block id")?;
            if id >= target {
                return Ok::<_, anyhow::Error>(id);
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    };
    tokio::time::timeout(timeout, poll)
        .await
        .with_context(|| format!("Timed out waiting for block id {target}"))?
}

/// Best-effort extraction of a panic payload's message (panics carry a `String`
/// or `&str`), for asserting a startup aborted for the *expected* reason.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .unwrap_or_else(|| "<non-string panic payload>".to_owned())
}

/// A `SupplyAccount` genesis action for a fresh account, returning the account
/// id the funds land in, so tests can assert genesis state is present.
fn supplied_account(balance: u128) -> (AccountId, GenesisAction) {
    let account_id = AccountId::from(&PublicKey::new_from_private_key(
        &PrivateKey::new_os_random(),
    ));
    (
        account_id,
        GenesisAction::SupplyAccount {
            account_id,
            balance,
        },
    )
}

/// Recursively copies the contents of `src` into `dst` (used to snapshot/restore a
/// sequencer's rocksdb directory while it is stopped).
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)
        .with_context(|| format!("Failed to create dir {}", dst.display()))?;
    for entry in
        std::fs::read_dir(src).with_context(|| format!("Failed to read dir {}", src.display()))?
    {
        let entry = entry.context("Failed to read dir entry")?;
        let target = dst.join(entry.file_name());
        if entry
            .file_type()
            .context("Failed to read file type")?
            .is_dir()
        {
            copy_dir_recursive(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)
                .with_context(|| format!("Failed to copy into {}", target.display()))?;
        }
    }
    Ok(())
}

/// Case 1: local store is empty and the Bedrock channel is empty.
///
/// The sequencer bootstraps genesis state, finds nothing to reconstruct, publishes
/// its own genesis to open the channel, and starts producing.
#[test]
async fn empty_local_and_empty_bedrock_bootstraps_from_genesis() -> Result<()> {
    let (_bedrock, bedrock_addr) = setup_bedrock_node()
        .await
        .context("Failed to setup Bedrock")?;
    let home = tempfile::tempdir().context("Failed to create sequencer home")?;

    let (supplied_id, supply) = supplied_account(12_345);
    let genesis = vec![
        supply,
        GenesisAction::SupplyBridgeAccount { balance: 1_000_000 },
    ];

    let handle = SequencerSetup::new(fast_blocks(), bedrock_addr)
        .with_genesis(genesis)
        .setup_at(home.path())
        .await
        .context("Failed to start sequencer")?;
    let client = sequencer_client(handle.addr())?;

    // Fresh store + empty channel: startup bootstrapped genesis state directly.
    assert_eq!(
        client.get_account_balance(supplied_id).await?,
        12_345,
        "genesis-supplied balance must be present after bootstrap"
    );

    // The sequencer is live and producing on the freshly opened channel.
    let last = wait_for_block_id(&client, 3, Duration::from_secs(60)).await?;
    assert!(
        last >= 3,
        "sequencer should keep producing blocks, last={last}"
    );
    assert!(handle.is_healthy(), "sequencer must stay healthy");

    Ok(())
}

/// Case 2: local store is empty, but the Bedrock channel already has blocks.
///
/// A first sequencer opens the channel and produces blocks; a second sequencer
/// starts from an empty store on the same channel (reusing the first's bedrock
/// signing key) and reconstructs the finalized history into its state.
#[test]
async fn empty_local_reconstructs_from_populated_bedrock() -> Result<()> {
    const PRODUCED_TARGET: u64 = 3;

    let (_bedrock, bedrock_addr) = setup_bedrock_node()
        .await
        .context("Failed to setup Bedrock")?;
    let (indexer_handle, _indexer_dir) = setup_indexer(
        bedrock_addr,
        test_fixtures::config::bedrock_channel_id(),
        None,
    )
    .await
    .context("Failed to setup indexer")?;
    let indexer_url = addr_to_url(UrlProtocol::Ws, indexer_handle.addr())
        .context("Failed to build indexer URL")?;
    let indexer = IndexerClient::new(&indexer_url)
        .await
        .context("Failed to build indexer client")?;

    let (supplied_id, supply) = supplied_account(7_777);
    let genesis = vec![
        supply,
        GenesisAction::SupplyBridgeAccount { balance: 1_000_000 },
    ];

    // Sequencer A opens the channel and produces a few blocks.
    let home_a = tempfile::tempdir().context("Failed to create sequencer A home")?;
    let handle_a = SequencerSetup::new(fast_blocks(), bedrock_addr)
        .with_genesis(genesis.clone())
        .setup_at(home_a.path())
        .await
        .context("Failed to start sequencer A")?;
    let client_a = sequencer_client(handle_a.addr())?;
    wait_for_block_id(&client_a, PRODUCED_TARGET, Duration::from_secs(60)).await?;

    // Wait until those blocks are finalized on Bedrock — reconstruction only
    // reads finalized history. A stays alive so its publish task keeps flushing.
    let finalized = wait_for_finalized(&indexer, PRODUCED_TARGET, FINALIZE_TIMEOUT).await?;

    // Stop A, then wipe just its L2 store (keeping the bedrock signing key) so it
    // restarts from an empty store on the same channel/identity — a sequencer that
    // lost its local DB.
    drop(handle_a);
    tokio::time::sleep(Duration::from_secs(2)).await;
    std::fs::remove_dir_all(home_a.path().join(format!(
        "rocksdb-{}",
        test_fixtures::config::bedrock_channel_id()
    )))
    .context("Failed to wipe sequencer L2 store")?;

    // Sequencer B restarts on the same home from that empty store and reconstructs.
    let handle_b = SequencerSetup::new(slow_blocks(), bedrock_addr)
        .with_genesis(genesis)
        .setup_at(home_a.path())
        .await
        .context("Failed to start sequencer B")?;
    let client_b = sequencer_client(handle_b.addr())?;

    // Reconstruction ran synchronously during B's startup: even though its local
    // store was empty, its tip is past genesis, matching the finalized channel.
    let tip_b = client_b.get_last_block_id().await?;
    assert!(
        tip_b >= finalized,
        "B should reconstruct at least the finalized blocks; tip_b={tip_b}, finalized={finalized}"
    );
    assert!(
        tip_b > 1,
        "B should have reconstructed blocks beyond genesis; tip_b={tip_b}"
    );

    // Genesis state was rebuilt as part of the reconstruction.
    assert_eq!(
        client_b.get_account_balance(supplied_id).await?,
        7_777,
        "reconstructed genesis balance must be present"
    );
    assert!(handle_b.is_healthy(), "sequencer B must stay healthy");

    Ok(())
}

/// Case 3: local store is not empty, but the Bedrock channel is empty.
///
/// A sequencer produces blocks (committing to a channel), is stopped, and is
/// restarted with the same channel id against a Bedrock node where that channel
/// is empty — i.e. the channel it committed to was wiped. Startup must fail
/// rather than silently resume onto a foreign channel. Crucially this must hold
/// even though the sequencer only ever *produced* (so it never recorded a
/// per-block anchor): the committed-but-missing-channel invariant catches it.
/// A *different* channel id no longer exercises this, because the db path is
/// per-channel and a new id simply fresh-starts beside the old store.
#[test]
async fn nonempty_local_against_empty_channel_fails_startup() -> Result<()> {
    const PRODUCED_TARGET: u64 = 3;

    let (_bedrock, bedrock_addr) = setup_bedrock_node()
        .await
        .context("Failed to setup Bedrock")?;

    let (_supplied_id, supply) = supplied_account(1);
    let genesis = vec![
        supply,
        GenesisAction::SupplyBridgeAccount { balance: 1_000_000 },
    ];

    // A opens the channel and produces blocks. They land in its local store
    // immediately, so no need to wait for finalization.
    let home_a = tempfile::tempdir().context("Failed to create sequencer A home")?;
    let handle_a = SequencerSetup::new(fast_blocks(), bedrock_addr)
        .with_genesis(genesis.clone())
        .setup_at(home_a.path())
        .await
        .context("Failed to start sequencer A")?;
    wait_for_block_id(
        &sequencer_client(handle_a.addr())?,
        PRODUCED_TARGET,
        Duration::from_secs(60),
    )
    .await?;
    drop(handle_a);
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Restart on the SAME home (A's committed store: blocks + checkpoint) and the
    // SAME channel id, but against a fresh Bedrock node where that channel does
    // not exist — the channel it committed to is gone.
    let (_bedrock_b, bedrock_addr_b) = setup_bedrock_node()
        .await
        .context("Failed to setup second Bedrock")?;

    // Startup aborts on the missing-channel invariant (a panic in
    // `start_from_config`). Run it on a dedicated OS thread with its own runtime
    // so the panic is isolated to `join()` instead of failing the test thread.
    // The `timeout` future must be created *inside* `block_on` (it needs a running
    // reactor), so build it in an `async` block rather than as an eager argument.
    let home_a_path = home_a.path().to_owned();
    let outcome = std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().expect("Failed to build runtime");
        runtime.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(90),
                SequencerSetup::new(slow_blocks(), bedrock_addr_b)
                    .with_genesis(genesis)
                    .setup_at(&home_a_path),
            )
            .await
        })
    })
    .join();

    match outcome {
        // Expected: `start_from_config` panicked on the missing-channel invariant.
        // Assert the *reason*, so an unrelated panic fails the test rather than
        // masquerading as success.
        Err(panic) => {
            let message = panic_message(&*panic);
            assert!(
                message.contains("Refusing to resume onto a foreign channel"),
                "startup panicked for an unexpected reason: {message}"
            );
        }
        Ok(Err(_elapsed)) => {
            bail!("Sequencer startup hung instead of failing against an empty channel")
        }
        Ok(Ok(Err(err))) => {
            bail!("Sequencer expected to panic, but it failed with error: {err:#?}")
        }
        Ok(Ok(Ok(_handle))) => {
            bail!("Sequencer startup unexpectedly succeeded against an empty channel")
        }
    }

    Ok(())
}

/// Case 4: both non-empty, but the local store is *ahead* of the finalized channel.
///
/// A sequencer produces blocks faster than Bedrock finalizes them (the normal
/// steady state), so on restart its local tip leads the channel's finalized tip.
/// Startup must succeed: reconstruction re-verifies the finalized blocks it already
/// holds and leaves the extra, not-yet-finalized local blocks untouched.
#[test]
async fn local_ahead_of_channel_resumes() -> Result<()> {
    const FINALIZED_TARGET: u64 = 2;

    let (_bedrock, bedrock_addr) = setup_bedrock_node()
        .await
        .context("Failed to setup Bedrock")?;
    let (indexer_handle, _indexer_dir) = setup_indexer(
        bedrock_addr,
        test_fixtures::config::bedrock_channel_id(),
        None,
    )
    .await
    .context("Failed to setup indexer")?;
    let indexer_url = addr_to_url(UrlProtocol::Ws, indexer_handle.addr())
        .context("Failed to build indexer URL")?;
    let indexer = IndexerClient::new(&indexer_url)
        .await
        .context("Failed to build indexer client")?;

    let (supplied_id, supply) = supplied_account(4_242);
    let genesis = vec![
        supply,
        GenesisAction::SupplyBridgeAccount { balance: 1_000_000 },
    ];

    // A produces continuously (fast cadence) while Bedrock finalizes slowly, so
    // its local tip runs well ahead of the channel's finalized tip.
    let home = tempfile::tempdir().context("Failed to create sequencer home")?;
    let handle_a = SequencerSetup::new(fast_blocks(), bedrock_addr)
        .with_genesis(genesis.clone())
        .setup_at(home.path())
        .await
        .context("Failed to start sequencer A")?;
    let client_a = sequencer_client(handle_a.addr())?;
    let finalized = wait_for_finalized(&indexer, FINALIZED_TARGET, FINALIZE_TIMEOUT).await?;
    let tip_before = client_a.get_last_block_id().await?;
    assert!(
        tip_before > finalized,
        "local tip {tip_before} should lead the finalized tip {finalized}"
    );

    // Restart on the same home; slow cadence so its tip stays put while we inspect.
    drop(handle_a);
    tokio::time::sleep(Duration::from_secs(2)).await;
    let handle_b = SequencerSetup::new(slow_blocks(), bedrock_addr)
        .with_genesis(genesis)
        .setup_at(home.path())
        .await
        .context("Failed to restart sequencer")?;
    let client_b = sequencer_client(handle_b.addr())?;

    // Reconstruction verified the finalized prefix and preserved the extra blocks.
    let tip_b = client_b.get_last_block_id().await?;
    assert!(
        tip_b >= tip_before,
        "restart must not lose locally-produced blocks; tip_b={tip_b}, before={tip_before}"
    );
    assert_eq!(
        client_b.get_account_balance(supplied_id).await?,
        4_242,
        "genesis state must survive the restart"
    );
    assert!(handle_b.is_healthy(), "sequencer must stay healthy");

    Ok(())
}

/// Case 5: both non-empty, but the local store is *behind* the finalized channel.
///
/// We snapshot a sequencer's store at an early tip, let it keep extending and
/// finalizing the channel, then restore the early snapshot and restart. Startup
/// must reconstruct forward — replay the finalized blocks the local store is
/// missing — catching the local tip up to the channel.
///
/// The snapshot/restore is essential here (not a gratuitous copy): a live
/// sequencer's local tip always leads finalization, so the only way to obtain a
/// local store that *lags* the finalized channel is to preserve an earlier state
/// while the same channel advances past it.
#[test]
async fn local_behind_channel_reconstructs_forward() -> Result<()> {
    const SNAPSHOT_TIP: u64 = 2;
    const FINALIZED_TARGET: u64 = 4;

    let (_bedrock, bedrock_addr) = setup_bedrock_node()
        .await
        .context("Failed to setup Bedrock")?;
    let (indexer_handle, _indexer_dir) = setup_indexer(
        bedrock_addr,
        test_fixtures::config::bedrock_channel_id(),
        None,
    )
    .await
    .context("Failed to setup indexer")?;
    let indexer_url = addr_to_url(UrlProtocol::Ws, indexer_handle.addr())
        .context("Failed to build indexer URL")?;
    let indexer = IndexerClient::new(&indexer_url)
        .await
        .context("Failed to build indexer client")?;

    let (supplied_id, supply) = supplied_account(5_005);
    let genesis = vec![
        supply,
        GenesisAction::SupplyBridgeAccount { balance: 1_000_000 },
    ];

    let home = tempfile::tempdir().context("Failed to create sequencer home")?;
    let rocksdb = home.path().join(format!(
        "rocksdb-{}",
        test_fixtures::config::bedrock_channel_id()
    ));

    // Bring the sequencer up to an early tip, then stop it so its store is at rest.
    {
        let handle = SequencerSetup::new(slow_blocks(), bedrock_addr)
            .with_genesis(genesis.clone())
            .setup_at(home.path())
            .await
            .context("Failed to start sequencer")?;
        wait_for_block_id(
            &sequencer_client(handle.addr())?,
            SNAPSHOT_TIP,
            Duration::from_secs(120),
        )
        .await?;
        drop(handle);
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    // Snapshot the early store (tip == SNAPSHOT_TIP), safe because it is at rest.
    let snapshot = tempfile::tempdir().context("Failed to create snapshot dir")?;
    copy_dir_recursive(&rocksdb, snapshot.path()).context("Failed to snapshot store")?;

    // Resume the sequencer (fast cadence) so it extends and finalizes the channel
    // beyond the snapshot.
    let finalized = {
        let handle = SequencerSetup::new(fast_blocks(), bedrock_addr)
            .with_genesis(genesis.clone())
            .setup_at(home.path())
            .await
            .context("Failed to resume sequencer")?;
        let finalized = wait_for_finalized(&indexer, FINALIZED_TARGET, FINALIZE_TIMEOUT).await?;
        drop(handle);
        tokio::time::sleep(Duration::from_secs(2)).await;
        finalized
    };

    // Restore the early snapshot: the local store now lags the finalized channel.
    std::fs::remove_dir_all(&rocksdb).context("Failed to remove store before restore")?;
    copy_dir_recursive(snapshot.path(), &rocksdb).context("Failed to restore snapshot")?;

    // Restart: reconstruction must catch the lagging store up to the channel.
    let handle = SequencerSetup::new(slow_blocks(), bedrock_addr)
        .with_genesis(genesis)
        .setup_at(home.path())
        .await
        .context("Failed to restart sequencer from a lagging store")?;
    let client = sequencer_client(handle.addr())?;
    let tip = client.get_last_block_id().await?;
    assert!(
        tip >= finalized,
        "lagging store must reconstruct forward to the finalized tip; tip={tip}, finalized={finalized}"
    );
    assert!(
        tip > SNAPSHOT_TIP,
        "reconstruction must advance beyond the snapshot tip; tip={tip}"
    );
    assert_eq!(
        client.get_account_balance(supplied_id).await?,
        5_005,
        "genesis state must be intact after reconstruction"
    );
    assert!(handle.is_healthy(), "sequencer must stay healthy");

    Ok(())
}
