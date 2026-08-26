//! Regenerate the prebuilt sequencer database dump for the fast `TestContext::new()` path.
//! Needs Docker. Run via `just regenerate-test-fixture`, then commit the dump.

#![expect(clippy::print_stdout, reason = "It's normal in this small cli")]

use std::path::Path;

use anyhow::{Context as _, Result};
use kameo::actor::Spawn as _;
use sequencer_storage_actor::{
    StorageActor,
    protocol::{DeleteZoneCheckpoint, DumpDb, ResetAllBlocksToPending},
};
use test_fixtures::{
    config,
    setup::{
        SequencerSetup, fund_private_accounts, prebuilt_sequencer_db_dump_path, setup_bedrock_node,
        setup_wallet,
    },
};
use wallet::config::WalletConfigOverrides;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let dest = prebuilt_sequencer_db_dump_path();
    println!(
        "🗃️  Regenerating prebuilt sequencer db fixture at {}",
        dest.display()
    );

    generate_prebuilt_fixture(&dest)
        .await
        .context("Failed to regenerate prebuilt sequencer database fixture")?;

    println!("✅ Wrote fixture dump to {}", dest.display());
    Ok(())
}

/// Run a real sequencer with the default accounts, apply genesis + claim the initial supply
/// (genesis block + claim block), then strip the checkpoint and reset blocks to `Pending` so the
/// dump replays cleanly against a fresh Bedrock. Writes the dump to `dest`.
async fn generate_prebuilt_fixture(dest: &Path) -> Result<()> {
    let (_bedrock_compose, bedrock_addr) = setup_bedrock_node()
        .await
        .context("Failed to setup Bedrock node")?;

    let initial_public_accounts = config::default_public_accounts_for_wallet();
    let initial_private_accounts = config::default_private_accounts_for_wallet();
    let genesis =
        config::genesis_from_accounts(&initial_public_accounts, &initial_private_accounts);

    let (sequencer_handle, temp_sequencer_dir) =
        SequencerSetup::new(config::SequencerPartialConfig::default(), bedrock_addr)
            .with_genesis(genesis)
            .with_bedrock_signing_key(config::SEQUENCER_BEDROCK_SIGNING_KEY)
            .setup()
            .await
            .context("Failed to setup Sequencer for fixture generation")?;

    let (mut wallet, _temp_wallet_dir, _wallet_password) = setup_wallet(
        &[sequencer_handle.addr()],
        &initial_public_accounts,
        &initial_private_accounts,
        WalletConfigOverrides::default(),
    )
    .await
    .context("Failed to setup wallet for fixture generation")?;

    wallet
        .sync_to_latest_block()
        .await
        .context("Failed to sync wallet for fixture generation")?;

    // The prebuilt store must already contain the private accounts' commitments, since a
    // context restored from it does no funding of its own.
    fund_private_accounts(
        &mut wallet,
        &initial_public_accounts[config::PRIVATE_FUNDER_INDEX].0,
        &initial_private_accounts,
    )
    .await
    .context("Failed to fund private accounts for fixture generation")?;

    // Shut down gracefully to release the rocksdb lock before reopening the store.
    drop(wallet);
    sequencer_handle.shutdown().await;

    let db_path = temp_sequencer_dir
        .path()
        .join(format!("rocksdb-{}", config::bedrock_channel_id()));
    let storage =
        StorageActor::new(&db_path).context("Failed to reopen sequencer storage after shutdown")?;
    let storage_ref = StorageActor::spawn(storage);
    storage_ref
        .ask(DeleteZoneCheckpoint)
        .await
        .context("Failed to strip zone-sdk checkpoint from fixture database")?;
    storage_ref
        .ask(ResetAllBlocksToPending)
        .await
        .context("Failed to reset fixture blocks to pending")?;
    let dump = storage_ref
        .ask(DumpDb)
        .await
        .context("Failed to dump fixture database")?;
    storage_ref.stop_gracefully().await?;
    storage_ref.wait_for_shutdown_with_result(|_| ()).await;

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create fixture directory {}", parent.display()))?;
    }
    let bytes = dump
        .to_bytes()
        .context("Failed to serialize fixture dump")?;
    std::fs::write(dest, bytes)
        .with_context(|| format!("Failed to write fixture dump to {}", dest.display()))?;

    Ok(())
}
