//! Regenerate the prebuilt sequencer database dump for the fast `TestContext::new()` path.
//! Needs Docker. Run via `just regenerate-test-fixture`, then commit the dump.

#![expect(clippy::print_stdout, reason = "It's normal in this small cli")]

use std::{path::Path, time::Duration};

use anyhow::{Context as _, Result};
use lee::PrivateKey;
use sequencer_core::block_store::SequencerStore;
use test_fixtures::{
    config,
    setup::{
        SequencerSetup, prebuilt_sequencer_db_dump_path, setup_bedrock_node,
        setup_private_accounts_with_initial_supply, setup_public_accounts_with_initial_supply,
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

    setup_public_accounts_with_initial_supply(&mut wallet, &initial_public_accounts)
        .await
        .context("Failed to initialize public accounts for fixture generation")?;
    setup_private_accounts_with_initial_supply(&mut wallet, &initial_private_accounts)
        .await
        .context("Failed to initialize private accounts for fixture generation")?;

    // Shut down gracefully to release the rocksdb lock before reopening the store.
    drop(wallet);
    drop(sequencer_handle);

    let db_path = temp_sequencer_dir
        .path()
        .join(format!("rocksdb-{}", config::bedrock_channel_id()));
    let store = open_store_with_retry(&db_path)
        .await
        .context("Failed to reopen sequencer store after shutdown")?;
    store
        .delete_zone_checkpoint()
        .context("Failed to strip zone-sdk checkpoint from fixture database")?;
    store
        .reset_all_blocks_to_pending()
        .context("Failed to reset fixture blocks to pending")?;
    let dump = store.dump().context("Failed to dump fixture database")?;
    drop(store);

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

/// Reopen the store, retrying while the shut-down sequencer's aborted tasks are still releasing
/// their db handles (the process holds the file lock until then). Must `await` between attempts.
async fn open_store_with_retry(db_path: &Path) -> Result<SequencerStore> {
    let signing_key = PrivateKey::try_new(config::SEQUENCER_SIGNING_KEY)
        .expect("Fixed sequencer signing key must be valid");

    let mut last_err = None;
    for _ in 0..100 {
        // Let the runtime drop the aborted sequencer tasks before each attempt.
        tokio::time::sleep(Duration::from_millis(100)).await;
        match SequencerStore::open_db(db_path, signing_key.clone()) {
            Ok(store) => return Ok(store),
            Err(err) => last_err = Some(err),
        }
    }
    Err(anyhow::anyhow!(
        "Failed to open sequencer store at {} after retries: {last_err:?}",
        db_path.display()
    ))
}
