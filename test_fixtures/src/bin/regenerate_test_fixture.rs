//! Regenerate the prebuilt sequencer database dump for the fast `TestContext::new()` path.
//! Needs Docker. Run via `just regenerate-test-fixture`, then commit the dump.

#![expect(clippy::print_stdout, reason = "It's normal in this small cli")]

use std::path::Path;

use anyhow::{Context as _, Result};
use common::block::{BedrockStatus, BlockMeta};
use kameo::actor::Spawn as _;
use logos_blockchain_zone_sdk::key_management_system_service::keys::UnsecuredEd25519Key;
use sequencer_bedrock_actor::storage::ZoneCheckpoint;
use sequencer_core::storage::{FinalSnapshotRecord, HeadStateRecord, blocks::BlockRecord};
use sequencer_storage_actor::{
    StorageActor,
    protocol::{Delete, DumpDb, Get, GetRange, Store, WriteBatch},
};
use test_fixtures::{
    config,
    setup::{
        SequencerSetup, fund_private_accounts, prebuilt_sequencer_db_circuit_id_path,
        prebuilt_sequencer_db_dump_path, privacy_preserving_circuit_id_stamp, setup_bedrock_node,
        setup_wallet,
    },
};
use wallet::config::WalletConfigOverrides;

#[tokio::main]
async fn main() -> Result<()> {
    logging::init();

    let dest = prebuilt_sequencer_db_dump_path();
    println!(
        "🗃️  Regenerating prebuilt sequencer db fixture at {}",
        dest.display()
    );

    Box::pin(generate_prebuilt_fixture(&dest))
        .await
        .context("Failed to regenerate prebuilt sequencer database fixture")?;

    println!("✅ Wrote fixture dump to {}", dest.display());
    Ok(())
}

/// Run a real sequencer with the default accounts, apply genesis + fund the private accounts
/// (genesis block + funding block), then strip the checkpoint and reset blocks to `Pending` so the
/// dump replays cleanly against a fresh Bedrock. Writes the dump to `dest`.
async fn generate_prebuilt_fixture(dest: &Path) -> Result<()> {
    let (_bedrock_compose, bedrock_addr) = setup_bedrock_node()
        .await
        .context("Failed to setup Bedrock node")?;

    let initial_public_accounts = config::default_public_accounts_for_wallet();
    let initial_private_accounts = config::default_private_accounts_for_wallet();
    let genesis = config::genesis_from_accounts(
        &initial_public_accounts,
        config::private_funding_cost(&initial_private_accounts),
    );

    let (sequencer_handle, temp_sequencer_dir) =
        SequencerSetup::new(config::SequencerPartialConfig::default(), bedrock_addr)
            .with_genesis(genesis)
            .with_channel_signing_key(UnsecuredEd25519Key::from_bytes(
                &config::CHANNEL_SIGNING_KEY,
            ))
            .setup()
            .await
            .context("Failed to setup Sequencer for fixture generation")?;

    let (mut wallet, _temp_wallet_dir, _wallet_password) = setup_wallet(
        &sequencer_handle.addr(),
        &initial_public_accounts,
        &initial_private_accounts,
        WalletConfigOverrides::default(),
    )
    .context("Failed to setup wallet for fixture generation")?;

    fund_private_accounts(
        &mut wallet,
        &initial_public_accounts,
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
        .ask(Delete::<ZoneCheckpoint>::default())
        .await
        .context("Failed to strip zone-sdk checkpoint from fixture database")?;
    let blocks = storage_ref
        .ask(GetRange::<BlockRecord>::new(None, None, usize::MAX))
        .await
        .context("Failed to read the fixture blocks")?;
    let tip = blocks
        .last()
        .map(|(_block_id, record)| BlockMeta::from(&record.block))
        .context("Fixture store has no blocks")?;
    let mut reset = WriteBatch::new();
    for (block_id, BlockRecord { mut block }) in blocks {
        block.bedrock_status = BedrockStatus::Pending;
        reset.store(Store::new(block_id, BlockRecord { block }));
    }
    storage_ref
        .ask(reset)
        .await
        .context("Failed to reset fixture blocks to pending")?;

    // Stamp the final snapshot at the tip so restore replays no fixture blocks.
    // The dump is generated under RISC0_DEV_MODE, so its privacy proofs are
    // fake receipts that cannot verify in a real-proof run if they land after
    // the finalized tip
    //
    // TODO: once Bedrock communication lives in its own mockable actor, mock it
    // here to finalize immediately and drop this direct storage manipulation.
    let head_state = storage_ref
        .ask(Get::<HeadStateRecord>::default())
        .await
        .context("Failed to read the fixture head state")?
        .context("Fixture store has no persisted head state")?;
    // Blocks must stay Pending for the re-publish; only the snapshot moves.
    storage_ref
        .ask(Store::from_value(FinalSnapshotRecord {
            state: head_state.state,
            meta: tip,
        }))
        .await
        .context("Failed to stamp the fixture final snapshot at the tip")?;

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
    std::fs::write(dest, dump.bytes)
        .with_context(|| format!("Failed to write fixture dump to {}", dest.display()))?;

    let stamp_path = prebuilt_sequencer_db_circuit_id_path();
    std::fs::write(&stamp_path, privacy_preserving_circuit_id_stamp()).with_context(|| {
        format!(
            "Failed to write fixture circuit id to {}",
            stamp_path.display()
        )
    })?;

    Ok(())
}
