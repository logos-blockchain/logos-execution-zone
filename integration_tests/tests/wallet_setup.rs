#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::time::Duration;

use anyhow::{Context as _, Result};
use integration_tests::TestContext;
use sequencer_service_rpc::RpcClient as _;
use tokio::test;
use wallet::{WalletCore, config::WalletConfigOverrides};

#[test]
async fn a_fresh_wallet_starts_at_the_chain_tip() -> Result<()> {
    let ctx = TestContext::new().await?;

    let mut tip_before = ctx.sequencer_client().get_last_block_id().await?;
    for _ in 0..30_u32 {
        if tip_before > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        tip_before = ctx.sequencer_client().get_last_block_id().await?;
    }
    anyhow::ensure!(tip_before > 0, "Chain did not produce a block");

    let home = tempfile::tempdir().context("Failed to create temp dir for wallet home")?;
    let mut node_config = ctx.wallet().config().clone();
    if let Some(applied) = ctx.wallet().config_overrides().clone() {
        node_config.apply_overrides(applied);
    }
    let overrides = WalletConfigOverrides {
        sequencer: Some(node_config.sequencer),
        ..WalletConfigOverrides::default()
    };

    let (mut wallet, _mnemonic) = WalletCore::new_init_storage(
        home.path().join("wallet_config.json"),
        home.path().join("storage.json"),
        Some(overrides.clone()),
        "test_pass",
    )?;
    let cursor = wallet.start_at_chain_tip().await?;
    wallet.store_persistent_data()?;
    drop(wallet);

    let tip_after = ctx.sequencer_client().get_last_block_id().await?;
    assert!(
        cursor >= tip_before && cursor <= tip_after,
        "Fresh wallet cursor {cursor} is outside the tip range {tip_before}..={tip_after}"
    );

    let mut reopened = WalletCore::new_update_chain(
        home.path().join("wallet_config.json"),
        home.path().join("storage.json"),
        Some(overrides),
        "test_pass",
    )?;
    assert_eq!(reopened.storage().last_synced_block(), cursor);
    let synced = reopened.sync_to_latest_block().await?;
    assert!(
        reopened.storage().last_synced_block() >= cursor,
        "Syncing to block {synced} rewound the cursor from {cursor} to {}",
        reopened.storage().last_synced_block()
    );

    Ok(())
}
