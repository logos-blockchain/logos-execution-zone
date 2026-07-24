//! "Genesis follows config" checks for both the from-scratch and prebuilt `TestContext` paths.
//! Need Docker/Bedrock, like the integration tests.
#![expect(clippy::tests_outside_test_module, reason = "It's a tests module")]

use anyhow::{Context as _, Result};
use lee::{AccountId, PublicKey};
use sequencer_service_rpc::RpcClient as _;
use test_fixtures::{
    TestContext,
    config::{default_private_accounts_for_wallet, default_public_accounts_for_wallet},
    verify_commitment_is_in_state,
};

/// Builds from genesis (no prebuilt database) and checks the on-chain state follows the config.
#[tokio::test]
async fn genesis_from_scratch_follows_config() -> Result<()> {
    let ctx = TestContext::builder().from_scratch().build().await?;
    assert_context_follows_config(&ctx).await
}

/// Loads the prebuilt database via [`TestContext::new`] and checks the restored state follows the
/// config — i.e. the dump round-trips and all expected data persists.
#[tokio::test]
async fn prebuilt_context_follows_config() -> Result<()> {
    let ctx = TestContext::new().await?;
    assert_context_follows_config(&ctx).await
}

/// Assert every configured default account is funded with its configured balance, and every
/// configured private account's commitment is present in sequencer state. (The wallet also has an
/// unfunded default root account, so we check the configured accounts specifically.)
async fn assert_context_follows_config(ctx: &TestContext) -> Result<()> {
    for (private_key, expected_balance) in default_public_accounts_for_wallet() {
        let account_id =
            AccountId::for_public_key(PublicKey::new_from_private_key(&private_key).value());
        let balance = ctx
            .sequencer_client()
            .get_account_balance(account_id)
            .await?;
        assert_eq!(
            balance, expected_balance,
            "public account {account_id} balance"
        );
    }

    for account in default_private_accounts_for_wallet() {
        let account_id = account.account_id();
        let commitment = ctx
            .wallet()
            .get_private_account_commitment(account_id)
            .with_context(|| format!("commitment for private account {account_id}"))?;
        assert!(
            verify_commitment_is_in_state(commitment, ctx.sequencer_client()).await,
            "private commitment for {account_id} should be in sequencer state"
        );
    }

    Ok(())
}
