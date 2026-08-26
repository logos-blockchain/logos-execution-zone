#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::time::Duration;

use anyhow::Result;
use indexer_service_rpc::RpcClient as _;
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext,
    config::INITIAL_PUBLIC_BALANCES_FOR_WALLET, private_mention, public_mention,
    utils::{
        account_balance, assert_private_commitment_in_state, get_account, send,
        wait_for_indexer_to_catch_up,
    },
};
use lee::AccountId;

#[tokio::test]
async fn indexer_state_consistency() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let (acc0, acc1) = (
        ctx.existing_public_accounts()[0],
        ctx.existing_public_accounts()[1],
    );
    send(&mut ctx, public_mention(acc0), public_mention(acc1), 100).await?;

    log::info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    log::info!("Checking correct balance move");
    let acc_1_balance = account_balance(&ctx, ctx.existing_public_accounts()[0]).await?;
    let acc_2_balance = account_balance(&ctx, ctx.existing_public_accounts()[1]).await?;

    log::info!("Balance of sender: {acc_1_balance:#?}");
    log::info!("Balance of receiver: {acc_2_balance:#?}");

    // Charged transfer: the recipient gains exactly the amount; the sender
    // pays the amount plus a positive fee within the protocol ceiling.
    assert_eq!(acc_2_balance, INITIAL_PUBLIC_BALANCES_FOR_WALLET[1] + 100);
    let fee = (INITIAL_PUBLIC_BALANCES_FOR_WALLET[0] - 100)
        .checked_sub(acc_1_balance)
        .expect("sender must be debited at least the transferred amount");
    assert!(
        fee > 0 && fee <= wallet::DEFAULT_MAX_FEE,
        "the sender must pay a positive fee within the protocol ceiling, got {fee}",
    );

    let from: AccountId = ctx.existing_private_accounts()[0];
    let to: AccountId = ctx.existing_private_accounts()[1];

    send(&mut ctx, private_mention(from), private_mention(to), 100).await?;

    log::info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    assert_private_commitment_in_state(&ctx, from, "sender").await?;
    assert_private_commitment_in_state(&ctx, to, "receiver").await?;

    log::info!("Successfully transferred privately to owned account");

    log::info!("Waiting for indexer to parse blocks");
    wait_for_indexer_to_catch_up(&ctx).await?;

    let acc1_ind_state = ctx
        .indexer_client()
        .get_account(ctx.existing_public_accounts()[0].into())
        .await
        .unwrap();
    let acc2_ind_state = ctx
        .indexer_client()
        .get_account(ctx.existing_public_accounts()[1].into())
        .await
        .unwrap();

    log::info!("Checking correct state transition");
    let acc1_seq_state = get_account(&ctx, ctx.existing_public_accounts()[0]).await?;
    let acc2_seq_state = get_account(&ctx, ctx.existing_public_accounts()[1]).await?;

    assert_eq!(acc1_ind_state, acc1_seq_state.into());
    assert_eq!(acc2_ind_state, acc2_seq_state.into());

    // ToDo: Check private state transition

    Ok(())
}
