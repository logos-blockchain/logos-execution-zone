#![expect(
    clippy::shadow_unrelated,
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::{str::FromStr as _, time::Duration};

use anyhow::{Context as _, Result};
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, assert_public_account_restored,
    fetch_privacy_preserving_tx, new_account, private_mention, public_mention,
    restored_private_account, send, verify_commitment_is_in_state,
};
use key_protocol::key_management::key_tree::chain_index::ChainIndex;
use lee::AccountId;
use log::info;
use sequencer_service_rpc::RpcClient as _;
use tokio::test;
use wallet::cli::{
    Command, SubcommandReturnValue, account::AccountSubcommand,
    programs::native_token_transfer::AuthTransferSubcommand,
};

#[test]
async fn sync_private_account_with_non_zero_chain_index() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let from: AccountId = ctx.existing_private_accounts()[0];

    // Key Tree shift — create 3 accounts to advance the key index
    for _ in 0..3 {
        new_account(&mut ctx, true, None).await?;
    }

    let to_account_id = new_account(&mut ctx, true, None).await?;

    // Get the keys for the newly created account
    let to_account = ctx
        .wallet()
        .storage()
        .key_chain()
        .private_account(to_account_id)
        .context("Failed to get private account")?;

    // Send to this account using claiming path (using npk and vpk instead of account ID)
    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: private_mention(from),
        to: None,
        to_npk: Some(hex::encode(to_account.key_chain.nullifier_public_key.0)),
        to_vpk: Some(hex::encode(
            to_account.key_chain.viewing_public_key.to_bytes(),
        )),
        to_keys: None,
        to_identifier: Some(to_account.kind.identifier()),
        amount: 100,
    });

    let sub_ret = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::TransactionExecuted { tx_hash } = sub_ret else {
        anyhow::bail!("Expected TransactionExecuted return value");
    };

    let tx = fetch_privacy_preserving_tx(ctx.sequencer_client(), tx_hash).await;

    // Sync the wallet to claim the new account
    let command = Command::Account(AccountSubcommand::SyncPrivate {});
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    let new_commitment1 = ctx
        .wallet()
        .get_private_account_commitment(from)
        .context("Failed to get private account commitment for sender")?;
    assert!(tx.message.commitments().contains(&new_commitment1));

    for commitment in tx.message.commitments() {
        assert!(verify_commitment_is_in_state(commitment, ctx.sequencer_client()).await);
    }

    let to_res_acc = ctx
        .wallet()
        .get_account_private(to_account_id)
        .context("Failed to get recipient's private account")?;
    assert_eq!(to_res_acc.balance, 100);

    info!("Successfully transferred using claiming path");

    Ok(())
}

#[test]
async fn restore_keys_from_seed() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let from: AccountId = ctx.existing_private_accounts()[0];

    // Create private accounts at root and /0
    let to_account_id1 = new_account(&mut ctx, true, Some(ChainIndex::root())).await?;
    let to_account_id2 = new_account(&mut ctx, true, Some(ChainIndex::from_str("/0")?)).await?;

    // Send to both private accounts
    send(
        &mut ctx,
        private_mention(from),
        private_mention(to_account_id1),
        100,
    )
    .await?;
    send(
        &mut ctx,
        private_mention(from),
        private_mention(to_account_id2),
        101,
    )
    .await?;

    let from: AccountId = ctx.existing_public_accounts()[0];

    // Create public accounts at root and /0
    let to_account_id3 = new_account(&mut ctx, false, Some(ChainIndex::root())).await?;
    let to_account_id4 = new_account(&mut ctx, false, Some(ChainIndex::from_str("/0")?)).await?;

    // Send to both public accounts
    send(
        &mut ctx,
        public_mention(from),
        public_mention(to_account_id3),
        102,
    )
    .await?;
    send(
        &mut ctx,
        public_mention(from),
        public_mention(to_account_id4),
        103,
    )
    .await?;

    info!("Preparation complete, performing keys restoration");

    // Restore keys from seed
    wallet::cli::execute_keys_restoration(ctx.wallet_mut(), 10).await?;

    // Verify restored private accounts
    let acc1 = restored_private_account(&ctx, to_account_id1, "Acc 1");
    let acc2 = restored_private_account(&ctx, to_account_id2, "Acc 2");

    // Verify restored public accounts
    assert_public_account_restored(&ctx, to_account_id3, "Acc 3");
    assert_public_account_restored(&ctx, to_account_id4, "Acc 4");

    assert_eq!(
        acc1.account.program_owner,
        programs::authenticated_transfer().id()
    );
    assert_eq!(
        acc2.account.program_owner,
        programs::authenticated_transfer().id()
    );

    assert_eq!(acc1.account.balance, 100);
    assert_eq!(acc2.account.balance, 101);

    info!("Tree checks passed, testing restored accounts can transact");

    // Test that restored accounts can send transactions
    send(
        &mut ctx,
        private_mention(to_account_id1),
        private_mention(to_account_id2),
        10,
    )
    .await?;
    send(
        &mut ctx,
        public_mention(to_account_id3),
        public_mention(to_account_id4),
        11,
    )
    .await?;

    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Verify commitments exist for private accounts
    let comm1 = ctx
        .wallet()
        .get_private_account_commitment(to_account_id1)
        .expect("Acc 1 commitment should exist");
    let comm2 = ctx
        .wallet()
        .get_private_account_commitment(to_account_id2)
        .expect("Acc 2 commitment should exist");

    assert!(verify_commitment_is_in_state(comm1, ctx.sequencer_client()).await);
    assert!(verify_commitment_is_in_state(comm2, ctx.sequencer_client()).await);

    // Verify public account balances
    let acc3 = ctx
        .sequencer_client()
        .get_account_balance(to_account_id3)
        .await?;
    let acc4 = ctx
        .sequencer_client()
        .get_account_balance(to_account_id4)
        .await?;

    assert_eq!(acc3, 91); // 102 - 11
    assert_eq!(acc4, 114); // 103 + 11

    info!("Successfully restored keys and verified transactions");

    Ok(())
}
