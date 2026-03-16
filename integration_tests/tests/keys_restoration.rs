use std::{str::FromStr, time::Duration};

use anyhow::{Context, Result};
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, fetch_privacy_preserving_tx,
    format_private_account_id, format_public_account_id, verify_commitment_is_in_state,
};
use key_protocol::key_management::key_tree::chain_index::ChainIndex;
use log::info;
use nssa::{AccountId, program::Program};
use tokio::test;
use wallet::cli::{
    Command, SubcommandReturnValue,
    account::{AccountSubcommand, NewSubcommand},
    programs::native_token_transfer::AuthTransferSubcommand,
};

#[test]
async fn sync_private_account_with_non_zero_chain_index() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let from: AccountId = ctx.existing_private_accounts()[0];

    // Create a new private account
    let command = Command::Account(AccountSubcommand::New(NewSubcommand::Private {
        cci: None,
        label: None,
    }));

    for _ in 0..3 {
        // Key Tree shift
        // This way we have account with child index > 0.
        let result = wallet::cli::execute_subcommand(
            ctx.wallet_mut(),
            Command::Account(AccountSubcommand::New(NewSubcommand::Private {
                cci: None,
                label: None,
            })),
        )
        .await?;
        let SubcommandReturnValue::RegisterAccount { account_id: _ } = result else {
            anyhow::bail!("Expected RegisterAccount return value");
        };
    }

    let sub_ret = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: to_account_id,
    } = sub_ret
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Get the keys for the newly created account
    let (to_keys, _) = ctx
        .wallet()
        .storage()
        .user_data
        .get_private_account(to_account_id)
        .cloned()
        .context("Failed to get private account")?;

    // Send to this account using claiming path (using npk and vpk instead of account ID)
    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: format_private_account_id(from),
        to: None,
        to_npk: Some(hex::encode(to_keys.nullifer_public_key.0)),
        to_vpk: Some(hex::encode(to_keys.viewing_public_key.0)),
        amount: 100,
    });

    let sub_ret = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash } = sub_ret else {
        anyhow::bail!("Expected PrivacyPreservingTransfer return value");
    };

    let tx = fetch_privacy_preserving_tx(ctx.sequencer_client(), tx_hash).await;

    // Sync the wallet to claim the new account
    let command = Command::Account(AccountSubcommand::SyncPrivate {});
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    let new_commitment1 = ctx
        .wallet()
        .get_private_account_commitment(from)
        .context("Failed to get private account commitment for sender")?;
    assert_eq!(tx.message.new_commitments[0], new_commitment1);

    assert_eq!(tx.message.new_commitments.len(), 2);
    for commitment in tx.message.new_commitments.into_iter() {
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

    // Create first private account at root
    let command = Command::Account(AccountSubcommand::New(NewSubcommand::Private {
        cci: Some(ChainIndex::root()),
        label: None,
    }));
    let result = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: to_account_id1,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create second private account at /0
    let command = Command::Account(AccountSubcommand::New(NewSubcommand::Private {
        cci: Some(ChainIndex::from_str("/0")?),
        label: None,
    }));
    let result = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: to_account_id2,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Send to first private account
    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: format_private_account_id(from),
        to: Some(format_private_account_id(to_account_id1)),
        to_npk: None,
        to_vpk: None,
        amount: 100,
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    // Send to second private account
    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: format_private_account_id(from),
        to: Some(format_private_account_id(to_account_id2)),
        to_npk: None,
        to_vpk: None,
        amount: 101,
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    let from: AccountId = ctx.existing_public_accounts()[0];

    // Create first public account at root
    let command = Command::Account(AccountSubcommand::New(NewSubcommand::Public {
        cci: Some(ChainIndex::root()),
        label: None,
    }));
    let result = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: to_account_id3,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create second public account at /0
    let command = Command::Account(AccountSubcommand::New(NewSubcommand::Public {
        cci: Some(ChainIndex::from_str("/0")?),
        label: None,
    }));
    let result = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: to_account_id4,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Send to first public account
    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: format_public_account_id(from),
        to: Some(format_public_account_id(to_account_id3)),
        to_npk: None,
        to_vpk: None,
        amount: 102,
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    // Send to second public account
    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: format_public_account_id(from),
        to: Some(format_public_account_id(to_account_id4)),
        to_npk: None,
        to_vpk: None,
        amount: 103,
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    info!("Preparation complete, performing keys restoration");

    // Restore keys from seed
    wallet::cli::execute_keys_restoration(ctx.wallet_mut(), 10).await?;

    // Verify restored private accounts
    let acc1 = ctx
        .wallet()
        .storage()
        .user_data
        .private_key_tree
        .get_node(to_account_id1)
        .expect("Acc 1 should be restored");

    let acc2 = ctx
        .wallet()
        .storage()
        .user_data
        .private_key_tree
        .get_node(to_account_id2)
        .expect("Acc 2 should be restored");

    // Verify restored public accounts
    let _acc3 = ctx
        .wallet()
        .storage()
        .user_data
        .public_key_tree
        .get_node(to_account_id3)
        .expect("Acc 3 should be restored");

    let _acc4 = ctx
        .wallet()
        .storage()
        .user_data
        .public_key_tree
        .get_node(to_account_id4)
        .expect("Acc 4 should be restored");

    assert_eq!(
        acc1.value.1.program_owner,
        Program::authenticated_transfer_program().id()
    );
    assert_eq!(
        acc2.value.1.program_owner,
        Program::authenticated_transfer_program().id()
    );

    assert_eq!(acc1.value.1.balance, 100);
    assert_eq!(acc2.value.1.balance, 101);

    info!("Tree checks passed, testing restored accounts can transact");

    // Test that restored accounts can send transactions
    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: format_private_account_id(to_account_id1),
        to: Some(format_private_account_id(to_account_id2)),
        to_npk: None,
        to_vpk: None,
        amount: 10,
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: format_public_account_id(to_account_id3),
        to: Some(format_public_account_id(to_account_id4)),
        to_npk: None,
        to_vpk: None,
        amount: 11,
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

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

    assert_eq!(acc3.balance, 91); // 102 - 11
    assert_eq!(acc4.balance, 114); // 103 + 11

    info!("Successfully restored keys and verified transactions");

    Ok(())
}
