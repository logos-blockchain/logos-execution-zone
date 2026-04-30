use std::time::Duration;

use anyhow::{Context as _, Result};
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, fetch_privacy_preserving_tx,
    format_private_account_id, format_public_account_id, verify_commitment_is_in_state,
};
use log::info;
use nssa::{AccountId, program::Program};
use nssa_core::{NullifierPublicKey, encryption::shared_key_derivation::Secp256k1Point};
use sequencer_service_rpc::RpcClient as _;
use tokio::test;
use wallet::cli::{
    Command, SubcommandReturnValue,
    account::{AccountSubcommand, NewSubcommand},
    programs::native_token_transfer::AuthTransferSubcommand,
};

#[test]
async fn private_transfer_to_owned_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let from: AccountId = ctx.existing_private_accounts()[0];
    let to: AccountId = ctx.existing_private_accounts()[1];

    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: Some(format_private_account_id(from)),
        from_label: None,
        to: Some(format_private_account_id(to)),
        to_label: None,
        to_npk: None,
        to_vpk: None,
        to_identifier: Some(0),
        amount: 100,
        to_key_path: None,
        from_key_path: None,
    });

    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let new_commitment1 = ctx
        .wallet()
        .get_private_account_commitment(from)
        .context("Failed to get private account commitment for sender")?;
    assert!(verify_commitment_is_in_state(new_commitment1, ctx.sequencer_client()).await);

    let new_commitment2 = ctx
        .wallet()
        .get_private_account_commitment(to)
        .context("Failed to get private account commitment for receiver")?;
    assert!(verify_commitment_is_in_state(new_commitment2, ctx.sequencer_client()).await);

    info!("Successfully transferred privately to owned account");

    Ok(())
}

#[test]
async fn private_transfer_to_foreign_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let from: AccountId = ctx.existing_private_accounts()[0];
    let to_npk = NullifierPublicKey([42; 32]);
    let to_npk_string = hex::encode(to_npk.0);
    let to_vpk = Secp256k1Point::from_scalar(to_npk.0);

    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: Some(format_private_account_id(from)),
        from_label: None,
        to: None,
        to_label: None,
        to_npk: Some(to_npk_string),
        to_vpk: Some(hex::encode(to_vpk.0)),
        to_identifier: Some(0),
        amount: 100,
        to_key_path: None,
        from_key_path: None,
    });

    let result = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash } = result else {
        anyhow::bail!("Expected PrivacyPreservingTransfer return value");
    };

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let new_commitment1 = ctx
        .wallet()
        .get_private_account_commitment(from)
        .context("Failed to get private account commitment for sender")?;

    let tx = fetch_privacy_preserving_tx(ctx.sequencer_client(), tx_hash).await;
    assert_eq!(tx.message.new_commitments[0], new_commitment1);

    assert_eq!(tx.message.new_commitments.len(), 2);
    for commitment in tx.message.new_commitments {
        assert!(verify_commitment_is_in_state(commitment, ctx.sequencer_client()).await);
    }

    info!("Successfully transferred privately to foreign account");

    Ok(())
}

#[test]
async fn deshielded_transfer_to_public_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let from: AccountId = ctx.existing_private_accounts()[0];
    let to: AccountId = ctx.existing_public_accounts()[1];

    // Check initial balance of the private sender
    let from_acc = ctx
        .wallet()
        .get_account_private(from)
        .context("Failed to get sender's private account")?;
    assert_eq!(from_acc.balance, 10000);

    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: Some(format_private_account_id(from)),
        from_label: None,
        to: Some(format_public_account_id(to)),
        to_label: None,
        to_npk: None,
        to_vpk: None,
        to_identifier: Some(0),
        amount: 100,
        to_key_path: None,
        from_key_path: None,
    });

    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let from_acc = ctx
        .wallet()
        .get_account_private(from)
        .context("Failed to get sender's private account")?;
    let new_commitment = ctx
        .wallet()
        .get_private_account_commitment(from)
        .context("Failed to get private account commitment")?;
    assert!(verify_commitment_is_in_state(new_commitment, ctx.sequencer_client()).await);

    let acc_2_balance = ctx.sequencer_client().get_account_balance(to).await?;

    assert_eq!(from_acc.balance, 9900);
    assert_eq!(acc_2_balance, 20100);

    info!("Successfully deshielded transfer to public account");

    Ok(())
}

#[test]
async fn private_transfer_to_owned_account_using_claiming_path() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let from: AccountId = ctx.existing_private_accounts()[0];

    // Create a new private account
    let command = Command::Account(AccountSubcommand::New(NewSubcommand::Private {
        cci: None,
        label: None,
    }));

    let sub_ret = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: to_account_id,
    } = sub_ret
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Get the keys for the newly created account
    let (to_keys, _, to_identifier) = ctx
        .wallet()
        .storage()
        .user_data
        .get_private_account(to_account_id)
        .context("Failed to get private account")?;

    // Send to this account using claiming path (using npk and vpk instead of account ID)
    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: Some(format_private_account_id(from)),
        from_label: None,
        to: None,
        to_label: None,
        to_npk: Some(hex::encode(to_keys.nullifier_public_key.0)),
        to_vpk: Some(hex::encode(to_keys.viewing_public_key.0)),
        to_identifier: Some(to_identifier),
        amount: 100,
        to_key_path: None,
        from_key_path: None,
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
    for commitment in tx.message.new_commitments {
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
async fn shielded_transfer_to_owned_private_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let from: AccountId = ctx.existing_public_accounts()[0];
    let to: AccountId = ctx.existing_private_accounts()[1];

    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: Some(format_public_account_id(from)),
        from_label: None,
        to: Some(format_private_account_id(to)),
        to_label: None,
        to_npk: None,
        to_vpk: None,
        to_identifier: Some(0),
        amount: 100,
        to_key_path: None,
        from_key_path: None,
    });

    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let acc_to = ctx
        .wallet()
        .get_account_private(to)
        .context("Failed to get receiver's private account")?;
    let new_commitment = ctx
        .wallet()
        .get_private_account_commitment(to)
        .context("Failed to get receiver's commitment")?;
    assert!(verify_commitment_is_in_state(new_commitment, ctx.sequencer_client()).await);

    let acc_from_balance = ctx.sequencer_client().get_account_balance(from).await?;

    assert_eq!(acc_from_balance, 9900);
    assert_eq!(acc_to.balance, 20100);

    info!("Successfully shielded transfer to owned private account");

    Ok(())
}

#[test]
async fn shielded_transfer_to_foreign_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let to_npk = NullifierPublicKey([42; 32]);
    let to_npk_string = hex::encode(to_npk.0);
    let to_vpk = Secp256k1Point::from_scalar(to_npk.0);
    let from: AccountId = ctx.existing_public_accounts()[0];

    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: Some(format_public_account_id(from)),
        from_label: None,
        to: None,
        to_label: None,
        to_npk: Some(to_npk_string),
        to_vpk: Some(hex::encode(to_vpk.0)),
        to_identifier: Some(0),
        amount: 100,
        to_key_path: None,
        from_key_path: None,
    });

    let result = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash } = result else {
        anyhow::bail!("Expected PrivacyPreservingTransfer return value");
    };

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let tx = fetch_privacy_preserving_tx(ctx.sequencer_client(), tx_hash).await;

    let acc_1_balance = ctx.sequencer_client().get_account_balance(from).await?;

    assert!(
        verify_commitment_is_in_state(
            tx.message.new_commitments[0].clone(),
            ctx.sequencer_client()
        )
        .await
    );

    assert_eq!(acc_1_balance, 9900);

    info!("Successfully shielded transfer to foreign account");

    Ok(())
}

#[test]
#[ignore = "Flaky, TODO: #197"]
async fn private_transfer_to_owned_account_continuous_run_path() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    // NOTE: This test needs refactoring - continuous run mode doesn't work well with TestContext
    // The original implementation spawned wallet::cli::execute_continuous_run() in background
    // but this conflicts with TestContext's wallet management

    let from: AccountId = ctx.existing_private_accounts()[0];

    // Create a new private account
    let command = Command::Account(AccountSubcommand::New(NewSubcommand::Private {
        cci: None,
        label: None,
    }));
    let sub_ret = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    let SubcommandReturnValue::RegisterAccount {
        account_id: to_account_id,
    } = sub_ret
    else {
        anyhow::bail!("Failed to register account");
    };

    // Get the newly created account's keys
    let (to_keys, _, to_identifier) = ctx
        .wallet()
        .storage()
        .user_data
        .get_private_account(to_account_id)
        .context("Failed to get private account")?;

    // Send transfer using nullifier and  viewing public keys
    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: Some(format_private_account_id(from)),
        from_label: None,
        to: None,
        to_label: None,
        to_npk: Some(hex::encode(to_keys.nullifier_public_key.0)),
        to_vpk: Some(hex::encode(to_keys.viewing_public_key.0)),
        to_identifier: Some(to_identifier),
        amount: 100,
        to_key_path: None,
        from_key_path: None,
    });

    let sub_ret = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash } = sub_ret else {
        anyhow::bail!("Failed to send transaction");
    };

    let tx = fetch_privacy_preserving_tx(ctx.sequencer_client(), tx_hash).await;

    info!("Waiting for next blocks to check if continuous run fetches account");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Verify commitments are in state
    assert_eq!(tx.message.new_commitments.len(), 2);
    for commitment in tx.message.new_commitments {
        assert!(verify_commitment_is_in_state(commitment, ctx.sequencer_client()).await);
    }

    // Verify receiver account balance
    let to_res_acc = ctx
        .wallet()
        .get_account_private(to_account_id)
        .context("Failed to get receiver account")?;

    assert_eq!(to_res_acc.balance, 100);

    Ok(())
}

#[test]
async fn initialize_private_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let command = Command::Account(AccountSubcommand::New(NewSubcommand::Private {
        cci: None,
        label: None,
    }));
    let result = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::RegisterAccount { account_id } = result else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    let command = Command::AuthTransfer(AuthTransferSubcommand::Init {
        account_id: Some(format_private_account_id(account_id)),
        account_label: None,
        key_path: None,
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    info!("Syncing private accounts");
    let command = Command::Account(AccountSubcommand::SyncPrivate {});
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    let new_commitment = ctx
        .wallet()
        .get_private_account_commitment(account_id)
        .context("Failed to get private account commitment")?;
    assert!(verify_commitment_is_in_state(new_commitment, ctx.sequencer_client()).await);

    let account = ctx
        .wallet()
        .get_account_private(account_id)
        .context("Failed to get private account")?;

    assert_eq!(
        account.program_owner,
        Program::authenticated_transfer_program().id()
    );
    assert_eq!(account.balance, 0);
    assert!(account.data.is_empty());

    info!("Successfully initialized private account");

    Ok(())
}

#[test]
async fn private_transfer_using_from_label() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let from: AccountId = ctx.existing_private_accounts()[0];
    let to: AccountId = ctx.existing_private_accounts()[1];

    // Assign a label to the sender account
    let label = "private-sender-label".to_owned();
    let command = Command::Account(AccountSubcommand::Label {
        account_id: Some(format_private_account_id(from)),
        account_label: None,
        label: label.clone(),
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    // Send using the label instead of account ID
    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: None,
        from_label: Some(label),
        to: Some(format_private_account_id(to)),
        to_label: None,
        to_npk: None,
        to_vpk: None,
        to_identifier: Some(0),
        amount: 100,
        from_key_path: None,
        to_key_path: None,
    });

    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let new_commitment1 = ctx
        .wallet()
        .get_private_account_commitment(from)
        .context("Failed to get private account commitment for sender")?;
    assert!(verify_commitment_is_in_state(new_commitment1, ctx.sequencer_client()).await);

    let new_commitment2 = ctx
        .wallet()
        .get_private_account_commitment(to)
        .context("Failed to get private account commitment for receiver")?;
    assert!(verify_commitment_is_in_state(new_commitment2, ctx.sequencer_client()).await);

    info!("Successfully transferred privately using from_label");

    Ok(())
}

#[test]
async fn initialize_private_account_using_label() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    // Create a new private account with a label
    let label = "init-private-label".to_owned();
    let command = Command::Account(AccountSubcommand::New(NewSubcommand::Private {
        cci: None,
        label: Some(label.clone()),
    }));
    let result = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::RegisterAccount { account_id } = result else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Initialize using the label instead of account ID
    let command = Command::AuthTransfer(AuthTransferSubcommand::Init {
        account_id: None,
        account_label: Some(label),
        key_path: None,
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let command = Command::Account(AccountSubcommand::SyncPrivate {});
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    let new_commitment = ctx
        .wallet()
        .get_private_account_commitment(account_id)
        .context("Failed to get private account commitment")?;
    assert!(verify_commitment_is_in_state(new_commitment, ctx.sequencer_client()).await);

    let account = ctx
        .wallet()
        .get_account_private(account_id)
        .context("Failed to get private account")?;

    assert_eq!(
        account.program_owner,
        Program::authenticated_transfer_program().id()
    );

    info!("Successfully initialized private account using label");

    Ok(())
}

#[test]
async fn shielded_transfers_to_two_identifiers_same_npk() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    // Both transfers below will target this same node with distinct identifiers.
    let chain_index = ctx.wallet_mut().create_private_accounts_key(None);
    let (npk, vpk) = {
        let node = ctx
            .wallet()
            .storage()
            .user_data
            .private_key_tree
            .key_map
            .get(&chain_index)
            .expect("node was just inserted");
        let key_chain = &node.value.0;
        (
            key_chain.nullifier_public_key,
            key_chain.viewing_public_key.clone(),
        )
    };

    let npk_hex = hex::encode(npk.0);
    let vpk_hex = hex::encode(vpk.0);

    let identifier_1 = 1_u128;
    let identifier_2 = 2_u128;

    let sender_0: AccountId = ctx.existing_public_accounts()[0];
    let sender_1: AccountId = ctx.existing_public_accounts()[1];

    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::AuthTransfer(AuthTransferSubcommand::Send {
            from: Some(format_public_account_id(sender_0)),
            from_label: None,
            to: None,
            to_label: None,
            to_npk: Some(npk_hex.clone()),
            to_vpk: Some(vpk_hex.clone()),
            to_identifier: Some(identifier_1),
            amount: 100,
        }),
    )
    .await?;

    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::AuthTransfer(AuthTransferSubcommand::Send {
            from: Some(format_public_account_id(sender_1)),
            from_label: None,
            to: None,
            to_label: None,
            to_npk: Some(npk_hex),
            to_vpk: Some(vpk_hex),
            to_identifier: Some(identifier_2),
            amount: 200,
        }),
    )
    .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::SyncPrivate {}),
    )
    .await?;

    // Both accounts must be discovered with the correct balances.
    let account_id_1 = AccountId::from((&npk, identifier_1));
    let acc_1 = ctx
        .wallet()
        .get_account_private(account_id_1)
        .context("account for identifier 1 not found after sync")?;
    assert_eq!(acc_1.balance, 100);

    let account_id_2 = AccountId::from((&npk, identifier_2));
    let acc_2 = ctx
        .wallet()
        .get_account_private(account_id_2)
        .context("account for identifier 2 not found after sync")?;
    assert_eq!(acc_2.balance, 200);

    // Both account ids must resolve to the same key node.
    let tree = &ctx.wallet().storage().user_data.private_key_tree;
    let ci_1 = tree
        .account_id_map
        .get(&account_id_1)
        .context("account_id_1 missing from private_key_tree.account_id_map")?;
    let ci_2 = tree
        .account_id_map
        .get(&account_id_2)
        .context("account_id_2 missing from private_key_tree.account_id_map")?;
    assert_eq!(
        ci_1, ci_2,
        "identifiers 1 and 2 under the same NPK must share a single chain_index"
    );
    assert_eq!(
        ci_1, &chain_index,
        "both accounts must resolve to the key node created at the start of the test"
    );

    info!("Successfully transferred to two distinct identifiers under the same NPK");

    Ok(())
}
