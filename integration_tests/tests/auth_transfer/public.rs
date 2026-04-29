use std::time::Duration;

use anyhow::Result;
use integration_tests::{TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, format_public_account_id};
use log::info;
use nssa::program::Program;
use sequencer_service_rpc::RpcClient as _;
use tokio::test;
use wallet::cli::{
    Command, SubcommandReturnValue,
    account::{AccountSubcommand, NewSubcommand},
    programs::native_token_transfer::AuthTransferSubcommand,
};

#[test]
async fn successful_transfer_to_existing_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: Some(format_public_account_id(ctx.existing_public_accounts()[0])),
        from_label: None,
        to: Some(format_public_account_id(ctx.existing_public_accounts()[1])),
        to_label: None,
        to_npk: None,
        to_vpk: None,
        amount: 100,
    });

    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    info!("Checking correct balance move");
    let acc_1_balance = ctx
        .sequencer_client()
        .get_account_balance(ctx.existing_public_accounts()[0])
        .await?;
    let acc_2_balance = ctx
        .sequencer_client()
        .get_account_balance(ctx.existing_public_accounts()[1])
        .await?;

    info!("Balance of sender: {acc_1_balance:#?}");
    info!("Balance of receiver: {acc_2_balance:#?}");

    assert_eq!(acc_1_balance, 9900);
    assert_eq!(acc_2_balance, 20100);

    Ok(())
}

#[test]
pub async fn successful_transfer_to_new_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let command = Command::Account(AccountSubcommand::New(NewSubcommand::Public {
        cci: None,
        label: None,
    }));

    wallet::cli::execute_subcommand(ctx.wallet_mut(), command)
        .await
        .unwrap();

    let new_persistent_account_id = ctx
        .wallet()
        .storage()
        .user_data
        .account_ids()
        .find(|acc_id| {
            *acc_id != ctx.existing_public_accounts()[0]
                && *acc_id != ctx.existing_public_accounts()[1]
        })
        .expect("Failed to find newly created account in the wallet storage");

    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: Some(format_public_account_id(ctx.existing_public_accounts()[0])),
        from_label: None,
        to: Some(format_public_account_id(new_persistent_account_id)),
        to_label: None,
        to_npk: None,
        to_vpk: None,
        amount: 100,
    });

    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    info!("Checking correct balance move");
    let acc_1_balance = ctx
        .sequencer_client()
        .get_account_balance(ctx.existing_public_accounts()[0])
        .await?;
    let acc_2_balance = ctx
        .sequencer_client()
        .get_account_balance(new_persistent_account_id)
        .await?;

    info!("Balance of sender: {acc_1_balance:#?}");
    info!("Balance of receiver: {acc_2_balance:#?}");

    assert_eq!(acc_1_balance, 9900);
    assert_eq!(acc_2_balance, 100);

    Ok(())
}

#[test]
async fn failed_transfer_with_insufficient_balance() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: Some(format_public_account_id(ctx.existing_public_accounts()[0])),
        from_label: None,
        to: Some(format_public_account_id(ctx.existing_public_accounts()[1])),
        to_label: None,
        to_npk: None,
        to_vpk: None,
        amount: 1_000_000,
    });

    let failed_send = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await;
    assert!(failed_send.is_err());

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    info!("Checking balances unchanged");
    let acc_1_balance = ctx
        .sequencer_client()
        .get_account_balance(ctx.existing_public_accounts()[0])
        .await?;
    let acc_2_balance = ctx
        .sequencer_client()
        .get_account_balance(ctx.existing_public_accounts()[1])
        .await?;

    info!("Balance of sender: {acc_1_balance:#?}");
    info!("Balance of receiver: {acc_2_balance:#?}");

    assert_eq!(acc_1_balance, 10000);
    assert_eq!(acc_2_balance, 20000);

    Ok(())
}

#[test]
async fn two_consecutive_successful_transfers() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    // First transfer
    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: Some(format_public_account_id(ctx.existing_public_accounts()[0])),
        from_label: None,
        to: Some(format_public_account_id(ctx.existing_public_accounts()[1])),
        to_label: None,
        to_npk: None,
        to_vpk: None,
        amount: 100,
    });

    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    info!("Checking correct balance move after first transfer");
    let acc_1_balance = ctx
        .sequencer_client()
        .get_account_balance(ctx.existing_public_accounts()[0])
        .await?;
    let acc_2_balance = ctx
        .sequencer_client()
        .get_account_balance(ctx.existing_public_accounts()[1])
        .await?;

    info!("Balance of sender: {acc_1_balance:#?}");
    info!("Balance of receiver: {acc_2_balance:#?}");

    assert_eq!(acc_1_balance, 9900);
    assert_eq!(acc_2_balance, 20100);

    info!("First TX Success!");

    // Second transfer
    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: Some(format_public_account_id(ctx.existing_public_accounts()[0])),
        from_label: None,
        to: Some(format_public_account_id(ctx.existing_public_accounts()[1])),
        to_label: None,
        to_npk: None,
        to_vpk: None,
        amount: 100,
    });

    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    info!("Checking correct balance move after second transfer");
    let acc_1_balance = ctx
        .sequencer_client()
        .get_account_balance(ctx.existing_public_accounts()[0])
        .await?;
    let acc_2_balance = ctx
        .sequencer_client()
        .get_account_balance(ctx.existing_public_accounts()[1])
        .await?;

    info!("Balance of sender: {acc_1_balance:#?}");
    info!("Balance of receiver: {acc_2_balance:#?}");

    assert_eq!(acc_1_balance, 9800);
    assert_eq!(acc_2_balance, 20200);

    info!("Second TX Success!");

    Ok(())
}

#[test]
async fn initialize_public_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let command = Command::Account(AccountSubcommand::New(NewSubcommand::Public {
        cci: None,
        label: None,
    }));
    let result = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::RegisterAccount { account_id } = result else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    let command = Command::AuthTransfer(AuthTransferSubcommand::Init {
        account_id: Some(format_public_account_id(account_id)),
        account_label: None,
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    info!("Checking correct execution");
    let account = ctx.sequencer_client().get_account(account_id).await?;

    assert_eq!(
        account.program_owner,
        Program::authenticated_transfer_program().id()
    );
    assert_eq!(account.balance, 0);
    assert_eq!(account.nonce.0, 1);
    assert!(account.data.is_empty());

    info!("Successfully initialized public account");

    Ok(())
}

#[test]
async fn successful_transfer_using_from_label() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    // Assign a label to the sender account
    let label = "sender-label".to_owned();
    let command = Command::Account(AccountSubcommand::Label {
        account_id: Some(format_public_account_id(ctx.existing_public_accounts()[0])),
        account_label: None,
        label: label.clone(),
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    // Send using the label instead of account ID
    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: None,
        from_label: Some(label),
        to: Some(format_public_account_id(ctx.existing_public_accounts()[1])),
        to_label: None,
        to_npk: None,
        to_vpk: None,
        amount: 100,
    });

    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    info!("Checking correct balance move");
    let acc_1_balance = ctx
        .sequencer_client()
        .get_account_balance(ctx.existing_public_accounts()[0])
        .await?;
    let acc_2_balance = ctx
        .sequencer_client()
        .get_account_balance(ctx.existing_public_accounts()[1])
        .await?;

    assert_eq!(acc_1_balance, 9900);
    assert_eq!(acc_2_balance, 20100);

    info!("Successfully transferred using from_label");

    Ok(())
}

#[test]
async fn successful_transfer_using_to_label() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    // Assign a label to the receiver account
    let label = "receiver-label".to_owned();
    let command = Command::Account(AccountSubcommand::Label {
        account_id: Some(format_public_account_id(ctx.existing_public_accounts()[1])),
        account_label: None,
        label: label.clone(),
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    // Send using the label for the recipient
    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: Some(format_public_account_id(ctx.existing_public_accounts()[0])),
        from_label: None,
        to: None,
        to_label: Some(label),
        to_npk: None,
        to_vpk: None,
        amount: 100,
    });

    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    info!("Checking correct balance move");
    let acc_1_balance = ctx
        .sequencer_client()
        .get_account_balance(ctx.existing_public_accounts()[0])
        .await?;
    let acc_2_balance = ctx
        .sequencer_client()
        .get_account_balance(ctx.existing_public_accounts()[1])
        .await?;

    assert_eq!(acc_1_balance, 9900);
    assert_eq!(acc_2_balance, 20100);

    info!("Successfully transferred using to_label");

    Ok(())
}
