#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use anyhow::Result;
use integration_tests::TestContext;
use log::info;
use nssa::program::Program;
use sequencer_service_rpc::RpcClient as _;
use tokio::test;
use wallet::cli::{
    Command,
    account::{AccountSubcommand, NewSubcommand},
    execute_subcommand,
};

#[test]
async fn get_existing_account() -> Result<()> {
    let ctx = TestContext::new().await?;

    let account = ctx
        .sequencer_client()
        .get_account(ctx.existing_public_accounts()[0])
        .await?;

    assert_eq!(
        account.program_owner,
        Program::authenticated_transfer_program().id()
    );
    assert_eq!(account.balance, 10000);
    assert!(account.data.is_empty());
    assert_eq!(account.nonce.0, 0);

    info!("Successfully retrieved account with correct details");

    Ok(())
}

#[test]
async fn new_public_account_with_label() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let label = "my-test-public-account".to_owned();
    let command = Command::Account(AccountSubcommand::New(NewSubcommand::Public {
        cci: None,
        label: Some(label.clone()),
    }));

    let result = execute_subcommand(ctx.wallet_mut(), command).await?;

    // Extract the account_id from the result
    let wallet::cli::SubcommandReturnValue::RegisterAccount { account_id } = result else {
        panic!("Expected RegisterAccount return value")
    };

    // Verify the label was stored
    let stored_label = ctx
        .wallet()
        .storage()
        .labels
        .get(&account_id.to_string())
        .expect("Label should be stored for the new account");

    assert_eq!(stored_label.to_string(), label);

    info!("Successfully created public account with label");

    Ok(())
}

#[test]
async fn new_private_account_with_label() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let label = "my-test-private-account".to_owned();
    let command = Command::Account(AccountSubcommand::New(NewSubcommand::Private {
        cci: None,
        label: Some(label.clone()),
    }));

    let result = execute_subcommand(ctx.wallet_mut(), command).await?;

    // Extract the account_id from the result

    let wallet::cli::SubcommandReturnValue::RegisterAccount { account_id } = result else {
        panic!("Expected RegisterAccount return value")
    };

    // Verify the label was stored
    let stored_label = ctx
        .wallet()
        .storage()
        .labels
        .get(&account_id.to_string())
        .expect("Label should be stored for the new account");

    assert_eq!(stored_label.to_string(), label);

    info!("Successfully created private account with label");

    Ok(())
}

#[test]
async fn new_public_account_without_label() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let command = Command::Account(AccountSubcommand::New(NewSubcommand::Public {
        cci: None,
        label: None,
    }));

    let result = execute_subcommand(ctx.wallet_mut(), command).await?;

    // Extract the account_id from the result

    let wallet::cli::SubcommandReturnValue::RegisterAccount { account_id } = result else {
        panic!("Expected RegisterAccount return value")
    };

    // Verify no label was stored
    assert!(
        !ctx.wallet()
            .storage()
            .labels
            .contains_key(&account_id.to_string()),
        "No label should be stored when not provided"
    );

    info!("Successfully created public account without label");

    Ok(())
}
