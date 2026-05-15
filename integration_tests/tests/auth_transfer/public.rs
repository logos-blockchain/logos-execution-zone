use std::time::Duration;

use anyhow::Result;
use common::transaction::NSSATransaction;
use integration_tests::{TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, public_mention};
use log::info;
use nssa::{program::Program, public_transaction, system_faucet_account_id};
use sequencer_service_rpc::RpcClient as _;
use tokio::test;
use wallet::{
    account::Label,
    cli::{
        CliAccountMention, Command, SubcommandReturnValue,
        account::{AccountSubcommand, NewSubcommand},
        programs::native_token_transfer::AuthTransferSubcommand,
    },
};

#[test]
async fn successful_transfer_to_existing_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: public_mention(ctx.existing_public_accounts()[0]),
        to: Some(public_mention(ctx.existing_public_accounts()[1])),
        to_npk: None,
        to_vpk: None,
        to_identifier: Some(0),
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
        .key_chain()
        .public_account_ids()
        .map(|(account_id, _)| account_id)
        .find(|acc_id| {
            *acc_id != ctx.existing_public_accounts()[0]
                && *acc_id != ctx.existing_public_accounts()[1]
        })
        .expect("Failed to find newly created account in the wallet storage");

    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: public_mention(ctx.existing_public_accounts()[0]),
        to: Some(public_mention(new_persistent_account_id)),
        to_npk: None,
        to_vpk: None,
        to_identifier: Some(0),
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
        from: public_mention(ctx.existing_public_accounts()[0]),
        to: Some(public_mention(ctx.existing_public_accounts()[1])),
        to_npk: None,
        to_vpk: None,
        to_identifier: Some(0),
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
        from: public_mention(ctx.existing_public_accounts()[0]),
        to: Some(public_mention(ctx.existing_public_accounts()[1])),
        to_npk: None,
        to_vpk: None,
        to_identifier: Some(0),
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
        from: public_mention(ctx.existing_public_accounts()[0]),
        to: Some(public_mention(ctx.existing_public_accounts()[1])),
        to_npk: None,
        to_vpk: None,
        to_identifier: Some(0),
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
        account_id: public_mention(account_id),
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
    let label = Label::new("sender-label");
    let command = Command::Account(AccountSubcommand::Label {
        account_id: public_mention(ctx.existing_public_accounts()[0]),
        label: label.clone(),
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    // Send using the label instead of account ID
    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: CliAccountMention::Label(label),
        to: Some(public_mention(ctx.existing_public_accounts()[1])),
        to_npk: None,
        to_vpk: None,
        to_identifier: Some(0),
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
    let label = Label::new("receiver-label");
    let command = Command::Account(AccountSubcommand::Label {
        account_id: public_mention(ctx.existing_public_accounts()[1]),
        label: label.clone(),
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    // Send using the label for the recipient
    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: public_mention(ctx.existing_public_accounts()[0]),
        to: Some(CliAccountMention::Label(label)),
        to_npk: None,
        to_vpk: None,
        to_identifier: Some(0),
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

#[test]
async fn cannot_transfer_funds_from_system_faucet_account() -> Result<()> {
    let ctx = TestContext::new().await?;
    let faucet_account_id = system_faucet_account_id();

    let recipient = ctx.existing_public_accounts()[0];
    let recipient_balance_before = ctx
        .sequencer_client()
        .get_account_balance(recipient)
        .await?;
    let faucet_balance_before = ctx
        .sequencer_client()
        .get_account_balance(faucet_account_id)
        .await?;

    let amount = 1_u128;
    let message = public_transaction::Message::try_new(
        Program::authenticated_transfer_program().id(),
        vec![faucet_account_id, recipient],
        vec![],
        authenticated_transfer_core::Instruction::Transfer { amount },
    )?;
    let tx = nssa::PublicTransaction::new(
        message,
        nssa::public_transaction::WitnessSet::from_raw_parts(vec![]),
    );
    let tx_hash = ctx
        .sequencer_client()
        .send_transaction(NSSATransaction::Public(tx))
        .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let recipient_balance_after = ctx
        .sequencer_client()
        .get_account_balance(recipient)
        .await?;
    let faucet_balance_after = ctx
        .sequencer_client()
        .get_account_balance(faucet_account_id)
        .await?;
    let tx_on_chain = ctx.sequencer_client().get_transaction(tx_hash).await?;

    assert_eq!(recipient_balance_after, recipient_balance_before);
    assert_eq!(faucet_balance_after, faucet_balance_before);
    assert!(tx_on_chain.is_none());

    Ok(())
}

#[test]
async fn can_transfer_funds_to_system_faucet_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let faucet_account_id = system_faucet_account_id();

    let sender = ctx.existing_public_accounts()[0];
    let sender_balance_before = ctx.sequencer_client().get_account_balance(sender).await?;
    let faucet_balance_before = ctx
        .sequencer_client()
        .get_account_balance(faucet_account_id)
        .await?;

    let amount = 100_u128;
    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: public_mention(sender),
        to: Some(public_mention(faucet_account_id)),
        to_npk: None,
        to_vpk: None,
        to_identifier: Some(0),
        amount,
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let sender_balance_after = ctx.sequencer_client().get_account_balance(sender).await?;
    let faucet_balance_after = ctx
        .sequencer_client()
        .get_account_balance(faucet_account_id)
        .await?;

    assert_eq!(sender_balance_after, sender_balance_before - amount);
    assert_eq!(faucet_balance_after, faucet_balance_before + amount);

    Ok(())
}

#[test]
async fn cannot_execute_faucet_program() -> Result<()> {
    let ctx = TestContext::new().await?;
    let faucet_account_id = system_faucet_account_id();

    let recipient = ctx.existing_public_accounts()[0];
    let vault_program_id = Program::vault().id();
    let recipient_vault_id = vault_core::compute_vault_account_id(vault_program_id, recipient);

    let recipient_balance_before = ctx
        .sequencer_client()
        .get_account_balance(recipient)
        .await?;
    let faucet_balance_before = ctx
        .sequencer_client()
        .get_account_balance(faucet_account_id)
        .await?;

    let amount = 1_u128;
    let message = public_transaction::Message::try_new(
        Program::faucet().id(),
        vec![faucet_account_id, recipient_vault_id],
        vec![],
        faucet_core::Instruction::Transfer {
            vault_program_id,
            recipient_id: recipient,
            amount,
        },
    )?;
    let tx = nssa::PublicTransaction::new(
        message,
        nssa::public_transaction::WitnessSet::from_raw_parts(vec![]),
    );
    let tx_hash = ctx
        .sequencer_client()
        .send_transaction(NSSATransaction::Public(tx))
        .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let recipient_balance_after = ctx
        .sequencer_client()
        .get_account_balance(recipient)
        .await?;
    let faucet_balance_after = ctx
        .sequencer_client()
        .get_account_balance(faucet_account_id)
        .await?;
    let tx_on_chain = ctx.sequencer_client().get_transaction(tx_hash).await?;

    assert_eq!(recipient_balance_after, recipient_balance_before);
    assert_eq!(faucet_balance_after, faucet_balance_before);
    assert!(tx_on_chain.is_none());

    Ok(())
}
