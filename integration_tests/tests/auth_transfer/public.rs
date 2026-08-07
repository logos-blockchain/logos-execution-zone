use std::time::Duration;

use anyhow::{Context as _, Result};
use common::transaction::LeeTransaction;
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, account_balance, new_account, public_mention, send,
};
use lee::{PublicKey, public_transaction};
use log::info;
use sequencer_service_rpc::RpcClient as _;
use tokio::test;
use wallet::{
    account::Label,
    cli::{
        CliAccountMention, Command, SubcommandReturnValue, account::AccountSubcommand,
        programs::native_token_transfer::AuthTransferSubcommand,
    },
};

#[test]
async fn successful_transfer_to_existing_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let sender = ctx.existing_public_accounts()[0];
    let receiver = ctx.existing_public_accounts()[1];

    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: public_mention(sender),
        to: Some(public_mention(receiver)),
        to_npk: None,
        to_vpk: None,
        to_keys: None,
        to_identifier: Some(0),
        amount: 100,
    });
    let result = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::TransactionExecuted { tx_hash } = result else {
        anyhow::bail!("Expected TransactionExecuted return value");
    };

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    info!("Checking correct balance move");
    let acc_1_balance = account_balance(&ctx, sender).await?;
    let acc_2_balance = account_balance(&ctx, receiver).await?;

    info!("Balance of sender: {acc_1_balance:#?}");
    info!("Balance of receiver: {acc_2_balance:#?}");

    assert_eq!(acc_1_balance, 9900);
    assert_eq!(acc_2_balance, 20100);

    // The recipient already exists, so the protocol doesn't require its signature, and the
    // wallet must never sign with a key it doesn't need to use. Assert the transfer's witness
    // set contains exactly the sender's signature, not the recipient's.
    let (tx, _block_id) = ctx
        .sequencer_client()
        .get_transaction(tx_hash)
        .await?
        .context("transfer transaction should be included in a block")?;
    let LeeTransaction::Public(tx) = tx else {
        anyhow::bail!("Expected a public transaction");
    };
    let sender_public_key = PublicKey::new_from_private_key(
        ctx.wallet()
            .get_account_public_signing_key(sender)
            .context("sender should have a signing key")?,
    );
    let signers: Vec<_> = tx
        .witness_set()
        .signatures_and_public_keys()
        .iter()
        .map(|(_, public_key)| public_key)
        .collect();
    assert_eq!(
        signers,
        vec![&sender_public_key],
        "only the sender should sign a transfer to an existing account"
    );

    Ok(())
}

#[test]
pub async fn successful_transfer_to_new_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let new_persistent_account_id = new_account(&mut ctx, false, None).await?;

    let sender = ctx.existing_public_accounts()[0];
    send(
        &mut ctx,
        public_mention(sender),
        public_mention(new_persistent_account_id),
        100,
    )
    .await?;

    info!("Checking correct balance move");
    let acc_1_balance = account_balance(&ctx, sender).await?;
    let acc_2_balance = account_balance(&ctx, new_persistent_account_id).await?;

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
        to_keys: None,
        to_identifier: Some(0),
        amount: 1_000_000,
    });

    let failed_send = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await;
    assert!(failed_send.is_err());

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    info!("Checking balances unchanged");
    let acc_1_balance = account_balance(&ctx, ctx.existing_public_accounts()[0]).await?;
    let acc_2_balance = account_balance(&ctx, ctx.existing_public_accounts()[1]).await?;

    info!("Balance of sender: {acc_1_balance:#?}");
    info!("Balance of receiver: {acc_2_balance:#?}");

    assert_eq!(acc_1_balance, 10000);
    assert_eq!(acc_2_balance, 20000);

    Ok(())
}

#[test]
async fn two_consecutive_successful_transfers() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let sender = ctx.existing_public_accounts()[0];
    let receiver = ctx.existing_public_accounts()[1];

    // First transfer
    send(
        &mut ctx,
        public_mention(sender),
        public_mention(receiver),
        100,
    )
    .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    info!("Checking correct balance move after first transfer");
    let acc_1_balance = account_balance(&ctx, sender).await?;
    let acc_2_balance = account_balance(&ctx, receiver).await?;

    info!("Balance of sender: {acc_1_balance:#?}");
    info!("Balance of receiver: {acc_2_balance:#?}");

    assert_eq!(acc_1_balance, 9900);
    assert_eq!(acc_2_balance, 20100);

    info!("First TX Success!");

    // Second transfer
    send(
        &mut ctx,
        public_mention(sender),
        public_mention(receiver),
        100,
    )
    .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    info!("Checking correct balance move after second transfer");
    let acc_1_balance = account_balance(&ctx, sender).await?;
    let acc_2_balance = account_balance(&ctx, receiver).await?;

    info!("Balance of sender: {acc_1_balance:#?}");
    info!("Balance of receiver: {acc_2_balance:#?}");

    assert_eq!(acc_1_balance, 9800);
    assert_eq!(acc_2_balance, 20200);

    info!("Second TX Success!");

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
    let sender = ctx.existing_public_accounts()[0];
    let receiver = ctx.existing_public_accounts()[1];
    send(
        &mut ctx,
        CliAccountMention::Label(label),
        public_mention(receiver),
        100,
    )
    .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    info!("Checking correct balance move");
    let acc_1_balance = account_balance(&ctx, sender).await?;
    let acc_2_balance = account_balance(&ctx, receiver).await?;

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
    let sender = ctx.existing_public_accounts()[0];
    let receiver = ctx.existing_public_accounts()[1];
    send(
        &mut ctx,
        public_mention(sender),
        CliAccountMention::Label(label),
        100,
    )
    .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    info!("Checking correct balance move");
    let acc_1_balance = account_balance(&ctx, sender).await?;
    let acc_2_balance = account_balance(&ctx, receiver).await?;

    assert_eq!(acc_1_balance, 9900);
    assert_eq!(acc_2_balance, 20100);

    info!("Successfully transferred using to_label");

    Ok(())
}

#[test]
async fn cannot_transfer_funds_from_system_faucet_account() -> Result<()> {
    let ctx = TestContext::new().await?;
    let faucet_account_id = system_accounts::faucet_account_id();

    let recipient = ctx.existing_public_accounts()[0];
    let recipient_balance_before = account_balance(&ctx, recipient).await?;
    let faucet_balance_before = account_balance(&ctx, faucet_account_id).await?;

    let amount = 1_u128;
    let message = public_transaction::Message::try_new(
        programs::authenticated_transfer().id(),
        vec![faucet_account_id, recipient],
        vec![],
        authenticated_transfer_core::Instruction::Transfer { amount },
    )?;
    let tx = lee::PublicTransaction::new(
        message,
        lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
    );
    let tx_hash = ctx
        .sequencer_client()
        .send_transaction(LeeTransaction::Public(tx))
        .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let recipient_balance_after = account_balance(&ctx, recipient).await?;
    let faucet_balance_after = account_balance(&ctx, faucet_account_id).await?;
    let tx_on_chain = ctx.sequencer_client().get_transaction(tx_hash).await?;

    assert_eq!(recipient_balance_after, recipient_balance_before);
    assert_eq!(faucet_balance_after, faucet_balance_before);
    assert!(tx_on_chain.is_none());

    Ok(())
}

#[test]
async fn cannot_execute_faucet_program() -> Result<()> {
    let ctx = TestContext::new().await?;
    let faucet_account_id = system_accounts::faucet_account_id();

    let recipient = ctx.existing_public_accounts()[0];

    let recipient_balance_before = account_balance(&ctx, recipient).await?;
    let faucet_balance_before = account_balance(&ctx, faucet_account_id).await?;

    let amount = 1_u128;
    let message = public_transaction::Message::try_new(
        programs::faucet().id(),
        vec![faucet_account_id, recipient],
        vec![],
        faucet_core::Instruction::GenesisTransferDirect { amount },
    )?;
    let tx = lee::PublicTransaction::new(
        message,
        lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
    );
    let tx_hash = ctx
        .sequencer_client()
        .send_transaction(LeeTransaction::Public(tx))
        .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let recipient_balance_after = account_balance(&ctx, recipient).await?;
    let faucet_balance_after = account_balance(&ctx, faucet_account_id).await?;
    let tx_on_chain = ctx.sequencer_client().get_transaction(tx_hash).await?;

    assert_eq!(recipient_balance_after, recipient_balance_before);
    assert_eq!(faucet_balance_after, faucet_balance_before);
    assert!(tx_on_chain.is_none());

    Ok(())
}

#[test]
async fn user_tx_that_chain_calls_faucet_is_dropped() -> Result<()> {
    let ctx = TestContext::new().await?;

    let faucet_chain_caller = test_programs::faucet_chain_caller();
    let deploy_tx = LeeTransaction::ProgramDeployment(lee::ProgramDeploymentTransaction::new(
        lee::program_deployment_transaction::Message::new(faucet_chain_caller.elf().to_owned()),
    ));
    ctx.sequencer_client().send_transaction(deploy_tx).await?;

    info!("Waiting for deploy block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let faucet_account_id = system_accounts::faucet_account_id();
    let attacker = ctx.existing_public_accounts()[0];
    let faucet_program_id = programs::faucet().id();
    let amount: u128 = 1;

    let message = public_transaction::Message::try_new(
        faucet_chain_caller.id(),
        vec![faucet_account_id, attacker],
        vec![],
        (faucet_program_id, attacker, amount),
    )?;
    let attack_tx = LeeTransaction::Public(lee::PublicTransaction::new(
        message,
        lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
    ));

    let faucet_balance_before = account_balance(&ctx, faucet_account_id).await?;
    let attacker_balance_before = account_balance(&ctx, attacker).await?;

    let tx_hash = ctx.sequencer_client().send_transaction(attack_tx).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let faucet_balance_after = account_balance(&ctx, faucet_account_id).await?;
    let attacker_balance_after = account_balance(&ctx, attacker).await?;
    let tx_on_chain = ctx.sequencer_client().get_transaction(tx_hash).await?;

    assert_eq!(faucet_balance_after, faucet_balance_before);
    assert_eq!(attacker_balance_after, attacker_balance_before);
    assert!(tx_on_chain.is_none());

    Ok(())
}
