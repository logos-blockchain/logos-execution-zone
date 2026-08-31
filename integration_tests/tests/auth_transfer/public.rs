use std::time::Duration;

use anyhow::{Context as _, Result};
use common::transaction::LeeTransaction;
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, public_mention,
    utils::{account_balance, get_account, new_account, send, send_claiming_new_account},
};
use lee::{PublicKey, public_transaction};
use sequencer_service_rpc::RpcClient as _;
use tokio::test;
use wallet::{
    AccountIdentity, DEFAULT_MAX_FEE, ExecutionFailureKind,
    account::Label,
    cli::{
        CliAccountMention, Command, SubcommandReturnValue, account::AccountSubcommand,
        programs::native_token_transfer::AuthTransferSubcommand,
    },
    program_facades::native_token_transfer::NativeTokenTransfer,
};

/// The sender's post-transfer balance is `before - amount - fee` where the
/// fee depends on metered cycles, so sender assertions are relative (a
/// positive fee was paid) while recipient assertions stay exact.
fn assert_sender_paid_fee(before: u128, after: u128, amount_sent: u128) {
    let fee = before
        .checked_sub(amount_sent)
        .and_then(|rest| rest.checked_sub(after))
        .expect("sender balance must drop by at least the transferred amount");
    assert!(
        fee > 0 && fee <= DEFAULT_MAX_FEE,
        "a charged transfer must pay a fee within the protocol ceiling, got {fee}"
    );
}

#[test]
async fn successful_transfer_to_existing_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let sender = ctx.existing_public_accounts()[0];
    let receiver = ctx.existing_public_accounts()[1];
    let sender_before = account_balance(&ctx, sender).await?;
    let receiver_before = account_balance(&ctx, receiver).await?;

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

    log::info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    log::info!("Checking correct balance move");
    let acc_1_balance = account_balance(&ctx, sender).await?;
    let acc_2_balance = account_balance(&ctx, receiver).await?;

    log::info!("Balance of sender: {acc_1_balance:#?}");
    log::info!("Balance of receiver: {acc_2_balance:#?}");

    assert_eq!(acc_2_balance, receiver_before + 100);
    assert_sender_paid_fee(sender_before, acc_1_balance, 100);

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
    let sender_before = account_balance(&ctx, sender).await?;
    // The wallet CLI never signs with the recipient's key, but claiming this fresh account
    // requires it, so bypass the CLI for this one send.
    send_claiming_new_account(&mut ctx, sender, new_persistent_account_id, 100).await?;

    log::info!("Checking correct balance move");
    let acc_1_balance = account_balance(&ctx, sender).await?;
    let acc_2_balance = account_balance(&ctx, new_persistent_account_id).await?;

    log::info!("Balance of sender: {acc_1_balance:#?}");
    log::info!("Balance of receiver: {acc_2_balance:#?}");

    assert_eq!(acc_2_balance, 100);
    assert_sender_paid_fee(sender_before, acc_1_balance, 100);

    Ok(())
}

/// A transfer beyond the sender's balance is refused by the wallet before it
/// ever reaches the sequencer: the native-transfer facade balance-checks the
/// amount client-side and returns `InsufficientFundsError`. Nothing is
/// submitted, so nothing moves, nothing is charged, and no nonce burns.
///
/// A raw over-balance transfer that bypassed this check and reached settlement
/// would be *charged-reverted*, not dropped (the guest panics inside metered
/// execution, which `is_chargeable` keeps and reverts) — that path is covered
/// at the settlement level by
/// `chain_state`'s `a_charged_action_that_reverts_is_charged_not_block_rejected`.
#[test]
async fn transfer_beyond_balance_is_refused_client_side() -> Result<()> {
    let ctx = TestContext::new().await?;

    let sender = ctx.existing_public_accounts()[0];
    let receiver = ctx.existing_public_accounts()[1];
    let sender_before = account_balance(&ctx, sender).await?;
    let receiver_before = account_balance(&ctx, receiver).await?;
    let sender_nonce_before = get_account(&ctx, sender).await?.nonce.0;

    let refused = NativeTokenTransfer(ctx.wallet())
        .send_public_transfer(
            AccountIdentity::Public(sender),
            AccountIdentity::Public(receiver),
            sender_before * 2,
        )
        .await;
    assert!(
        matches!(refused, Err(ExecutionFailureKind::InsufficientFundsError)),
        "an over-balance transfer must be refused client-side, got: {refused:?}",
    );

    log::info!("Checking nothing was submitted: no move, no charge, no nonce burn");
    let sender_after = account_balance(&ctx, sender).await?;
    let receiver_after = account_balance(&ctx, receiver).await?;
    let sender_nonce_after = get_account(&ctx, sender).await?.nonce.0;

    assert_eq!(receiver_after, receiver_before, "nothing was transferred");
    assert_eq!(
        sender_after, sender_before,
        "a refused transfer must not be charged",
    );
    assert_eq!(
        sender_nonce_after, sender_nonce_before,
        "a refused transfer must not consume the replay nonce",
    );

    Ok(())
}

#[test]
async fn two_consecutive_successful_transfers() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let sender = ctx.existing_public_accounts()[0];
    let receiver = ctx.existing_public_accounts()[1];
    let sender_before = account_balance(&ctx, sender).await?;
    let receiver_before = account_balance(&ctx, receiver).await?;

    // First transfer
    send(
        &mut ctx,
        public_mention(sender),
        public_mention(receiver),
        100,
    )
    .await?;

    log::info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    log::info!("Checking correct balance move after first transfer");
    let acc_1_balance = account_balance(&ctx, sender).await?;
    let acc_2_balance = account_balance(&ctx, receiver).await?;

    log::info!("Balance of sender: {acc_1_balance:#?}");
    log::info!("Balance of receiver: {acc_2_balance:#?}");

    assert_eq!(acc_2_balance, receiver_before + 100);
    assert_sender_paid_fee(sender_before, acc_1_balance, 100);
    let sender_after_first = acc_1_balance;

    log::info!("First TX Success!");

    // Second transfer
    send(
        &mut ctx,
        public_mention(sender),
        public_mention(receiver),
        100,
    )
    .await?;

    log::info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    log::info!("Checking correct balance move after second transfer");
    let acc_1_balance = account_balance(&ctx, sender).await?;
    let acc_2_balance = account_balance(&ctx, receiver).await?;

    log::info!("Balance of sender: {acc_1_balance:#?}");
    log::info!("Balance of receiver: {acc_2_balance:#?}");

    assert_eq!(acc_2_balance, receiver_before + 200);
    assert_sender_paid_fee(sender_after_first, acc_1_balance, 100);

    log::info!("Second TX Success!");

    Ok(())
}

/// A fresh account holds nothing, so it cannot pay the fee to claim itself:
/// the wallet designates the transaction's own signer as its fee payer, and
/// admission refuses the submission (`PayerCannotFund`). Bootstrap paths for
/// a new account are a claiming transfer from a funded account (see
/// `successful_transfer_to_new_account`) or a fee-exempt full vault sweep.
#[test]
async fn fresh_account_cannot_pay_to_initialize_itself() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let account_id = new_account(&mut ctx, false, None).await?;

    let command = Command::AuthTransfer(AuthTransferSubcommand::Init {
        account_id: public_mention(account_id),
    });
    let refused = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await;
    let err = refused
        .expect_err("an unfunded account must not be able to pay for its own initialization");
    // Pin the specific rejection: a bare `is_err()` would pass equally on a
    // network or wallet-build failure. The wallet now surfaces the sequencer's
    // fee-admission message, so match the `PayerCannotFund` text — distinct from
    // every other admission rejection.
    assert!(
        err.to_string().contains("but the fee reserve is"),
        "expected a PayerCannotFund rejection, got: {err}",
    );

    log::info!("Checking the account was never touched");
    let account = get_account(&ctx, account_id).await?;
    assert_eq!(account, lee::Account::default());

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
    let sender_before = account_balance(&ctx, sender).await?;
    let receiver_before = account_balance(&ctx, receiver).await?;
    send(
        &mut ctx,
        CliAccountMention::Label(label),
        public_mention(receiver),
        100,
    )
    .await?;

    log::info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    log::info!("Checking correct balance move");
    let acc_1_balance = account_balance(&ctx, sender).await?;
    let acc_2_balance = account_balance(&ctx, receiver).await?;

    assert_eq!(acc_2_balance, receiver_before + 100);
    assert_sender_paid_fee(sender_before, acc_1_balance, 100);

    log::info!("Successfully transferred using from_label");

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
    let sender_before = account_balance(&ctx, sender).await?;
    let receiver_before = account_balance(&ctx, receiver).await?;
    send(
        &mut ctx,
        public_mention(sender),
        CliAccountMention::Label(label),
        100,
    )
    .await?;

    log::info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    log::info!("Checking correct balance move");
    let acc_1_balance = account_balance(&ctx, sender).await?;
    let acc_2_balance = account_balance(&ctx, receiver).await?;

    assert_eq!(acc_2_balance, receiver_before + 100);
    assert_sender_paid_fee(sender_before, acc_1_balance, 100);

    log::info!("Successfully transferred using to_label");

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
    // Unsigned and fee-less: the fee-admission door refuses it at submission,
    // so it never even reaches the mempool.
    let err = ctx
        .sequencer_client()
        .send_transaction(LeeTransaction::Public(tx))
        .await
        .expect_err("a fee-less faucet impersonation must be refused at admission");
    assert!(
        err.to_string().contains("must declare a fee"),
        "expected the missing-fee admission rejection, got: {err}",
    );

    let recipient_balance_after = account_balance(&ctx, recipient).await?;
    let faucet_balance_after = account_balance(&ctx, faucet_account_id).await?;

    assert_eq!(recipient_balance_after, recipient_balance_before);
    assert_eq!(faucet_balance_after, faucet_balance_before);

    Ok(())
}

#[test]
async fn cannot_execute_faucet_program() -> Result<()> {
    let ctx = TestContext::new().await?;
    let faucet_account_id = system_accounts::faucet_account_id();

    let recipient = ctx.existing_public_accounts()[0];
    let vault_program_id = programs::vault().id();
    let recipient_vault_id = vault_core::compute_vault_account_id(vault_program_id, recipient);

    let recipient_balance_before = account_balance(&ctx, recipient).await?;
    let faucet_balance_before = account_balance(&ctx, faucet_account_id).await?;

    let amount = 1_u128;
    let message = public_transaction::Message::try_new(
        programs::faucet().id(),
        vec![faucet_account_id, recipient_vault_id],
        vec![],
        faucet_core::Instruction::GenesisTransferVault {
            vault_program_id,
            recipient_id: recipient,
            amount,
        },
    )?;
    let tx = lee::PublicTransaction::new(
        message,
        lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
    );
    // Unsigned and fee-less: refused at the fee-admission door.
    let err = ctx
        .sequencer_client()
        .send_transaction(LeeTransaction::Public(tx))
        .await
        .expect_err("a fee-less faucet invocation must be refused at admission");
    assert!(
        err.to_string().contains("must declare a fee"),
        "expected the missing-fee admission rejection, got: {err}",
    );

    let recipient_balance_after = account_balance(&ctx, recipient).await?;
    let faucet_balance_after = account_balance(&ctx, faucet_account_id).await?;

    assert_eq!(recipient_balance_after, recipient_balance_before);
    assert_eq!(faucet_balance_after, faucet_balance_before);

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

    log::info!("Waiting for deploy block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let faucet_account_id = system_accounts::faucet_account_id();
    let attacker = ctx.existing_public_accounts()[0];
    let faucet_program_id = programs::faucet().id();
    let vault_program_id = programs::vault().id();
    let attacker_vault_id = vault_core::compute_vault_account_id(vault_program_id, attacker);
    let amount: u128 = 1;

    let message = public_transaction::Message::try_new(
        faucet_chain_caller.id(),
        vec![faucet_account_id, attacker_vault_id],
        vec![],
        (faucet_program_id, vault_program_id, attacker, amount),
    )?;
    let attack_tx = LeeTransaction::Public(lee::PublicTransaction::new(
        message,
        lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
    ));

    let faucet_balance_before = account_balance(&ctx, faucet_account_id).await?;
    let vault_balance_before = account_balance(&ctx, attacker_vault_id).await?;

    // Unsigned and fee-less: refused at the fee-admission door before the
    // sequencer-only chain-call defense would even see it.
    let err = ctx
        .sequencer_client()
        .send_transaction(attack_tx)
        .await
        .expect_err("a fee-less chain-call attack must be refused at admission");
    assert!(
        err.to_string().contains("must declare a fee"),
        "expected the missing-fee admission rejection, got: {err}",
    );

    let faucet_balance_after = account_balance(&ctx, faucet_account_id).await?;
    let vault_balance_after = account_balance(&ctx, attacker_vault_id).await?;

    assert_eq!(faucet_balance_after, faucet_balance_before);
    assert_eq!(vault_balance_after, vault_balance_before);

    Ok(())
}
