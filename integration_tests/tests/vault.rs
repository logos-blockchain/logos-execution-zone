#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use anyhow::{Context as _, Result};
use integration_tests::{TestContext, private_mention, public_mention};
use sequencer_service_rpc::RpcClient as _;
use tokio::test;
use wallet::cli::{Command, SubcommandReturnValue, programs::vault::VaultSubcommand};

#[test]
async fn public_transfer_and_public_claim() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let amount: u128 = 100;
    let sender = ctx.existing_public_accounts()[0];
    let recipient = ctx.existing_public_accounts()[1];

    let vault_account_id = programs::vault().deployed_account_id();
    let recipient_vault_id = vault_core::compute_vault_account_id(vault_account_id, recipient);

    let sender_balance_before = ctx.sequencer_client().get_account_balance(sender).await?;
    let recipient_balance_before = ctx
        .sequencer_client()
        .get_account_balance(recipient)
        .await?;
    let recipient_vault_balance_before = ctx
        .sequencer_client()
        .get_account_balance(recipient_vault_id)
        .await?;

    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Vault(VaultSubcommand::Transfer {
            from: public_mention(sender),
            to: public_mention(recipient),
            amount,
        }),
    )
    .await?;

    let sender_balance_after_transfer = ctx.sequencer_client().get_account_balance(sender).await?;
    let recipient_balance_after_transfer = ctx
        .sequencer_client()
        .get_account_balance(recipient)
        .await?;
    let recipient_vault_balance_after_transfer = ctx
        .sequencer_client()
        .get_account_balance(recipient_vault_id)
        .await?;

    assert_eq!(
        sender_balance_after_transfer,
        sender_balance_before - amount
    );
    assert_eq!(recipient_balance_after_transfer, recipient_balance_before);
    assert_eq!(
        recipient_vault_balance_after_transfer,
        recipient_vault_balance_before + amount
    );

    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Vault(VaultSubcommand::Claim {
            account_id: public_mention(recipient),
            amount,
        }),
    )
    .await?;

    let sender_balance_after_claim = ctx.sequencer_client().get_account_balance(sender).await?;
    let recipient_balance_after_claim = ctx
        .sequencer_client()
        .get_account_balance(recipient)
        .await?;
    let recipient_vault_balance_after_claim = ctx
        .sequencer_client()
        .get_account_balance(recipient_vault_id)
        .await?;

    assert_eq!(sender_balance_after_claim, sender_balance_before - amount);
    assert_eq!(
        recipient_balance_after_claim,
        recipient_balance_before + amount
    );
    assert_eq!(
        recipient_vault_balance_after_claim,
        recipient_vault_balance_before
    );

    Ok(())
}

#[test]
async fn private_transfer_and_private_claim() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let amount: u128 = 100;
    let sender = ctx.existing_private_accounts()[0];
    let owner = ctx.existing_private_accounts()[1];

    let vault_account_id = programs::vault().deployed_account_id();
    let owner_vault_id = vault_core::compute_vault_account_id(vault_account_id, owner);

    let sender_balance_before = ctx
        .wallet()
        .get_account_private(sender)
        .context("Failed to load sender private account")?
        .balance;
    let owner_balance_before = ctx
        .wallet()
        .get_account_private(owner)
        .context("Failed to load owner private account")?
        .balance;
    let owner_vault_balance_before = ctx
        .sequencer_client()
        .get_account_balance(owner_vault_id)
        .await?;

    let transfer_result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Vault(VaultSubcommand::Transfer {
            from: private_mention(sender),
            to: private_mention(owner),
            amount,
        }),
    )
    .await?;
    assert!(
        matches!(
            transfer_result,
            SubcommandReturnValue::TransactionExecuted { .. }
        ),
        "Expected TransactionExecuted return value for private vault transfer"
    );

    let sender_balance_after_transfer = ctx
        .wallet()
        .get_account_private(sender)
        .context("Failed to load sender private account after transfer")?
        .balance;
    let owner_balance_after_transfer = ctx
        .wallet()
        .get_account_private(owner)
        .context("Failed to load owner private account after transfer")?
        .balance;
    let owner_vault_balance_after_transfer = ctx
        .sequencer_client()
        .get_account_balance(owner_vault_id)
        .await?;

    assert_eq!(
        sender_balance_after_transfer,
        sender_balance_before - amount
    );
    assert_eq!(owner_balance_after_transfer, owner_balance_before);
    assert_eq!(
        owner_vault_balance_after_transfer,
        owner_vault_balance_before + amount
    );

    let claim_result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Vault(VaultSubcommand::Claim {
            account_id: private_mention(owner),
            amount,
        }),
    )
    .await?;
    assert!(
        matches!(
            claim_result,
            SubcommandReturnValue::TransactionExecuted { .. }
        ),
        "Expected TransactionExecuted return value for private vault claim"
    );

    let sender_balance_after_claim = ctx
        .wallet()
        .get_account_private(sender)
        .context("Failed to load sender private account after claim")?
        .balance;
    let owner_balance_after_claim = ctx
        .wallet()
        .get_account_private(owner)
        .context("Failed to load owner private account after claim")?
        .balance;
    let owner_vault_balance_after_claim = ctx
        .sequencer_client()
        .get_account_balance(owner_vault_id)
        .await?;

    assert_eq!(sender_balance_after_claim, sender_balance_before - amount);
    assert_eq!(owner_balance_after_claim, owner_balance_before + amount);
    assert_eq!(owner_vault_balance_after_claim, owner_vault_balance_before);

    Ok(())
}
