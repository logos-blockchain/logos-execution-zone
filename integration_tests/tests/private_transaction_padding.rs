#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use anyhow::Result;
use integration_tests::{
    TestContext, fetch_privacy_preserving_tx, new_account, private_mention, public_mention,
};
use tokio::test;
use wallet::cli::{
    Command, SubcommandReturnValue, programs::native_token_transfer::AuthTransferSubcommand,
};

#[test]
async fn private_transaction_pads_notes_to_max() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let account_id = new_account(&mut ctx, true, None).await?;
    let funder = ctx.existing_public_accounts()[0];

    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: public_mention(funder),
        to: Some(private_mention(account_id)),
        to_npk: None,
        to_vpk: None,
        to_keys: None,
        to_identifier: None,
        amount: 100,
    });
    let result = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::TransactionExecuted { tx_hash } = result else {
        anyhow::bail!("Expected TransactionExecuted return value");
    };

    let tx = fetch_privacy_preserving_tx(ctx.sequencer_client(), tx_hash).await;

    assert_eq!(tx.message.private_actions.len(), 7);

    Ok(())
}
