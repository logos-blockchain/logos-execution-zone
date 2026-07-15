#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use anyhow::Result;
use integration_tests::{TestContext, fetch_privacy_preserving_tx, new_account, private_mention};
use tokio::test;
use wallet::cli::{
    Command, SubcommandReturnValue, programs::native_token_transfer::AuthTransferSubcommand,
};

#[test]
async fn private_transaction_pads_notes_to_max() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let account_id = new_account(&mut ctx, true, None).await?;

    let command = Command::AuthTransfer(AuthTransferSubcommand::Init {
        account_id: private_mention(account_id),
    });
    let result = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::TransactionExecuted { tx_hash } = result else {
        anyhow::bail!("Expected TransactionExecuted return value");
    };

    let tx = fetch_privacy_preserving_tx(ctx.sequencer_client(), tx_hash).await;

    assert_eq!(tx.message.new_commitments.len(), 7);
    assert_eq!(tx.message.new_nullifiers.len(), 7);
    assert_eq!(tx.message.encrypted_private_post_states.len(), 7);

    Ok(())
}
