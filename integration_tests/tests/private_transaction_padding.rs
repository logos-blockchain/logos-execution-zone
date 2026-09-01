#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use anyhow::Result;
use integration_tests::{TestContext, fetch_privacy_preserving_tx, private_mention};
use lee::AccountId;
use tokio::test;
use wallet::cli::{
    Command, SubcommandReturnValue, programs::native_token_transfer::AuthTransferSubcommand,
};

/// Every privacy-preserving transaction carries the same number of notes, so the
/// count of accounts it really touched is not observable on the wire.
#[test]
async fn private_transaction_pads_notes_to_max() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let from: AccountId = ctx.existing_private_accounts()[0];
    let to: AccountId = ctx.existing_private_accounts()[1];

    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: private_mention(from),
        to: Some(private_mention(to)),
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

    // Two accounts moved; the rest of the notes are padding.
    assert_eq!(tx.message.private_actions.len(), 7);

    Ok(())
}
