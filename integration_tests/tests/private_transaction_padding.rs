#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use anyhow::Result;
use integration_tests::{TestContext, fetch_privacy_preserving_tx, private_mention};
use lee::AccountId;
use tokio::test;
use wallet::{
    CIPHERTEXT_PAD_SIZE,
    cli::{
        Command, SubcommandReturnValue, programs::native_token_transfer::AuthTransferSubcommand,
    },
};

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

    assert_eq!(tx.message.private_actions.len(), 7);

    let expected = usize::try_from(CIPHERTEXT_PAD_SIZE).expect("pad size fits in usize");
    let lengths: Vec<usize> = tx
        .message
        .private_actions
        .iter()
        .map(|action| action.encrypted_post_state.ciphertext.as_bytes().len())
        .collect();
    assert!(
        lengths.iter().all(|&len| len == expected),
        "all note ciphertexts must be padded to {expected} bytes, got {lengths:?}"
    );

    Ok(())
}
