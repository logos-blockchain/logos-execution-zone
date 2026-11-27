#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use anyhow::Result;
use integration_tests::{
    TestContext, funded_private_account, new_account, private_balance, sync_private,
    wait_for_inclusion,
};
use lee::{
    AccountId, Publication, privacy_preserving_transaction::circuit::ProgramCatalog,
    program::Program,
};
use lee_core::native_token;
use tokio::test;
use wallet::{
    AccountIdentity, AsyncDelivery, Promotions,
    program_facades::{CreditDelivery, native_token_transfer::NativeTokenTransfer},
};

const AMOUNT: u128 = 100;

// A private sender's deferred credit to a private account leaves its proof sealed. The recipient's
// keys find it, the recipient receives it privately, and the wallet then lists it no more.
#[test]
async fn a_private_native_credit_is_sealed_and_received_by_its_recipient() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let sender = funded_private_account(&mut ctx, AMOUNT).await?;
    let recipient = new_account(&mut ctx, true, None).await?;

    let (sent, _) = NativeTokenTransfer(ctx.wallet())
        .transfer(
            AccountIdentity::PrivateOwned(sender),
            AccountIdentity::PrivateOwned(recipient),
            AMOUNT,
            CreditDelivery::DeferredPrivate,
        )
        .await?;
    wait_for_inclusion(&ctx, sent).await?;

    receive_sealed_transfer(&mut ctx, recipient).await
}

// An async message back to the sender's own account, which the transaction witnesses, executes at
// once unless the selection lists only other candidates: then it is sealed for the sender to
// receive.
#[test]
async fn an_async_message_to_a_witnessed_account_is_sealed_when_the_selection_lists_only_others()
-> Result<()> {
    let mut ctx = TestContext::new().await?;
    let holder_id = funded_private_account(&mut ctx, AMOUNT).await?;
    let holder = AccountIdentity::PrivateOwned(holder_id).balance();
    let (_, async_delivery) = ctx.wallet().seal_destination(holder.clone())?;

    let (sent, _) = ctx
        .wallet()
        .send_tx(
            vec![holder],
            0,
            Program::serialize_message(native_token::Message::Transfer {
                to: holder_id,
                amount: AMOUNT,
            })?,
            &ProgramCatalog::default(),
            None,
            AsyncDelivery {
                promotions: Promotions {
                    listed_only: true,
                    ..Promotions::default()
                },
                ..async_delivery
            },
        )
        .await?;
    wait_for_inclusion(&ctx, sent).await?;
    sync_private(&mut ctx).await?;

    assert_eq!(
        private_balance(&ctx, holder_id)?,
        0,
        "the deferred credit has not reached the holder yet"
    );
    receive_sealed_transfer(&mut ctx, holder_id).await
}

// Receives the one transfer pending for the wallet, sealed to `to` and binding nothing, which then
// holds `AMOUNT`.
async fn receive_sealed_transfer(ctx: &mut TestContext, to: AccountId) -> Result<()> {
    assert_eq!(
        ctx.wallet().get_recovery_binding(to).await?,
        None,
        "a sealed message binds nothing"
    );
    let [pending] = <[_; 1]>::try_from(ctx.wallet_mut().owned_pending_messages().await?)
        .map_err(|pending| anyhow::anyhow!("expected one transfer, found {}", pending.len()))?;
    anyhow::ensure!(
        matches!(pending.publication, Publication::Sealed(_)),
        "a private sender's async message to a private account is sealed"
    );
    assert_eq!(
        (pending.body.to.account_id, pending.recipient.account_id()),
        (to, to)
    );

    let (received, _) = ctx.wallet_mut().receive_pending_message(pending).await?;
    wait_for_inclusion(ctx, received).await?;
    sync_private(ctx).await?;

    assert_eq!(private_balance(ctx, to)?, AMOUNT);
    assert!(
        ctx.wallet_mut().owned_pending_messages().await?.is_empty(),
        "receiving spends the sealed transfer"
    );
    Ok(())
}
