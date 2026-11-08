#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use anyhow::{Context as _, Result};
use integration_tests::{
    TestContext, private_mention, public_mention,
    utils::{account_balance, get_account, new_account, send, wait_for_inclusion},
};
use lee::{AccountId, program::Program, test_utils::TestSigner};
use lee_core::{
    account::{ActorState, Nonce},
    native_token::Message,
    signing_key::{KeyType, SIGNATURE_PROGRAM_ID},
};
use sequencer_service_rpc::RpcClient as _;
use tokio::test;
use wallet::{
    AccountIdentity, ExecutionFailureKind,
    program_facades::{CreditDelivery, native_token_transfer::NativeTokenTransfer},
    storage::leaf_records::LeafRecords,
};

/// Sends `sender`'s transfer to `recipient` with no client-side balance check, paid by `payer`
/// or by the sender.
async fn raw_transfer(
    ctx: &TestContext,
    sender: AccountId,
    recipient: AccountId,
    amount: u128,
    payer: Option<AccountId>,
) -> Result<common::HashType> {
    let tx_hash = ctx
        .wallet()
        .send_pub_tx_paid_by(
            vec![
                AccountIdentity::Public(sender).balance(),
                AccountIdentity::PublicNoSign(recipient).balance(),
            ],
            0,
            Program::serialize_message(Message::Transfer {
                to: recipient,
                amount,
            })?,
            payer,
        )
        .await?;
    wait_for_inclusion(ctx, tx_hash).await?;
    Ok(tx_hash)
}

fn test_signer(ctx: &TestContext, account_id: AccountId) -> Result<TestSigner> {
    Ok(TestSigner::from(
        ctx.wallet()
            .storage()
            .key_chain()
            .pub_account_secret(account_id)
            .context("the wallet holds the account")?,
    ))
}

/// The account's nonce and the key the chain stores for it.
async fn stored_key(ctx: &TestContext, account_id: AccountId) -> Result<(Nonce, ActorState)> {
    let account = get_account(ctx, account_id).await?;
    Ok((
        account.nonce,
        account.data.actor_state(SIGNATURE_PROGRAM_ID).clone(),
    ))
}

fn leaf_records(ctx: &TestContext) -> Result<LeafRecords> {
    LeafRecords::open(ctx.wallet().storage_path().with_extension("leaves"))
}

#[test]
async fn each_transfer_rotates_the_senders_key() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let sender = ctx.existing_public_accounts()[0];
    let receiver = ctx.existing_public_accounts()[1];
    let signer = test_signer(&ctx, sender)?;

    for _ in 0..3 {
        let (before, _) = stored_key(&ctx, sender).await?;
        send(
            &mut ctx,
            public_mention(sender),
            public_mention(receiver),
            10,
        )
        .await?;

        let (nonce, key) = stored_key(&ctx, sender).await?;
        assert_eq!(nonce.0, before.0 + 1);
        assert_eq!(key, signer.key_state(nonce).into());
    }

    Ok(())
}

#[test]
async fn an_account_switches_to_schnorr_and_back() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let sender = ctx.existing_public_accounts()[0];
    let receiver = ctx.existing_public_accounts()[1];
    let (start, _) = stored_key(&ctx, sender).await?;
    let schnorr_from = Nonce(start.0 + 1);
    let wots_from = Nonce(start.0 + 3);
    let signer = test_signer(&ctx, sender)?
        .rotating_to(KeyType::Schnorr, schnorr_from)
        .rotating_to(KeyType::Wots, wots_from);

    // Rotates to Schnorr, then keeps it without the flag, then rotates back.
    for next in [Some(KeyType::Schnorr), None, Some(KeyType::Wots)] {
        ctx.wallet_mut().set_next_key_type(next);
        send(
            &mut ctx,
            public_mention(sender),
            public_mention(receiver),
            10,
        )
        .await?;

        let (nonce, key) = stored_key(&ctx, sender).await?;
        assert_eq!(key, signer.key_state(nonce).into());
    }
    assert_eq!(ctx.wallet().current_key_type(sender).await?, KeyType::Wots);

    Ok(())
}

/// The second transfer at a pending nonce signs with the next leaf; the mempool keeps the first.
#[test]
async fn a_second_transfer_at_a_pending_nonce_signs_with_the_next_leaf() -> Result<()> {
    let ctx = TestContext::new().await?;
    let sender = ctx.existing_public_accounts()[0];
    let receiver = ctx.existing_public_accounts()[1];
    let (nonce, _) = stored_key(&ctx, sender).await?;
    let transfer = async |amount| {
        NativeTokenTransfer(ctx.wallet())
            .transfer(
                AccountIdentity::Public(sender),
                AccountIdentity::Public(receiver),
                amount,
                CreditDelivery::Automatic,
            )
            .await
            .map(|(tx_hash, _)| tx_hash)
    };

    let first = transfer(10).await?;
    let second = transfer(11).await;
    assert!(
        matches!(second, Err(ExecutionFailureKind::SequencerClientError(_))),
        "the mempool refuses a second transaction at a pending nonce, got {second:?}"
    );
    assert_eq!(leaf_records(&ctx)?.next_leaf(sender, nonce), Ok(2));

    wait_for_inclusion(&ctx, first).await?;
    let third = transfer(12).await?;
    wait_for_inclusion(&ctx, third).await?;
    assert_eq!(stored_key(&ctx, sender).await?.0.0, nonce.0 + 2);

    Ok(())
}

#[test]
async fn a_shield_rotates_its_public_signers_key() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let sender = ctx.existing_public_accounts()[0];
    let signer = test_signer(&ctx, sender)?;
    let (before, _) = stored_key(&ctx, sender).await?;
    let recipient = new_account(&mut ctx, true, None).await?;

    send(
        &mut ctx,
        public_mention(sender),
        private_mention(recipient),
        10,
    )
    .await?;

    let (nonce, key) = stored_key(&ctx, sender).await?;
    assert_eq!(nonce.0, before.0 + 1);
    assert_eq!(key, signer.key_state(nonce).into());

    Ok(())
}

#[test]
async fn a_transfer_paid_by_a_co_signer_rotates_both_keys() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let sender = ctx.existing_public_accounts()[0];
    let recipient = ctx.existing_public_accounts()[1];
    let payer = new_account(&mut ctx, false, None).await?;
    send(
        &mut ctx,
        public_mention(sender),
        public_mention(payer),
        1_000_000_000,
    )
    .await?;
    let (sender_before, _) = stored_key(&ctx, sender).await?;

    let tx_hash = raw_transfer(&ctx, sender, recipient, 10, Some(payer)).await?;

    let (tx, _) = ctx
        .sequencer_client()
        .get_transaction(tx_hash)
        .await?
        .context("the transfer is included")?;
    let common::transaction::LeeTransaction::Public(tx) = tx else {
        anyhow::bail!("Expected a public transaction");
    };
    assert_eq!(tx.witness_set().entries().len(), 2);

    let (nonce, key) = stored_key(&ctx, sender).await?;
    assert_eq!(nonce.0, sender_before.0 + 1);
    assert_eq!(key, test_signer(&ctx, sender)?.key_state(nonce).into());
    let (payer_nonce, payer_key) = stored_key(&ctx, payer).await?;
    assert_eq!(payer_nonce, Nonce(1));
    assert_eq!(
        payer_key,
        test_signer(&ctx, payer)?.key_state(payer_nonce).into()
    );

    Ok(())
}

/// An over-balance transfer reaches settlement, which charges its fee, reverts it, rotates the
/// key and advances the nonce; the next transfer signs at the new nonce from its first leaf.
#[test]
async fn a_charged_revert_rotates_the_key_and_the_next_transfer_follows() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let sender = ctx.existing_public_accounts()[0];
    let recipient = ctx.existing_public_accounts()[1];
    let signer = test_signer(&ctx, sender)?;
    let (before, _) = stored_key(&ctx, sender).await?;
    let sender_balance = account_balance(&ctx, sender).await?;
    let recipient_balance = account_balance(&ctx, recipient).await?;

    raw_transfer(&ctx, sender, recipient, sender_balance * 2, None).await?;

    assert_eq!(account_balance(&ctx, recipient).await?, recipient_balance);
    assert!(account_balance(&ctx, sender).await? < sender_balance);
    let (nonce, key) = stored_key(&ctx, sender).await?;
    assert_eq!(nonce.0, before.0 + 1);
    assert_eq!(key, signer.key_state(nonce).into());

    send(
        &mut ctx,
        public_mention(sender),
        public_mention(recipient),
        10,
    )
    .await?;

    assert_eq!(
        account_balance(&ctx, recipient).await?,
        recipient_balance + 10
    );
    let (next, next_key) = stored_key(&ctx, sender).await?;
    assert_eq!(next.0, before.0 + 2);
    assert_eq!(next_key, signer.key_state(next).into());
    assert_eq!(leaf_records(&ctx)?.next_leaf(sender, nonce), Ok(1));

    Ok(())
}
