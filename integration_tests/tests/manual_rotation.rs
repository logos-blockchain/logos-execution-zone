#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

//! Manual key rotation through the wallet, against a running sequencer.

use anyhow::{Context as _, Result};
use integration_tests::{
    TestContext, private_mention, public_mention,
    utils::{get_account, new_account, send, wait_for_inclusion},
};
use lee::{AccountId, signature::PublicAccountSecret};
use lee_core::{
    account::{ActorState, Nonce},
    signing_key::{KeyType, signature_program_id},
};
use tokio::test;
use wallet::cli::{Command, SubcommandReturnValue, account::AccountSubcommand, execute_subcommand};

/// Rotates `accounts`, paid by `fee_payer`, and waits for inclusion.
async fn rotate_key(
    ctx: &mut TestContext,
    accounts: &[AccountId],
    fee_payer: AccountId,
) -> Result<()> {
    let command = Command::Account(AccountSubcommand::RotateKey {
        accounts: accounts.iter().copied().map(public_mention).collect(),
        fee_payer: private_mention(fee_payer),
    });
    let SubcommandReturnValue::TransactionExecuted { tx_hash } =
        execute_subcommand(ctx.wallet_mut(), command).await?
    else {
        anyhow::bail!("rotate-key returns its transaction hash");
    };
    wait_for_inclusion(ctx, tx_hash).await
}

fn secret(ctx: &TestContext, account: AccountId) -> Result<PublicAccountSecret> {
    ctx.wallet()
        .storage()
        .key_chain()
        .pub_account_secret(account)
        .cloned()
        .context("the wallet holds the account")
}

/// The account's nonce and the key the chain stores for it.
async fn stored_key(ctx: &TestContext, account: AccountId) -> Result<(Nonce, ActorState)> {
    let account = get_account(ctx, account).await?;
    Ok((
        account.nonce,
        account.data.actor_state(signature_program_id()).clone(),
    ))
}

/// The key the account gets from its `counter`-th manual rotation at `nonce`.
fn rotated(secret: &PublicAccountSecret, nonce: Nonce, counter: u32) -> ActorState {
    lee::signature::key_state_with_counter(secret, KeyType::Schnorr, nonce, counter).encode()
}

#[test]
async fn a_manually_rotated_account_signs_again_at_the_same_nonce() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let account = ctx.existing_public_accounts()[0];
    let receiver = ctx.existing_public_accounts()[1];
    let fee_payer = ctx.existing_private_accounts()[0];
    let secret = secret(&ctx, account)?;
    let (nonce, _) = stored_key(&ctx, account).await?;

    rotate_key(&mut ctx, &[account], fee_payer).await?;
    assert_eq!(
        stored_key(&ctx, account).await?,
        (nonce, rotated(&secret, nonce, 1)),
        "the key is replaced and the nonce is unchanged"
    );
    let tx_hash = send(
        &mut ctx,
        public_mention(account),
        public_mention(receiver),
        1,
    )
    .await?;
    wait_for_inclusion(&ctx, tx_hash).await?;
    let (after, _) = stored_key(&ctx, account).await?;
    assert_eq!(after.0, nonce.0 + 1, "the rotated key signed");
    Ok(())
}

#[test]
async fn a_second_manual_rotation_at_a_nonce_takes_the_next_counter() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let account = ctx.existing_public_accounts()[0];
    let fee_payer = ctx.existing_private_accounts()[0];
    let secret = secret(&ctx, account)?;
    let (nonce, _) = stored_key(&ctx, account).await?;

    for counter in 1..=2 {
        rotate_key(&mut ctx, &[account], fee_payer).await?;
        assert_eq!(
            stored_key(&ctx, account).await?,
            (nonce, rotated(&secret, nonce, counter))
        );
    }
    Ok(())
}

#[test]
async fn a_batch_rotates_two_accounts_manually() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let accounts = [
        ctx.existing_public_accounts()[0],
        ctx.existing_public_accounts()[1],
    ];
    let fee_payer = ctx.existing_private_accounts()[0];
    let before = [
        stored_key(&ctx, accounts[0]).await?.0,
        stored_key(&ctx, accounts[1]).await?.0,
    ];

    rotate_key(&mut ctx, &accounts, fee_payer).await?;

    for (account, nonce) in accounts.into_iter().zip(before) {
        let secret = secret(&ctx, account)?;
        assert_eq!(
            stored_key(&ctx, account).await?,
            (nonce, rotated(&secret, nonce, 1))
        );
    }
    Ok(())
}

#[test]
async fn a_fresh_account_is_rotated_manually_at_nonce_zero() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let account = new_account(&mut ctx, false, None).await?;
    let fee_payer = ctx.existing_private_accounts()[0];
    let secret = secret(&ctx, account)?;

    rotate_key(&mut ctx, &[account], fee_payer).await?;

    assert_eq!(
        stored_key(&ctx, account).await?,
        (Nonce(0), rotated(&secret, Nonce(0), 1))
    );
    assert_eq!(
        ctx.wallet().current_signing_key(account, &secret).await?,
        (KeyType::Schnorr, 1)
    );
    Ok(())
}
