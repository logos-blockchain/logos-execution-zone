#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

//! Manual key rotation through the wallet, against a running sequencer and indexer.

use anyhow::{Context as _, Result};
use integration_tests::{
    TestContext, private_mention, public_mention,
    utils::{get_account, new_account, send, wait_for_inclusion, wait_for_indexer_to_catch_up},
};
use lee::{AccountId, signature::PublicAccountSecret};
use lee_core::{
    account::{ActorState, Nonce},
    signing_key::{KeyType, signature_program_id},
};
use sequencer_service_rpc::SequencerClientBuilder;
use tokio::test;
use wallet::{
    WalletCore,
    cli::{Command, SubcommandReturnValue, account::AccountSubcommand, execute_subcommand},
};

/// Rotates `accounts` to keys of type `to`, paid by `fee_payer`, and waits for inclusion.
async fn rotate_key(
    ctx: &mut TestContext,
    accounts: &[AccountId],
    to: KeyType,
    fee_payer: AccountId,
) -> Result<()> {
    let command = Command::Account(AccountSubcommand::RotateKey {
        accounts: accounts.iter().copied().map(public_mention).collect(),
        to,
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
fn rotated(
    secret: &PublicAccountSecret,
    key_type: KeyType,
    nonce: Nonce,
    counter: u32,
) -> ActorState {
    lee::signature::key_state_with_counter(secret, key_type, nonce, counter).into()
}

#[test]
async fn a_manually_rotated_account_signs_again_at_the_same_nonce() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let account = ctx.existing_public_accounts()[0];
    let receiver = ctx.existing_public_accounts()[1];
    let fee_payer = ctx.existing_private_accounts()[0];
    let secret = secret(&ctx, account)?;
    let (nonce, _) = stored_key(&ctx, account).await?;

    rotate_key(&mut ctx, &[account], KeyType::Wots, fee_payer).await?;
    assert_eq!(
        stored_key(&ctx, account).await?,
        (nonce, rotated(&secret, KeyType::Wots, nonce, 1)),
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
async fn manual_rotation_changes_the_key_type_both_ways() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let account = ctx.existing_public_accounts()[0];
    let receiver = ctx.existing_public_accounts()[1];
    let fee_payer = ctx.existing_private_accounts()[0];
    let secret = secret(&ctx, account)?;

    for to in [KeyType::Schnorr, KeyType::Wots] {
        let (nonce, _) = stored_key(&ctx, account).await?;
        rotate_key(&mut ctx, &[account], to, fee_payer).await?;
        assert_eq!(
            stored_key(&ctx, account).await?,
            (nonce, rotated(&secret, to, nonce, 1))
        );
        let tx_hash = send(
            &mut ctx,
            public_mention(account),
            public_mention(receiver),
            1,
        )
        .await?;
        wait_for_inclusion(&ctx, tx_hash).await?;
        assert_eq!(stored_key(&ctx, account).await?.0, Nonce(nonce.0 + 1));
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

    rotate_key(&mut ctx, &accounts, KeyType::Schnorr, fee_payer).await?;

    for (account, nonce) in accounts.into_iter().zip(before) {
        let secret = secret(&ctx, account)?;
        assert_eq!(
            stored_key(&ctx, account).await?,
            (nonce, rotated(&secret, KeyType::Schnorr, nonce, 1))
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

    rotate_key(&mut ctx, &[account], KeyType::Schnorr, fee_payer).await?;

    assert_eq!(
        stored_key(&ctx, account).await?,
        (Nonce(0), rotated(&secret, KeyType::Schnorr, Nonce(0), 1))
    );
    assert_eq!(
        ctx.wallet().current_signing_key(account, &secret).await?,
        (KeyType::Schnorr, 1)
    );
    Ok(())
}

/// A wallet with no record of the rotation, as after a restore, finds the counter in the
/// account's history on the indexer.
#[test]
async fn a_restored_wallet_finds_a_manually_rotated_key() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let account = ctx.existing_public_accounts()[0];
    let fee_payer = ctx.existing_private_accounts()[0];
    let secret = secret(&ctx, account)?;
    rotate_key(&mut ctx, &[account], KeyType::Schnorr, fee_payer).await?;
    wait_for_indexer_to_catch_up(&ctx).await?;

    let storage_path = ctx.wallet().storage_path().clone();
    std::fs::remove_file(storage_path.with_extension("leaves"))
        .context("the wallet's leaf records exist")?;
    let mut config = ctx.wallet().config().clone();
    config.indexer_url = Some(format!("http://{}", ctx.indexer_addr()).parse()?);
    let mut restored = WalletCore::new_update_chain_with_client(
        ctx.wallet().config_path().clone(),
        storage_path,
        None,
        ctx.wallet_password(),
        SequencerClientBuilder::default().build(&config.sequencer.sequencer_addr)?,
    )?;
    restored.set_config(config);

    assert_eq!(
        restored.current_signing_key(account, &secret).await?,
        (KeyType::Schnorr, 1)
    );
    Ok(())
}
