#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use anyhow::{Context as _, Result};
use integration_tests::{TestContext, account_balance, new_account, wait_for_inclusion};
use lee::{
    AccountId, Actor, privacy_preserving_transaction::circuit::ProgramCatalog, program::Program,
};
use lee_core::{native_token::Message as NativeMessage, program::SyncMessage};
use test_guest_core::Script;
use tokio::test;
use wallet::{
    AccountIdentity, AccountMention, AsyncDelivery, ExecutionFailureKind,
    program_facades::program_loader::ProgramLoader,
};

const AMOUNT: u128 = 7;

async fn deploy(ctx: &mut TestContext, program: &Program) -> Result<AccountId> {
    let payer = ctx.existing_public_accounts()[0];
    let header = new_account(ctx, false, None).await?;
    let mut segments = Vec::new();
    for _ in program
        .user_elf()?
        .chunks(program_loader_core::MAX_SEGMENT_DATA_LEN)
    {
        segments.push(new_account(ctx, false, None).await?);
    }
    ProgramLoader(ctx.wallet())
        .deploy(header, &segments, program.elf().to_vec(), true, Some(payer))
        .await
}

// The user signs a call to a program that transfers out of the user's native balance.
async fn call_draining_program(
    ctx: &TestContext,
    program: AccountId,
    user: AccountId,
    recipient: AccountId,
    balance: AccountMention,
) -> Result<common::HashType, ExecutionFailureKind> {
    let balance_actor = Actor::native_balance(user);
    let drain = Script::default().send(
        SyncMessage::new(
            balance_actor,
            &NativeMessage::Transfer {
                to: recipient,
                amount: AMOUNT,
            },
        )
        .with_grants([balance_actor]),
    );
    ctx.wallet()
        .send_tx(
            vec![
                AccountIdentity::Public(user).select_program_actor_state(program),
                balance,
                AccountIdentity::Public(recipient)
                    .balance()
                    .without_authorization(),
            ],
            0,
            Program::serialize_message(drain).expect("Script should serialize"),
            &ProgramCatalog::from([(program, test_programs::scripted())]),
            None,
            AsyncDelivery::default(),
        )
        .await
        .map(|(hash, _)| hash)
}

#[test]
async fn a_signed_call_cannot_spend_a_native_balance_declared_without_authority() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let program = deploy(&mut ctx, &test_programs::scripted()).await?;
    let [recipient, user] = [
        ctx.existing_public_accounts()[0],
        ctx.existing_public_accounts()[1],
    ];
    let recipient_before = account_balance(&ctx, recipient).await?;

    let refused = call_draining_program(
        &ctx,
        program,
        user,
        recipient,
        AccountIdentity::Public(user)
            .balance()
            .without_authorization(),
    )
    .await;
    assert!(
        matches!(
            &refused,
            Err(ExecutionFailureKind::SimulatedRevert(reason))
                if reason.contains("that its sender does not hold")
        ),
        "the drain should revert for want of authority: {:?}",
        refused.as_ref().map(ToString::to_string)
    );
    assert_eq!(account_balance(&ctx, recipient).await?, recipient_before);

    let hash = call_draining_program(
        &ctx,
        program,
        user,
        recipient,
        AccountIdentity::Public(user).balance(),
    )
    .await
    .context("the transfer the user authorizes should be sent")?;
    wait_for_inclusion(&ctx, hash).await?;
    assert_eq!(
        account_balance(&ctx, recipient).await?,
        recipient_before + AMOUNT
    );
    Ok(())
}
