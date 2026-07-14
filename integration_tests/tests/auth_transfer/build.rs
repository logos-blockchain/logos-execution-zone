use std::time::Duration;

use anyhow::{Context as _, Result};
use authenticated_transfer_core::Instruction as AuthTransferInstruction;
use common::transaction::LeeTransaction;
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, verify_commitment_is_in_state,
};
use lee::{privacy_preserving_transaction::circuit::ProgramWithDependencies, program::Program};
use sequencer_service_rpc::RpcClient as _;
use tokio::test;
use wallet::{AccountIdentity, poller::TxPoller};

#[test]
async fn public_build_requires_explicit_submission() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let (account_id, _) = ctx.wallet_mut().create_new_account_public(None);
    let before_build = ctx.sequencer_client().get_account(account_id).await?;

    let transaction = ctx
        .wallet()
        .build_pub_tx(
            vec![AccountIdentity::Public(account_id)],
            Program::serialize_instruction(AuthTransferInstruction::Initialize)?,
            programs::authenticated_transfer().id(),
        )
        .await?;
    let transaction = LeeTransaction::Public(transaction);
    let transaction_hash = transaction.hash();

    // Let a sequencer block interval pass: accidental submission would index the transaction.
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;
    assert!(
        ctx.sequencer_client()
            .get_transaction(transaction_hash)
            .await?
            .is_none(),
        "build_pub_tx must not submit the transaction"
    );

    let after_build = ctx.sequencer_client().get_account(account_id).await?;
    assert_eq!(after_build.balance, before_build.balance);
    assert_eq!(after_build.nonce, before_build.nonce);
    assert_eq!(after_build.program_owner, before_build.program_owner);

    let hash = ctx.wallet().submit_transaction(transaction).await?;
    assert_eq!(hash, transaction_hash);
    let (submitted, _) = TxPoller::new(ctx.wallet().config(), ctx.sequencer_client().clone())
        .poll_tx(hash)
        .await?;
    assert!(matches!(submitted, LeeTransaction::Public(_)));

    let after_submit = ctx.sequencer_client().get_account(account_id).await?;
    assert_eq!(
        after_submit.program_owner,
        programs::authenticated_transfer().id()
    );
    assert_eq!(after_submit.nonce.0, before_build.nonce.0 + 1);

    Ok(())
}

#[test]
async fn private_build_requires_explicit_submission() -> Result<()> {
    let ctx = TestContext::new().await?;
    let from = ctx.existing_private_accounts()[0];
    let to = ctx.existing_private_accounts()[1];
    let from_commitment = ctx
        .wallet()
        .get_private_account_commitment(from)
        .context("sender commitment should exist")?;
    let to_commitment = ctx
        .wallet()
        .get_private_account_commitment(to)
        .context("recipient commitment should exist")?;
    assert!(verify_commitment_is_in_state(from_commitment.clone(), ctx.sequencer_client()).await);
    assert!(verify_commitment_is_in_state(to_commitment.clone(), ctx.sequencer_client()).await);
    let program: ProgramWithDependencies = programs::authenticated_transfer().into();

    let (transaction, shared_secrets) = ctx
        .wallet()
        .build_privacy_preserving_tx(
            vec![
                AccountIdentity::PrivateOwned(from),
                AccountIdentity::PrivateOwned(to),
            ],
            Program::serialize_instruction(AuthTransferInstruction::Transfer { amount: 100 })?,
            &program,
        )
        .await?;
    let transaction = LeeTransaction::PrivacyPreserving(transaction);
    let transaction_hash = transaction.hash();

    assert_eq!(shared_secrets.len(), 2);

    // Let a sequencer block interval pass: accidental submission would index the transaction.
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;
    assert!(
        ctx.sequencer_client()
            .get_transaction(transaction_hash)
            .await?
            .is_none(),
        "build_privacy_preserving_tx must not submit the transaction"
    );
    assert!(verify_commitment_is_in_state(from_commitment, ctx.sequencer_client()).await);
    assert!(verify_commitment_is_in_state(to_commitment, ctx.sequencer_client()).await);

    let hash = ctx.wallet().submit_transaction(transaction).await?;
    assert_eq!(hash, transaction_hash);
    let (submitted, _) = TxPoller::new(ctx.wallet().config(), ctx.sequencer_client().clone())
        .poll_tx(hash)
        .await?;
    let LeeTransaction::PrivacyPreserving(submitted_transaction) = submitted else {
        anyhow::bail!("expected a privacy-preserving transaction");
    };

    assert_eq!(submitted_transaction.message.new_commitments.len(), 2);
    for commitment in submitted_transaction.message.new_commitments {
        assert!(verify_commitment_is_in_state(commitment, ctx.sequencer_client()).await);
    }

    Ok(())
}
