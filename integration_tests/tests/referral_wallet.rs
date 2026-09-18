#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::time::Duration;

use anyhow::Result;
use integration_tests::{
    TestContext,
    utils::{new_account, sync_private},
};
use lee::AccountId;
use program_loader_core::MAX_SEGMENT_DATA_LEN;
use referral_core::{
    Invitation, NodeId,
    ed25519_dalek::{Signer as _, SigningKey},
};
use testnet_initial_state::{PublicAccountPrivateInitialData, initial_pub_accounts_private_keys};
use tokio::test;
use wallet::{
    program_facades::{program_loader::ProgramLoader, referral::Referral},
    storage::referral::{OperationKind, SubmissionStatus},
};

const SETTLE_ATTEMPTS: usize = 30;

fn genesis_payer(ctx: &mut TestContext) -> PublicAccountPrivateInitialData {
    let payer = initial_pub_accounts_private_keys().swap_remove(0);
    ctx.wallet_mut()
        .storage_mut()
        .key_chain_mut()
        .add_imported_public_account(payer.pub_sign_key.clone());
    payer
}

async fn deploy_referral(ctx: &mut TestContext, payer: AccountId) -> Result<AccountId> {
    let program = programs::referral();
    let mut segments = Vec::new();
    for _ in 0..program.elf().len().div_ceil(MAX_SEGMENT_DATA_LEN) {
        segments.push(new_account(ctx, false, None).await?);
    }

    ProgramLoader(ctx.wallet())
        .deploy(
            program.id().into(),
            &segments,
            program.elf().to_vec(),
            true,
            Some(payer),
        )
        .await
}

fn facade(ctx: &mut TestContext, program: AccountId) -> Referral<'_> {
    Referral::new(ctx.wallet_mut(), programs::referral(), program)
}

async fn settle(ctx: &mut TestContext, program: AccountId, reference: [u8; 32]) -> Result<()> {
    for _ in 0..SETTLE_ATTEMPTS {
        match facade(ctx, program).reconcile(reference).await? {
            SubmissionStatus::Settled => return Ok(()),
            SubmissionStatus::Rejected => {
                anyhow::bail!("the operation was rejected instead of settling")
            }
            SubmissionStatus::Pending => tokio::time::sleep(Duration::from_secs(1)).await,
        }
    }
    anyhow::bail!("the operation never settled on its effects")
}

fn node(seed: u8) -> (SigningKey, NodeId) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let id = NodeId::new(key.verifying_key().to_bytes());
    (key, id)
}

async fn register(
    ctx: &mut TestContext,
    program: AccountId,
    participant: AccountId,
    node_key: &SigningKey,
    referrer: Option<NodeId>,
    invitation: Option<Invitation>,
) -> Result<()> {
    if let Some(from_referrer) = invitation {
        facade(ctx, program).import_invitation(participant, from_referrer)?;
    }

    let node = NodeId::new(node_key.verifying_key().to_bytes());
    let authorization = facade(ctx, program).prepare_registration(participant, node, referrer)?;
    let signature = node_key.sign(&authorization.message()).to_bytes();
    facade(ctx, program).attach_node_signature(participant, signature)?;

    let reference = node.to_bytes();
    let (hash, _broadcast) = facade(ctx, program)
        .submit(reference, OperationKind::Register { participant })
        .await?;
    ctx.wallet().poll_transaction(hash).await?;
    settle(ctx, program, reference).await?;

    sync_private(ctx).await
}

#[test]
async fn registration_bookkeeping_resumes_and_refuses_conflicts() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let payer = genesis_payer(&mut ctx);
    let program = deploy_referral(&mut ctx, payer.account_id).await?;

    let (bob_key, bob_node) = node(1);
    let (_alice_key, alice_node) = node(2);
    let bob = facade(&mut ctx, program).create_participant()?;
    let stranger = facade(&mut ctx, program).create_participant()?;

    let authorization = facade(&mut ctx, program).prepare_registration(bob, bob_node, None)?;
    let signature = bob_key.sign(&authorization.message()).to_bytes();
    facade(&mut ctx, program).attach_node_signature(bob, signature)?;

    let resumed = facade(&mut ctx, program).prepare_registration(bob, bob_node, None)?;
    assert_eq!(
        resumed.message(),
        authorization.message(),
        "the same configuration resumes the registration already recorded"
    );

    let other_node = facade(&mut ctx, program).prepare_registration(bob, alice_node, None);
    assert!(
        other_node.is_err(),
        "a second node for an unresolved registration is a conflict: {other_node:?}"
    );
    let kept = facade(&mut ctx, program)
        .pending_registration(bob)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("the refused node must leave the recorded registration"))?;
    assert_eq!(
        kept.node, bob_node,
        "the recorded node is the authorized one"
    );
    assert_eq!(
        kept.signed(),
        Some(signature),
        "and its node signature survives the refusal"
    );

    let other_deployment =
        facade(&mut ctx, AccountId::new([0xAB; 32])).prepare_registration(bob, bob_node, None);
    assert!(
        other_deployment.is_err(),
        "another deployment with the same node is a conflict: {other_deployment:?}"
    );

    let stranger_invitation = facade(&mut ctx, program).invitation(stranger, alice_node)?;
    let foreign = facade(&mut ctx, program).import_invitation(bob, stranger_invitation);
    assert!(
        foreign.is_err(),
        "an invitation naming another referrer than the participant's is refused: {foreign:?}"
    );
    let unbacked = facade(&mut ctx, program).prepare_registration(bob, bob_node, Some(alice_node));
    assert!(
        unbacked.is_err(),
        "a registration for a referrer without its invitation is refused: {unbacked:?}"
    );

    register(&mut ctx, program, bob, &bob_key, None, None).await?;
    let repeat = facade(&mut ctx, program).prepare_registration(bob, bob_node, None);
    assert!(
        repeat.is_err(),
        "a registered participant refuses a second registration: {repeat:?}"
    );

    let twin = facade(&mut ctx, program).create_participant()?;
    let twin_authorization =
        facade(&mut ctx, program).prepare_registration(twin, bob_node, None)?;
    let twin_signature = bob_key.sign(&twin_authorization.message()).to_bytes();
    facade(&mut ctx, program).attach_node_signature(twin, twin_signature)?;
    let taken = facade(&mut ctx, program)
        .submit([0x77; 32], OperationKind::Register { participant: twin })
        .await;
    assert!(
        taken.is_err(),
        "a fresh participant for a node the registry already holds is refused when its registration is built: {taken:?}"
    );
    assert_eq!(
        facade(&mut ctx, program).operation_status([0x77; 32]),
        None,
        "the refused registration is never recorded"
    );

    Ok(())
}
