#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::time::Duration;

use anyhow::Result;
use integration_tests::{
    TestContext, public_mention,
    utils::{new_account, send, sync_private},
};
use lee::{AccountId, PrivateKey};
use program_loader_core::MAX_SEGMENT_DATA_LEN;
use referral_core::{
    Invitation, NodeId, ORACLE_ACCOUNT_ID, PROTOTYPE_ORACLE_SIGNING_KEY, State,
    ed25519_dalek::{Signer as _, SigningKey},
};
use testnet_initial_state::{PublicAccountPrivateInitialData, initial_pub_accounts_private_keys};
use tokio::test;
use wallet::{
    program_facades::{program_loader::ProgramLoader, referral::Referral},
    storage::referral::{OperationKind, SubmissionStatus},
};

const ORACLE_FUNDING: u128 = 100_000_000_000;

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

async fn fund_oracle(ctx: &mut TestContext, payer: AccountId) -> Result<()> {
    send(
        ctx,
        public_mention(payer),
        public_mention(ORACLE_ACCOUNT_ID),
        ORACLE_FUNDING,
    )
    .await?;
    ctx.wallet_mut()
        .storage_mut()
        .key_chain_mut()
        .add_imported_public_account(PrivateKey::try_new(PROTOTYPE_ORACLE_SIGNING_KEY)?);
    Ok(())
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

async fn claim(
    ctx: &mut TestContext,
    program: AccountId,
    participant: AccountId,
    reference: [u8; 32],
) -> Result<u128> {
    let notes = note_ids(ctx, program, participant)?;
    let (hash, _broadcast) = facade(ctx, program)
        .submit(reference, OperationKind::Claim { participant, notes })
        .await?;
    ctx.wallet().poll_transaction(hash).await?;
    settle(ctx, program, reference).await?;

    sync_private(ctx).await?;
    reward_balance(ctx, program, participant)
}

async fn publish(
    ctx: &mut TestContext,
    program: AccountId,
    epoch: u32,
    active: &[NodeId],
) -> Result<()> {
    let hash = facade(ctx, program)
        .publish(epoch, active.iter().copied().collect())
        .await?;
    ctx.wallet().poll_transaction(hash).await?;
    Ok(())
}

fn note_ids(
    ctx: &mut TestContext,
    program: AccountId,
    participant: AccountId,
) -> Result<Vec<AccountId>> {
    Ok(facade(ctx, program)
        .notes(participant)?
        .into_iter()
        .map(|(id, _state)| id)
        .collect())
}

fn reward_balance(
    ctx: &mut TestContext,
    program: AccountId,
    participant: AccountId,
) -> Result<u128> {
    let State::Participant(record) = facade(ctx, program).state(participant)? else {
        anyhow::bail!("a registered participant's own state is a participant record");
    };
    Ok(record.reward_balance)
}

#[test]
async fn the_worked_example_pays_one_per_active_child_through_real_wallets() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let payer = genesis_payer(&mut ctx);
    let program = deploy_referral(&mut ctx, payer.account_id).await?;
    fund_oracle(&mut ctx, payer.account_id).await?;

    let (carol_key, carol_node) = node(3);
    let (alice_key, alice_node) = node(2);
    let (bob_key, bob_node) = node(1);
    let (dave_key, dave_node) = node(4);

    let carol = facade(&mut ctx, program).create_participant()?;
    let alice = facade(&mut ctx, program).create_participant()?;
    let bob = facade(&mut ctx, program).create_participant()?;
    let dave = facade(&mut ctx, program).create_participant()?;

    register(&mut ctx, program, carol, &carol_key, None, None).await?;
    let carol_invites_alice = facade(&mut ctx, program).invitation(carol, carol_node)?;
    register(
        &mut ctx,
        program,
        alice,
        &alice_key,
        Some(carol_node),
        Some(carol_invites_alice),
    )
    .await?;
    let alice_invites_bob = facade(&mut ctx, program).invitation(alice, alice_node)?;
    register(
        &mut ctx,
        program,
        bob,
        &bob_key,
        Some(alice_node),
        Some(alice_invites_bob),
    )
    .await?;

    for (participant, who) in [(carol, "Carol"), (alice, "Alice"), (bob, "Bob")] {
        assert_eq!(
            facade(&mut ctx, program).claimable(participant).await?,
            0,
            "{who} has nothing to claim before any epoch is published"
        );
    }
    let bob_notes = note_ids(&mut ctx, program, bob)?;
    let bob_refused = facade(&mut ctx, program)
        .submit(
            [1; 32],
            OperationKind::Claim {
                participant: bob,
                notes: bob_notes,
            },
        )
        .await;
    assert!(
        bob_refused.is_err(),
        "an announced child pays nothing until its node is published as active: {bob_refused:?}"
    );

    publish(&mut ctx, program, 1, &[alice_node, bob_node]).await?;

    assert_eq!(
        facade(&mut ctx, program).claimable(alice).await?,
        1,
        "Alice's only child is active in the published epoch"
    );
    assert_eq!(
        claim(&mut ctx, program, alice, [2; 32]).await?,
        1,
        "one active child pays one"
    );
    assert!(
        facade(&mut ctx, program).notes(alice)?.is_empty(),
        "and the announcement it adopted was consumed"
    );

    let carol_holds: Vec<State> = facade(&mut ctx, program)
        .notes(carol)?
        .into_iter()
        .map(|(_id, state)| state)
        .collect();
    assert_eq!(
        carol_holds.len(),
        2,
        "Carol holds an announcement and a forwarded credit"
    );
    assert!(
        carol_holds.contains(&State::Child {
            node: alice_node,
            referrer: carol_node,
        }),
        "Alice announced herself to Carol when she registered"
    );
    assert!(
        carol_holds.contains(&State::Credit {
            recipient_node: carol_node,
            amount: 1,
        }),
        "and forwarded what her own claim earned"
    );
    assert_eq!(
        facade(&mut ctx, program).claimable(carol).await?,
        2,
        "an active child of her own and the credit it forwarded"
    );
    assert_eq!(
        claim(&mut ctx, program, carol, [3; 32]).await?,
        2,
        "the chain paid her for her child and for her child's child"
    );

    assert_eq!(
        facade(&mut ctx, program).claimable(bob).await?,
        0,
        "Bob's own activity is never his own reward"
    );
    let bob_later_notes = note_ids(&mut ctx, program, bob)?;
    let bob_refused_again = facade(&mut ctx, program)
        .submit(
            [4; 32],
            OperationKind::Claim {
                participant: bob,
                notes: bob_later_notes,
            },
        )
        .await;
    assert!(
        bob_refused_again.is_err(),
        "a participant with no active children has nothing to claim: {bob_refused_again:?}"
    );

    publish(&mut ctx, program, 2, &[bob_node, dave_node]).await?;

    assert_eq!(
        facade(&mut ctx, program).claimable(alice).await?,
        1,
        "Bob is active again in the second epoch"
    );
    assert_eq!(
        claim(&mut ctx, program, alice, [5; 32]).await?,
        2,
        "an epoch pays her child once"
    );
    assert_eq!(
        facade(&mut ctx, program).claimable(carol).await?,
        1,
        "Alice fell inactive, so only the credit she forwarded is left to claim"
    );
    assert_eq!(
        claim(&mut ctx, program, carol, [6; 32]).await?,
        3,
        "the cascade pays her for activity she has no child of her own for"
    );

    let carol_invites_dave = facade(&mut ctx, program).invitation(carol, carol_node)?;
    register(
        &mut ctx,
        program,
        dave,
        &dave_key,
        Some(carol_node),
        Some(carol_invites_dave),
    )
    .await?;
    assert_eq!(
        facade(&mut ctx, program).claimable(carol).await?,
        1,
        "a child announced after this epoch's claim is still paid for it"
    );
    assert_eq!(
        claim(&mut ctx, program, carol, [7; 32]).await?,
        4,
        "the same epoch pays for the child announced after her claim"
    );

    assert_eq!(
        facade(&mut ctx, program).claimable(alice).await?,
        0,
        "the epoch that paid Alice's child pays it only once"
    );
    let alice_notes = note_ids(&mut ctx, program, alice)?;
    let alice_refused = facade(&mut ctx, program)
        .submit(
            [8; 32],
            OperationKind::Claim {
                participant: alice,
                notes: alice_notes,
            },
        )
        .await;
    assert!(
        alice_refused.is_err(),
        "a second claim in the same epoch is refused: {alice_refused:?}"
    );

    Ok(())
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
