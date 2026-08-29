#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::time::Duration;

use anyhow::{Context as _, Result};
use authenticated_transfer_core::Instruction as AuthTransferInstruction;
use common::transaction::LeeTransaction;
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS,
    utils::sync_private,
    verify_commitment_is_in_state,
};
use lee::{
    AccountId, PrivacyPreservingTransaction,
    privacy_preserving_transaction::{
        circuit::{ProgramWithDependencies, execute_and_prove},
        message::Message,
        witness_set::WitnessSet,
    },
    program::Program,
};
use lee_core::{
    DUMMY_COMMITMENT_HASH, InputAccountIdentity, NullifierPublicKey, NullifierWitness,
    PrivateWitness, WitnessKind,
    account::{Account, AccountWithMetadata},
    encryption::ViewingPublicKey,
    program::PdaSeed,
};
use sequencer_service_rpc::RpcClient as _;
use test_fixtures::{MultiZoneTestContextBuilder, ZoneTestContextBuilder, config::MultiNodeTestContextConfig};
use tokio::test;
use wallet::{AccountIdentity, WalletCore};

/// Funds a private PDA by calling `auth_transfer` directly.
#[expect(
    clippy::too_many_arguments,
    reason = "test helper — grouping args would obscure intent"
)]
async fn fund_private_pda(
    wallet: &WalletCore,
    sender: AccountId,
    npk: NullifierPublicKey,
    vpk: ViewingPublicKey,
    identifier: u128,
    seed: PdaSeed,
    authority_account_id: AccountId,
    amount: u128,
    auth_transfer: &ProgramWithDependencies,
) -> Result<()> {
    let pda_account_id =
        AccountId::for_private_pda(&authority_account_id, &seed, &npk, &vpk, identifier);
    let sender_account = wallet
        .get_account_public(sender)
        .await
        .map_err(|e| anyhow::anyhow!("failed to get sender account: {e}"))?;
    let sender_sk = wallet
        .get_account_public_signing_key(sender)
        .context("sender signing key not found")?;

    let sender_pre = AccountWithMetadata::new(sender_account.clone(), true, sender);
    let pda_pre = AccountWithMetadata::new(Account::default(), false, pda_account_id);

    let instruction = Program::serialize_instruction(AuthTransferInstruction::Transfer { amount })
        .context("failed to serialize auth_transfer instruction")?;

    let account_identities = vec![
        InputAccountIdentity::Public,
        InputAccountIdentity::Private(PrivateWitness {
            vpk,
            random_seed: [0; 32],
            identifier,
            kind: WitnessKind::Pda {
                binding: Some((authority_account_id, seed)),
            },
            nullifier: NullifierWitness::Init {
                npk,
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        }),
    ];

    let (output, proof) = execute_and_prove(
        vec![sender_pre, pda_pre],
        instruction,
        account_identities,
        auth_transfer,
    )
    .map_err(|e| anyhow::anyhow!("circuit proving failed: {e}"))?;

    let message = Message::from_circuit_output(vec![sender_account.nonce], output);

    let witness_set = WitnessSet::for_message(&message, proof, &[sender_sk]);
    let tx = PrivacyPreservingTransaction::new(message, witness_set);

    wallet
        .helm_owned()
        .send_transaction(LeeTransaction::PrivacyPreserving(tx))
        .await
        .map_err(|e| anyhow::anyhow!("send transaction failed: {e}"))?;

    Ok(())
}

/// Spends from an owned private PDA to a fresh private-foreign recipient.
///
/// Alice must own the PDA in the wallet (i.e. it must have been synced after a receive).
#[expect(
    clippy::too_many_arguments,
    reason = "test helper — grouping args would obscure intent"
)]
async fn spend_private_pda(
    wallet: &WalletCore,
    pda_account_id: AccountId,
    recipient_npk: NullifierPublicKey,
    recipient_vpk: ViewingPublicKey,
    seed: PdaSeed,
    amount: u128,
    spend_program: &ProgramWithDependencies,
    auth_transfer_account_id: AccountId,
) -> Result<()> {
    wallet
        .send_privacy_preserving_tx(
            vec![
                AccountIdentity::PrivatePdaOwned(pda_account_id),
                AccountIdentity::PrivateForeign {
                    npk: recipient_npk,
                    vpk: recipient_vpk,
                    identifier: 0,
                },
            ],
            Program::serialize_instruction((seed, amount, auth_transfer_account_id))
                .context("failed to serialize pda_spend_proxy instruction")?,
            spend_program,
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

/// Two private transfers go to distinct members of the same PDA family (same seed and npk,
/// but identifier=0 and identifier=1). Alice then spends from both PDAs.
///
/// This exercises the full identifier-diversified private PDA lifecycle:
///   receive(id=0), receive(id=1) → sync → spend(id=0), spend(id=1) → sync → assert.
#[test]
async fn private_pda_family_members_receive_and_spend() -> Result<()> {
    // Seeded into genesis: a live `Deploy` has no predictable address to give
    // `ProgramWithDependencies` anymore, since segment/header addresses aren't derivable.
    let proxy = test_programs::pda_spend_proxy();
    let mut ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig::default())
                .with_extra_genesis_programs(vec![proxy.clone()]),
        )
        .build()
        .await?;

    // ── Build alice's key chain ──────────────────────────────────────────────────────────────────
    let (alice_id, _alice_chain_index) = ctx.wallet_mut().create_new_account_private(None);
    let (alice_npk, alice_vpk) = {
        let account = ctx
            .wallet()
            .storage()
            .key_chain()
            .private_account(alice_id)
            .expect("Account was just created, should be present");
        let kc = account.key_chain;
        (kc.nullifier_public_key, kc.viewing_public_key.clone())
    };

    let auth_transfer = programs::authenticated_transfer();
    let proxy_id = proxy.deployed_account_id();
    let auth_transfer_id = auth_transfer.id();
    let seed = PdaSeed::new([42; 32]);
    let amount: u128 = 100;

    let auth_transfer_account_id =
        program_loader_core::immutable_deploy_account_id(auth_transfer_id);
    let auth_transfer_program = ProgramWithDependencies::new(auth_transfer.clone(), [].into())
        .with_program_account_id(auth_transfer_account_id);
    let spend_program =
        ProgramWithDependencies::new(proxy, [(auth_transfer_account_id, auth_transfer)].into());

    let alice_pda_0_id = AccountId::for_private_pda(&proxy_id, &seed, &alice_npk, &alice_vpk, 0);
    let alice_pda_1_id = AccountId::for_private_pda(&proxy_id, &seed, &alice_npk, &alice_vpk, 1);

    // Use two different public senders to avoid nonce conflicts between the back-to-back txs.
    let senders = ctx.existing_public_accounts();
    let sender_0 = senders[0];
    let sender_1 = senders[1];

    // ── Receive ──────────────────────────────────────────────────────────────────────────────────

    log::info!("Sending to alice_pda_0 (identifier=0)");
    fund_private_pda(
        ctx.wallet_mut(),
        sender_0,
        alice_npk,
        alice_vpk.clone(),
        0,
        seed,
        proxy_id,
        amount,
        &auth_transfer_program,
    )
    .await?;

    log::info!("Sending to alice_pda_1 (identifier=1)");
    fund_private_pda(
        ctx.wallet_mut(),
        sender_1,
        alice_npk,
        alice_vpk.clone(),
        1,
        seed,
        proxy_id,
        amount,
        &auth_transfer_program,
    )
    .await?;

    log::info!("Waiting for block");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Sync so alice's wallet discovers and stores both PDAs.
    sync_private(&mut ctx).await?;

    // Both PDAs must be discoverable and have the correct balance.
    let pda_0_account = ctx
        .wallet()
        .get_account_private(alice_pda_0_id)
        .context("alice_pda_0 not found after sync")?;
    assert_eq!(pda_0_account.balance, amount);

    let pda_1_account = ctx
        .wallet()
        .get_account_private(alice_pda_1_id)
        .context("alice_pda_1 not found after sync")?;
    assert_eq!(pda_1_account.balance, amount);

    // Commitments for both PDAs must be in the sequencer's state.
    let commitment_0 = ctx
        .wallet()
        .get_private_account_commitment(alice_pda_0_id)
        .context("commitment for alice_pda_0 missing")?;
    assert!(
        verify_commitment_is_in_state(commitment_0, ctx.sequencer_client()).await,
        "alice_pda_0 commitment not in state after receive"
    );

    let commitment_1 = ctx
        .wallet()
        .get_private_account_commitment(alice_pda_1_id)
        .context("commitment for alice_pda_1 missing")?;
    assert!(
        verify_commitment_is_in_state(commitment_1, ctx.sequencer_client()).await,
        "alice_pda_1 commitment not in state after receive"
    );
    assert_ne!(
        commitment_0, commitment_1,
        "distinct identifiers must yield distinct commitments"
    );

    // ── Spend ─────────────────────────────────────────────────────────────────────────────────────

    // Fresh recipients — hardcoded npks not in any wallet.
    let recipient_npk_0 = NullifierPublicKey([0xAA; 32]);
    let recipient_vpk_0 = ViewingPublicKey::from_seed(&[0_u8; 32], &[1_u8; 32]);

    let recipient_npk_1 = NullifierPublicKey([0xBB; 32]);
    let recipient_vpk_1 = ViewingPublicKey::from_seed(&[2_u8; 32], &[3_u8; 32]);

    let amount_spend_0: u128 = 13;
    let amount_spend_1: u128 = 37;

    log::info!("Alice spending from alice_pda_0");
    spend_private_pda(
        ctx.wallet_mut(),
        alice_pda_0_id,
        recipient_npk_0,
        recipient_vpk_0,
        seed,
        amount_spend_0,
        &spend_program,
        auth_transfer_account_id,
    )
    .await?;

    log::info!("Alice spending from alice_pda_1");
    spend_private_pda(
        ctx.wallet_mut(),
        alice_pda_1_id,
        recipient_npk_1,
        recipient_vpk_1,
        seed,
        amount_spend_1,
        &spend_program,
        auth_transfer_account_id,
    )
    .await?;

    log::info!("Waiting for block");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    sync_private(&mut ctx).await?;

    // After spending, PDAs should have the remaining balance.
    let pda_0_spent = ctx
        .wallet()
        .get_account_private(alice_pda_0_id)
        .context("alice_pda_0 not found after spend sync")?;
    assert_eq!(pda_0_spent.balance, amount - amount_spend_0);

    let pda_1_spent = ctx
        .wallet()
        .get_account_private(alice_pda_1_id)
        .context("alice_pda_1 not found after spend sync")?;
    assert_eq!(pda_1_spent.balance, amount - amount_spend_1);

    // Post-spend commitments must be in state.
    let post_spend_commitment_0 = ctx
        .wallet()
        .get_private_account_commitment(alice_pda_0_id)
        .context("post-spend commitment for alice_pda_0 missing")?;
    assert!(
        verify_commitment_is_in_state(post_spend_commitment_0, ctx.sequencer_client()).await,
        "alice_pda_0 post-spend commitment not in state"
    );

    let post_spend_commitment_1 = ctx
        .wallet()
        .get_private_account_commitment(alice_pda_1_id)
        .context("post-spend commitment for alice_pda_1 missing")?;
    assert!(
        verify_commitment_is_in_state(post_spend_commitment_1, ctx.sequencer_client()).await,
        "alice_pda_1 post-spend commitment not in state"
    );

    log::info!("Private PDA family member receive-and-spend test passed");
    Ok(())
}
