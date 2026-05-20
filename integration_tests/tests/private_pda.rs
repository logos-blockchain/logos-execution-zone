#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::{path::PathBuf, time::Duration};

use anyhow::{Context as _, Result};
use authenticated_transfer_core::Instruction as AuthTransferInstruction;
use common::transaction::LeeTransaction;
use integration_tests::{
    LEE_PROGRAM_FOR_TEST_PDA_SPEND_PROXY, TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext,
    verify_commitment_is_in_state,
};
use key_protocol::key_management::ephemeral_key_holder::EphemeralKeyHolder;
use lee::{
    AccountId, PrivacyPreservingTransaction, ProgramId,
    privacy_preserving_transaction::{
        circuit::{ProgramWithDependencies, execute_and_prove},
        message::Message,
        witness_set::WitnessSet,
    },
    program::Program,
};
use lee_core::{
    InputAccountIdentity, NullifierPublicKey,
    account::{Account, AccountWithMetadata},
    encryption::ViewingPublicKey,
    program::PdaSeed,
};
use log::info;
use sequencer_service_rpc::RpcClient as _;
use tokio::test;
use wallet::{
    AccountIdentity, WalletCore,
    cli::{Command, account::AccountSubcommand},
};

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
    authority_program_id: ProgramId,
    amount: u128,
    auth_transfer: &ProgramWithDependencies,
) -> Result<()> {
    let pda_account_id = AccountId::for_private_pda(&authority_program_id, &seed, &npk, identifier);
    let sender_account = wallet
        .get_account_public(sender)
        .await
        .map_err(|e| anyhow::anyhow!("failed to get sender account: {e}"))?;
    let sender_sk = wallet
        .get_account_public_signing_key(sender)
        .context("sender signing key not found")?;

    let sender_pre = AccountWithMetadata::new(sender_account.clone(), true, sender);
    let pda_pre = AccountWithMetadata::new(Account::default(), false, pda_account_id);

    let eph_holder = EphemeralKeyHolder::new(&npk);
    let ssk = eph_holder.calculate_shared_secret_sender(&vpk);
    let epk = eph_holder.generate_ephemeral_public_key();

    let instruction = Program::serialize_instruction(AuthTransferInstruction::Transfer { amount })
        .context("failed to serialize auth_transfer instruction")?;

    let account_identities = vec![
        InputAccountIdentity::Public,
        InputAccountIdentity::PrivatePdaInit {
            npk,
            ssk,
            identifier,
            seed: Some((seed, authority_program_id)),
        },
    ];

    let (output, proof) = execute_and_prove(
        vec![sender_pre, pda_pre],
        instruction,
        account_identities,
        auth_transfer,
    )
    .map_err(|e| anyhow::anyhow!("circuit proving failed: {e}"))?;

    let message = Message::try_from_circuit_output(
        vec![sender],
        vec![sender_account.nonce],
        vec![(npk, vpk, epk)],
        output,
    )
    .map_err(|e| anyhow::anyhow!("message build failed: {e}"))?;

    let witness_set = WitnessSet::for_message(&message, proof, &[sender_sk]);
    let tx = PrivacyPreservingTransaction::new(message, witness_set);

    wallet
        .sequencer_client
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
    auth_transfer_id: ProgramId,
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
            Program::serialize_instruction((seed, amount, auth_transfer_id))
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
    let mut ctx = TestContext::new().await?;

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

    let proxy = {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../artifacts/test_program_methods")
            .join(LEE_PROGRAM_FOR_TEST_PDA_SPEND_PROXY);
        Program::new(std::fs::read(&path).with_context(|| format!("reading {path:?}"))?)
            .context("invalid pda_spend_proxy binary")?
    };
    let auth_transfer = Program::authenticated_transfer_program();
    let proxy_id = proxy.id();
    let auth_transfer_id = auth_transfer.id();
    let seed = PdaSeed::new([42; 32]);
    let amount: u128 = 100;

    let auth_transfer_program = ProgramWithDependencies::new(auth_transfer.clone(), [].into());
    let spend_program =
        ProgramWithDependencies::new(proxy, [(auth_transfer_id, auth_transfer)].into());

    let alice_pda_0_id = AccountId::for_private_pda(&proxy_id, &seed, &alice_npk, 0);
    let alice_pda_1_id = AccountId::for_private_pda(&proxy_id, &seed, &alice_npk, 1);

    // Use two different public senders to avoid nonce conflicts between the back-to-back txs.
    let senders = ctx.existing_public_accounts();
    let sender_0 = senders[0];
    let sender_1 = senders[1];

    // ── Receive ──────────────────────────────────────────────────────────────────────────────────

    info!("Sending to alice_pda_0 (identifier=0)");
    fund_private_pda(
        ctx.wallet(),
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

    info!("Sending to alice_pda_1 (identifier=1)");
    fund_private_pda(
        ctx.wallet(),
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

    info!("Waiting for block");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Sync so alice's wallet discovers and stores both PDAs.
    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::SyncPrivate {}),
    )
    .await?;

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
        verify_commitment_is_in_state(commitment_0.clone(), ctx.sequencer_client()).await,
        "alice_pda_0 commitment not in state after receive"
    );

    let commitment_1 = ctx
        .wallet()
        .get_private_account_commitment(alice_pda_1_id)
        .context("commitment for alice_pda_1 missing")?;
    assert!(
        verify_commitment_is_in_state(commitment_1.clone(), ctx.sequencer_client()).await,
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

    info!("Alice spending from alice_pda_0");
    spend_private_pda(
        ctx.wallet(),
        alice_pda_0_id,
        recipient_npk_0,
        recipient_vpk_0,
        seed,
        amount_spend_0,
        &spend_program,
        auth_transfer_id,
    )
    .await?;

    info!("Alice spending from alice_pda_1");
    spend_private_pda(
        ctx.wallet(),
        alice_pda_1_id,
        recipient_npk_1,
        recipient_vpk_1,
        seed,
        amount_spend_1,
        &spend_program,
        auth_transfer_id,
    )
    .await?;

    info!("Waiting for block");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::SyncPrivate {}),
    )
    .await?;

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

    info!("Private PDA family member receive-and-spend test passed");
    Ok(())
}
