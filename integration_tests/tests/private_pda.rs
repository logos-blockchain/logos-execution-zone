#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::{collections::HashMap, time::Duration};

use anyhow::{Context as _, Result};
use authenticated_transfer_core::Instruction as AuthTransferInstruction;
use common::transaction::LeeTransaction;
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, get_account, utils::sync_private,
    verify_commitment_is_in_state,
};
use lee::{
    AccountId, PrivacyPreservingTransaction, PrivateKey, ProgramId, ProgramShardSelector,
    ProvingInput, PublicKey,
    privacy_preserving_transaction::{
        circuit::{ProgramWithDependencies, execute_and_prove},
        message::Message,
        witness_set::WitnessSet,
    },
    program::Program,
};
use lee_core::{
    DUMMY_COMMITMENT_HASH, NullifierPublicKey, NullifierWitness, PrivateAccountKind,
    PrivateWitness, WitnessKind, account::Account, encryption::ViewingPublicKey, program::PdaSeed,
};
use sequencer_service_rpc::RpcClient as _;
use testnet_initial_state::initial_pub_accounts_private_keys;
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
    authority_program_id: AccountId,
    amount: u128,
    auth_transfer: &ProgramWithDependencies,
) -> Result<()> {
    let pda_account_id =
        AccountId::for_private_pda(&authority_program_id, &seed, &npk, &vpk, identifier);
    let sender_account = wallet
        .get_account_public(sender)
        .await
        .map_err(|e| anyhow::anyhow!("failed to get sender account: {e}"))?;
    let sender_sk = wallet
        .get_account_public_signing_key(sender)
        .context("sender signing key not found")?;

    let instruction = Program::serialize_instruction(AuthTransferInstruction::Transfer { amount })
        .context("failed to serialize auth_transfer instruction")?;

    let (output, proof) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::balance_only(sender),
                ProgramShardSelector::balance_only(pda_account_id),
            ],
            signers: [sender].into(),
            public_accounts: HashMap::from([(sender, sender_account.clone())]),
            private_witnesses: vec![PrivateWitness {
                account: Account::default(),
                vpk,
                random_seed: [0; 32],
                identifier,
                kind: WitnessKind::Pda {
                    binding: (authority_program_id, seed),
                },
                nullifier: NullifierWitness::Init {
                    npk,
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
            }],
            instruction_data: instruction,
            ..Default::default()
        },
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
    auth_transfer_id: ProgramId,
) -> Result<()> {
    wallet
        .send_privacy_preserving_tx(
            vec![
                AccountIdentity::PrivateOwned(pda_account_id).balance_only(),
                AccountIdentity::PrivateForeign {
                    npk: recipient_npk,
                    vpk: recipient_vpk,
                    kind: PrivateAccountKind::Regular(0),
                }
                .balance_only(),
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

    let proxy = test_programs::pda_spend_proxy();
    let auth_transfer = programs::authenticated_transfer();
    let proxy_id: AccountId = proxy.id().into();
    // Kept as a `ProgramId`: the `pda_spend_proxy` guest's instruction carries the delegate's
    // bytecode identity, converting to `AccountId` only at its own `ChainedCall` dispatch site.
    let auth_transfer_id: ProgramId = auth_transfer.id();
    let auth_transfer_account_id: AccountId = auth_transfer_id.into();
    let seed = PdaSeed::new([42; 32]);
    let amount: u128 = 100;

    // The circuit anchors the PDAs' authority binding to `proxy_id`'s real on-chain image, so
    // `pda_spend_proxy` must actually be deployed there through `program_loader`, not just known
    // locally — a `WriteSegment` claiming a fresh segment account, then a `CreateHeader` naming
    // `proxy_id` itself as the header.
    let payer = &initial_pub_accounts_private_keys()[0];
    let segment_key = PrivateKey::try_new([230; 32]).unwrap();
    let segment_id = AccountId::from(&PublicKey::new_from_private_key(&segment_key));
    let payer_nonce = get_account(&ctx, payer.account_id).await?.nonce;

    let segment_message = lee::public_transaction::Message::try_new_with_fees(
        lee_core::program::PROGRAM_LOADER_ACCOUNT_ID,
        vec![ProgramShardSelector::new(
            segment_id,
            lee_core::program::PROGRAM_LOADER_ACCOUNT_ID,
        )],
        vec![lee_core::account::Nonce(0), payer_nonce],
        program_loader_core::Instruction::WriteSegment {
            bytecode: proxy.elf().to_vec(),
            next_segment: None,
        },
        common::test_utils::test_fee_declaration(payer.account_id),
    )?;
    let segment_witness_set = lee::public_transaction::WitnessSet::for_message(
        &segment_message,
        &[&segment_key, &payer.pub_sign_key],
    );
    ctx.sequencer_client()
        .send_transaction(LeeTransaction::Public(lee::PublicTransaction::new(
            segment_message,
            segment_witness_set,
        )))
        .await?;

    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let header_message = lee::public_transaction::Message::try_new_with_fees(
        lee_core::program::PROGRAM_LOADER_ACCOUNT_ID,
        vec![
            ProgramShardSelector::new(proxy_id, lee_core::program::PROGRAM_LOADER_ACCOUNT_ID),
            ProgramShardSelector::new(segment_id, lee_core::program::PROGRAM_LOADER_ACCOUNT_ID),
        ],
        vec![lee_core::account::Nonce(payer_nonce.0 + 1)],
        program_loader_core::Instruction::CreateHeader {
            first_segment: segment_id,
            immutable: true,
        },
        common::test_utils::test_fee_declaration(payer.account_id),
    )?;
    let header_witness_set =
        lee::public_transaction::WitnessSet::for_message(&header_message, &[&payer.pub_sign_key]);
    ctx.sequencer_client()
        .send_transaction(LeeTransaction::Public(lee::PublicTransaction::new(
            header_message,
            header_witness_set,
        )))
        .await?;

    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let auth_transfer_program =
        ProgramWithDependencies::new(auth_transfer.clone(), auth_transfer_account_id, [].into());
    let spend_program = ProgramWithDependencies::new(
        proxy,
        proxy_id,
        [(auth_transfer_account_id, auth_transfer)].into(),
    );

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
    assert_eq!(pda_0_account.data.balance, amount);

    let pda_1_account = ctx
        .wallet()
        .get_account_private(alice_pda_1_id)
        .context("alice_pda_1 not found after sync")?;
    assert_eq!(pda_1_account.data.balance, amount);

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
        auth_transfer_id,
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
        auth_transfer_id,
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
    assert_eq!(pda_0_spent.data.balance, amount - amount_spend_0);

    let pda_1_spent = ctx
        .wallet()
        .get_account_private(alice_pda_1_id)
        .context("alice_pda_1 not found after spend sync")?;
    assert_eq!(pda_1_spent.data.balance, amount - amount_spend_1);

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
