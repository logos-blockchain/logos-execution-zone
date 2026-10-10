#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use anyhow::{Context as _, Result};
use common::transaction::LeeTransaction;
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, get_account, no_seal, utils::sync_private,
    verify_commitment_is_in_state,
};
use lee::{
    AccountId, Actor, PrivacyPreservingTransaction, PrivateKey, ProvingInput,
    PublicExecutionContext, PublicKey, SenderPresentation,
    privacy_preserving_transaction::{
        circuit::{ProgramCatalog, Simulation, execute_and_prove},
        message::Message,
        witness_set::WitnessSet,
    },
    program::Program,
};
use lee_core::{
    DUMMY_COMMITMENT_HASH, NullifierPublicKey, NullifierSecretKey, NullifierWitness,
    PrivateAccountKind, PrivateWitness, RootCall, WitnessKind,
    encryption::ViewingPublicKey,
    execution_state::TransactionEntry,
    native_token::{Message as NativeMessage, NATIVE_TOKEN_PROGRAM_ID},
    program::{Call, PdaSeed},
};
use sequencer_service_rpc::RpcClient as _;
use test_guest_core::Script;
use testnet_initial_state::initial_pub_accounts_private_keys;
use tokio::test;
use wallet::{AccountIdentity, WalletCore};

/// Funds a private PDA by calling the native token program directly, initializing it under its
/// owner's `nsk`.
async fn fund_private_pda(
    wallet: &WalletCore,
    sender: AccountId,
    nsk: NullifierSecretKey,
    vpk: ViewingPublicKey,
    seed: PdaSeed,
    authority_program_id: AccountId,
    amount: u128,
) -> Result<()> {
    let pda_account_id = AccountId::for_private_pda(
        &authority_program_id,
        &seed,
        &NullifierPublicKey::from(&nsk),
        &vpk,
    );
    let sender_account = wallet
        .get_account_public(sender)
        .await
        .map_err(|e| anyhow::anyhow!("failed to get sender account: {e}"))?
        .unwrap_or_default();
    let sender_sk = wallet
        .get_account_public_signing_key(sender)
        .context("sender signing key not found")?;

    let sender_actor = Actor::native_balance(sender);
    let transfer = Program::serialize_message(NativeMessage::Transfer {
        to: pda_account_id,
        amount,
    })
    .context("failed to serialize the native transfer message")?;

    let (output, proof) = execute_and_prove(
        ProvingInput {
            root: TransactionEntry::Call(RootCall {
                to: sender_actor,
                message: transfer,
            }),
            context: PublicExecutionContext::new(vec![sender_actor], [sender]),
            private_witnesses: vec![PrivateWitness {
                vpk,
                random_seed: [0; 32],
                kind: WitnessKind::Pda {
                    nsk,
                    binding: (authority_program_id, seed),
                },
                nullifier: NullifierWitness::Init {
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
                openings: BTreeSet::new(),
            }],
            dummy_inputs: Vec::new(),
            ciphertext_padding: None,
            recoveries: Vec::new(),
            private_cast_promotions: BTreeSet::new(),
        },
        &Simulation {
            public_actor_states: [(
                sender_actor,
                sender_account
                    .data
                    .actor_state(NATIVE_TOKEN_PROGRAM_ID)
                    .clone(),
            )]
            .into(),
            admitted_accounts: None,
        },
        &ProgramCatalog::default(),
        |_| SenderPresentation::Canonical,
        |_, body| body.to.account_id == pda_account_id,
        no_seal,
    )
    .map_err(|e| anyhow::anyhow!("circuit proving failed: {e}"))?;

    let message =
        Message::from_circuit_output(BTreeMap::from([(sender, sender_account.nonce)]), output);

    let witness_set = WitnessSet::for_message(&message, proof, &[sender_sk]);
    let tx = PrivacyPreservingTransaction::new(message, witness_set);

    wallet
        .helm_owned()
        .send_transaction(LeeTransaction::PrivacyPreserving(tx))
        .await
        .map_err(|e| anyhow::anyhow!("send transaction failed: {e}"))?;

    Ok(())
}

/// Spends from an owned private PDA to a fresh private-foreign recipient, sealing its credit.
///
/// Alice must own the PDA in the wallet (i.e. it must have been synced after a receive). The
/// PDA's own actor under the proxy program is the root; it transfers out of the PDA's native
/// balance under the seed that binds the PDA to the proxy.
async fn spend_private_pda(
    wallet: &WalletCore,
    pda_account_id: AccountId,
    recipient_npk: NullifierPublicKey,
    recipient_vpk: ViewingPublicKey,
    seed: PdaSeed,
    amount: u128,
    (proxy_id, spend_program): (AccountId, &ProgramCatalog),
) -> Result<()> {
    let recipient = AccountIdentity::PrivateForeign {
        npk: recipient_npk,
        vpk: recipient_vpk,
        kind: PrivateAccountKind::Regular,
    };
    let to = recipient.account_id();
    let (_, casts) = wallet
        .seal_destination(recipient.balance())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let accounts = vec![
        AccountIdentity::PrivateOwned(pda_account_id).select_program_actor_state(proxy_id),
        AccountIdentity::PrivateOwned(pda_account_id).balance(),
    ];
    let spend = Script::default().send(
        Call::new(accounts[1].actor(), &NativeMessage::Transfer { to, amount })
            .with_pda_seeds(vec![seed]),
    );
    wallet
        .send_tx(
            accounts,
            0,
            Program::serialize_message(spend)
                .context("failed to serialize the proxy's spend script")?,
            spend_program,
            None,
            casts,
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

/// A private transfer funds Alice's private PDA, which she then spends from.
///
/// This exercises the full private PDA lifecycle: receive → sync → spend → sync → assert.
#[test]
async fn a_private_pda_receives_and_spends() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    // ── Build alice's key chain ──────────────────────────────────────────────────────────────────
    let (alice_id, _alice_chain_index) = ctx.wallet_mut().create_new_account_private(None);
    let (alice_nsk, alice_npk, alice_vpk) = {
        let account = ctx
            .wallet()
            .storage()
            .key_chain()
            .private_account(alice_id)
            .expect("Account was just created, should be present");
        let kc = account.key_chain;
        (
            kc.private_key_holder.nullifier_secret_key(),
            kc.nullifier_public_key,
            kc.viewing_public_key.clone(),
        )
    };

    let proxy = test_programs::scripted();
    // The scripted proxy is deployed fresh below, so its header target must be a real key the
    // wallet signs for — `program_loader` requires `is_authorized` for `CreateHeader`.
    let proxy_key = PrivateKey::try_new([209; 32]).unwrap();
    let proxy_id = AccountId::from(&PublicKey::new_from_private_key(&proxy_key));
    let seed = PdaSeed::new([42; 32]);
    let amount: u128 = 100;

    // The circuit anchors the PDAs' authority binding to `proxy_id`'s real on-chain image, so
    // the proxy must actually be deployed there through `program_loader`, not just known
    // locally — one `WriteSegment` per `MAX_SEGMENT_DATA_LEN` chunk of the ELF (linked
    // tail-to-head), then a `CreateHeader` naming `proxy_id` itself as the header.
    let payer = &initial_pub_accounts_private_keys()[0];
    let payer_nonce = get_account(&ctx, payer.account_id).await?.nonce;

    // Segments only ever hold `user_elf`.
    let user_elf = proxy.user_elf().expect("valid ProgramBinary");
    let chunks: Vec<&[u8]> = user_elf
        .chunks(program_loader_core::MAX_SEGMENT_DATA_LEN)
        .collect();
    // Base 230 avoids colliding with other fixed account ids in this test.
    let segment_keys: Vec<PrivateKey> = (0..chunks.len())
        .map(|i| PrivateKey::try_new([u8::try_from(i).unwrap().saturating_add(230); 32]).unwrap())
        .collect();
    let segment_ids: Vec<AccountId> = segment_keys
        .iter()
        .map(|key| AccountId::from(&PublicKey::new_from_private_key(key)))
        .collect();

    let mut next_payer_nonce = payer_nonce.0;
    for i in (0..chunks.len()).rev() {
        let segment = Actor::new(segment_ids[i], lee_core::program::PROGRAM_LOADER_ACCOUNT_ID);
        let segment_message = lee::public_transaction::Message::try_new_with_fees(
            segment,
            vec![segment],
            BTreeMap::from([
                (segment_ids[i], lee_core::account::Nonce(0)),
                (payer.account_id, lee_core::account::Nonce(next_payer_nonce)),
            ]),
            program_loader_core::Message::WriteSegment {
                bytecode: chunks[i].to_vec(),
                next_segment: segment_ids.get(i.saturating_add(1)).copied(),
            },
            common::test_utils::test_fee_declaration(payer.account_id),
        )?;
        let segment_witness_set = lee::public_transaction::WitnessSet::for_message(
            &segment_message,
            &[&segment_keys[i], &payer.pub_sign_key],
        );
        ctx.sequencer_client()
            .send_transaction(LeeTransaction::Public(lee::PublicTransaction::new(
                segment_message,
                segment_witness_set,
            )))
            .await?;
        next_payer_nonce = next_payer_nonce.saturating_add(1);

        // Segments link tail-to-head: the next chunk's `WriteSegment` must see this one
        // already on chain before it can reference it.
        tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;
    }

    let header = Actor::new(proxy_id, lee_core::program::PROGRAM_LOADER_ACCOUNT_ID);
    let header_message = lee::public_transaction::Message::try_new_with_fees(
        header,
        vec![header],
        BTreeMap::from([
            (proxy_id, lee_core::account::Nonce(0)),
            (payer.account_id, lee_core::account::Nonce(next_payer_nonce)),
        ]),
        program_loader_core::Message::CreateHeader {
            first_segment: segment_ids[0],
            immutable: true,
        },
        common::test_utils::test_fee_declaration(payer.account_id),
    )?;
    let header_witness_set = lee::public_transaction::WitnessSet::for_message(
        &header_message,
        &[&proxy_key, &payer.pub_sign_key],
    );
    ctx.sequencer_client()
        .send_transaction(LeeTransaction::Public(lee::PublicTransaction::new(
            header_message,
            header_witness_set,
        )))
        .await?;

    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let spend_program = ProgramCatalog::from([(proxy_id, proxy)]);

    let alice_pda_id = AccountId::for_private_pda(&proxy_id, &seed, &alice_npk, &alice_vpk);
    let sender = ctx.existing_public_accounts()[0];
    // Alice's wallet records the PDA it allocates, so sync follows it from its first nullifier.
    ctx.wallet_mut()
        .storage_mut()
        .key_chain_mut()
        .insert_private_account(
            alice_pda_id,
            PrivateAccountKind::Pda {
                account_id: proxy_id,
                seed,
            },
            lee::Account::default(),
        )?;

    // ── Receive ──────────────────────────────────────────────────────────────────────────────────

    log::info!("Sending to alice_pda");
    fund_private_pda(
        ctx.wallet_mut(),
        sender,
        alice_nsk,
        alice_vpk.clone(),
        seed,
        proxy_id,
        amount,
    )
    .await?;

    log::info!("Waiting for block");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Sync so alice's wallet stores the PDA's first state.
    sync_private(&mut ctx).await?;

    // The PDA must have the correct balance.
    let pda_account = ctx
        .wallet()
        .get_account_private(alice_pda_id)
        .context("alice_pda not found after sync")?;
    assert_eq!(pda_account.data.native_balance().unwrap(), amount);

    // The PDA's commitment must be in the sequencer's state.
    let commitment = ctx
        .wallet()
        .get_private_account_commitment(alice_pda_id)
        .context("commitment for alice_pda missing")?;
    assert!(
        verify_commitment_is_in_state(commitment, ctx.sequencer_client()).await,
        "alice_pda commitment not in state after receive"
    );

    // ── Spend ─────────────────────────────────────────────────────────────────────────────────────

    // A fresh recipient — a hardcoded npk not in any wallet.
    let recipient_npk = NullifierPublicKey([0xAA; 32]);
    let recipient_vpk = ViewingPublicKey::from_seed(&[0_u8; 32], &[1_u8; 32]);
    let amount_spend: u128 = 13;

    log::info!("Alice spending from alice_pda");
    spend_private_pda(
        ctx.wallet_mut(),
        alice_pda_id,
        recipient_npk,
        recipient_vpk,
        seed,
        amount_spend,
        (proxy_id, &spend_program),
    )
    .await?;

    log::info!("Waiting for block");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    sync_private(&mut ctx).await?;

    // After spending, the PDA should have the remaining balance.
    let pda_spent = ctx
        .wallet()
        .get_account_private(alice_pda_id)
        .context("alice_pda not found after spend sync")?;
    assert_eq!(
        pda_spent.data.native_balance().unwrap(),
        amount - amount_spend
    );

    // The post-spend commitment must be in state.
    let post_spend_commitment = ctx
        .wallet()
        .get_private_account_commitment(alice_pda_id)
        .context("post-spend commitment for alice_pda missing")?;
    assert!(
        verify_commitment_is_in_state(post_spend_commitment, ctx.sequencer_client()).await,
        "alice_pda post-spend commitment not in state"
    );

    log::info!("Private PDA receive-and-spend test passed");
    Ok(())
}
