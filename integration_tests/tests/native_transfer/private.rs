use std::{collections::BTreeSet, time::Duration};

use anyhow::{Context as _, Result};
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, fetch_privacy_preserving_tx, no_seal,
    private_mention, public_mention,
    utils::{
        account_balance, assert_private_commitment_in_state, new_account, receive_pending, send,
        sync_private,
    },
    verify_commitment_is_in_state,
};
use lee::{
    AccountId, Actor, ProvingInput, PublicExecutionContext, SenderPresentation, Simulation,
    execute_and_prove, privacy_preserving_transaction::circuit::ProgramCatalog, program::Program,
};
use lee_core::{
    DUMMY_COMMITMENT_HASH, Nullifier, NullifierPublicKey, NullifierWitness, PrivateWitness,
    RegularKey, RootCall, WitnessKind, encryption::ViewingPublicKey,
    execution_state::TransactionEntry, native_token,
};
use sequencer_service_rpc::RpcClient as _;
use tokio::test;
use wallet::{
    account::Label,
    cli::{
        CliAccountMention, Command, SubcommandReturnValue, account::AccountSubcommand,
        programs::native_token_transfer::AuthTransferSubcommand,
    },
};

#[test]
async fn private_transfer_to_owned_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let from: AccountId = ctx.existing_private_accounts()[0];
    let to: AccountId = ctx.existing_private_accounts()[1];

    send(&mut ctx, private_mention(from), private_mention(to), 100).await?;

    log::info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    assert_private_commitment_in_state(&ctx, from, "sender").await?;
    assert_private_commitment_in_state(&ctx, to, "receiver").await?;

    log::info!("Successfully transferred privately to owned account");

    Ok(())
}

#[test]
async fn private_transfer_to_foreign_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let from: AccountId = ctx.existing_private_accounts()[0];
    let to_npk = NullifierPublicKey([42; 32]);
    let to_npk_string = hex::encode(to_npk.0);
    let to_vpk = ViewingPublicKey::from_seed(&[0_u8; 32], &[1_u8; 32]);

    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: private_mention(from),
        to: None,
        to_npk: Some(to_npk_string),
        to_vpk: Some(hex::encode(to_vpk.to_bytes())),
        to_keys: None,
        to_pk: None,
        amount: 100,
    });

    let result = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::TransactionExecuted { tx_hash } = result else {
        anyhow::bail!("Expected TransactionExecuted return value");
    };

    log::info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let new_commitment1 = ctx
        .wallet()
        .get_private_account_commitment(from)
        .context("Failed to get private account commitment for sender")?;

    let tx = fetch_privacy_preserving_tx(ctx.sequencer_client(), tx_hash).await;
    assert!(
        tx.message
            .execution
            .commitments()
            .contains(&new_commitment1)
    );

    for commitment in tx.message.execution.commitments() {
        assert!(verify_commitment_is_in_state(commitment, ctx.sequencer_client()).await);
    }

    log::info!("Successfully transferred privately to foreign account");

    Ok(())
}

#[test]
async fn deshielded_transfer_to_public_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let from: AccountId = ctx.existing_private_accounts()[0];
    let to: AccountId = ctx.existing_public_accounts()[1];

    // Check initial balance of the private sender
    let from_acc = ctx
        .wallet()
        .get_account_private(from)
        .context("Failed to get sender's private account")?;
    assert_eq!(from_acc.data.native_balance().unwrap(), 10000);
    let to_before = account_balance(&ctx, to).await?;

    send(&mut ctx, private_mention(from), public_mention(to), 100).await?;

    log::info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let from_acc = ctx
        .wallet()
        .get_account_private(from)
        .context("Failed to get sender's private account")?;
    assert_private_commitment_in_state(&ctx, from, "sender").await?;

    let acc_2_balance = account_balance(&ctx, to).await?;

    // A deshielded transfer is a privacy-preserving transaction — fee-exempt
    // under the interim policy — so both sides move by exactly the amount.
    assert_eq!(from_acc.data.native_balance().unwrap(), 9900);
    assert_eq!(acc_2_balance, to_before + 100);

    log::info!("Successfully deshielded transfer to public account");

    Ok(())
}

/// Two senders deshield to one receiver without waiting for settlement.
/// Settlement must retain both credits.
#[test]
async fn concurrent_deshielded_transfers_settle_against_live_state() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let sender_1: AccountId = ctx.existing_private_accounts()[0];
    let sender_2: AccountId = ctx.existing_private_accounts()[1];
    let receiver: AccountId = ctx.existing_public_accounts()[2];

    let sender_1_before = ctx
        .wallet()
        .get_account_private(sender_1)
        .context("Failed to get sender_1's private account")?
        .data
        .native_balance()
        .unwrap();
    let sender_2_before = ctx
        .wallet()
        .get_account_private(sender_2)
        .context("Failed to get sender_2's private account")?
        .data
        .native_balance()
        .unwrap();
    let receiver_before = account_balance(&ctx, receiver).await?;

    // Submitted with no wait between them — both prove against the receiver's pre-transfer
    // balance, exactly the concurrent scenario this branch's effect model exists to settle
    // correctly.
    send(
        &mut ctx,
        private_mention(sender_1),
        public_mention(receiver),
        30,
    )
    .await?;
    send(
        &mut ctx,
        private_mention(sender_2),
        public_mention(receiver),
        20,
    )
    .await?;

    log::info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let sender_1_after = ctx
        .wallet()
        .get_account_private(sender_1)
        .context("Failed to get sender_1's private account")?
        .data
        .native_balance()
        .unwrap();
    let sender_2_after = ctx
        .wallet()
        .get_account_private(sender_2)
        .context("Failed to get sender_2's private account")?
        .data
        .native_balance()
        .unwrap();
    let receiver_after = account_balance(&ctx, receiver).await?;

    assert_private_commitment_in_state(&ctx, sender_1, "sender_1").await?;
    assert_private_commitment_in_state(&ctx, sender_2, "sender_2").await?;

    // Deshielded transfers are fee-exempt under the interim policy, so each side moves by
    // exactly the amount.
    assert_eq!(
        sender_1_after,
        sender_1_before - 30,
        "sender_1 must reflect its own debit"
    );
    assert_eq!(
        sender_2_after,
        sender_2_before - 20,
        "sender_2 must reflect its own debit"
    );
    assert_eq!(
        receiver_after,
        receiver_before + 50,
        "receiver must reflect both credits (30 + 20), not just whichever transfer settled last"
    );

    log::info!("Successfully settled two concurrent deshielded transfers against live state");

    Ok(())
}

/// A deshielded transfer's public recipient must not be asked to sign the transaction: the
/// sender's private-side proof is the only authorization the protocol requires, and signing
/// with the recipient's key (when the wallet happens to hold it) would leak a link between
/// the two accounts.
#[test]
async fn deshielded_transfer_does_not_sign_with_recipient_key() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let from: AccountId = ctx.existing_private_accounts()[0];
    let to: AccountId = ctx.existing_public_accounts()[1];

    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: private_mention(from),
        to: Some(public_mention(to)),
        to_npk: None,
        to_vpk: None,
        to_keys: None,
        to_pk: None,
        amount: 100,
    });

    let result = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::TransactionExecuted { tx_hash } = result else {
        anyhow::bail!("Expected TransactionExecuted return value");
    };

    log::info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let tx = fetch_privacy_preserving_tx(ctx.sequencer_client(), tx_hash).await;

    assert!(
        tx.witness_set().signatures_and_public_keys().is_empty(),
        "deshielded transfer must not carry any signature, in particular not the recipient's"
    );

    log::info!("Deshielded transfer correctly did not sign with the recipient's key");

    Ok(())
}

#[test]
async fn private_transfer_to_owned_account_over_foreign_keys() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let from: AccountId = ctx.existing_private_accounts()[0];

    // Create a new private account
    let to_account_id = new_account(&mut ctx, true, None).await?;

    // Get the keys for the newly created account
    let to = ctx
        .wallet()
        .storage()
        .key_chain()
        .private_account(to_account_id)
        .context("Failed to get private account")?;

    // Send to this account over the foreign-keys path (npk and vpk instead of the account ID)
    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: private_mention(from),
        to: None,
        to_npk: Some(hex::encode(to.key_chain.nullifier_public_key.0)),
        to_vpk: Some(hex::encode(to.key_chain.viewing_public_key.to_bytes())),
        to_keys: None,
        to_pk: None,
        amount: 100,
    });

    let sub_ret = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::TransactionExecuted { tx_hash } = sub_ret else {
        anyhow::bail!("Expected TransactionExecuted return value");
    };

    let tx = fetch_privacy_preserving_tx(ctx.sequencer_client(), tx_hash).await;

    // Sync the wallet to discover the new account
    sync_private(&mut ctx).await?;

    let sender_commitment = ctx
        .wallet()
        .get_private_account_commitment(from)
        .context("Failed to get private account commitment for sender")?;
    assert!(
        tx.message
            .execution
            .commitments()
            .contains(&sender_commitment)
    );

    for commitment in tx.message.execution.commitments() {
        assert!(verify_commitment_is_in_state(commitment, ctx.sequencer_client()).await);
    }

    // Sent by keys, the credit is pending until the owner receives it.
    receive_pending(&mut ctx).await?;
    let to_res_acc = ctx
        .wallet()
        .get_account_private(to_account_id)
        .context("Failed to get recipient's private account")?;
    assert_eq!(to_res_acc.data.native_balance().unwrap(), 100);

    log::info!("Successfully transferred over the foreign-keys path");

    Ok(())
}

#[test]
async fn shielded_transfer_to_owned_private_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let from: AccountId = ctx.existing_public_accounts()[0];
    let to: AccountId = ctx.existing_private_accounts()[1];
    let from_before = account_balance(&ctx, from).await?;

    send(&mut ctx, public_mention(from), private_mention(to), 100).await?;

    log::info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let acc_to = ctx
        .wallet()
        .get_account_private(to)
        .context("Failed to get receiver's private account")?;
    assert_private_commitment_in_state(&ctx, to, "receiver").await?;

    let acc_from_balance = account_balance(&ctx, from).await?;

    // A shielded transfer is a privacy-preserving transaction — fee-exempt
    // under the interim policy — so the public sender pays exactly the amount.
    assert_eq!(acc_from_balance, from_before - 100);
    assert_eq!(acc_to.data.native_balance().unwrap(), 20100);

    log::info!("Successfully shielded transfer to owned private account");

    Ok(())
}

#[test]
async fn shielded_transfer_to_foreign_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let to_npk = NullifierPublicKey([42; 32]);
    let to_npk_string = hex::encode(to_npk.0);
    let to_vpk = ViewingPublicKey::from_seed(&[0_u8; 32], &[1_u8; 32]);
    let from: AccountId = ctx.existing_public_accounts()[0];
    let from_before = account_balance(&ctx, from).await?;

    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: public_mention(from),
        to: None,
        to_npk: Some(to_npk_string),
        to_vpk: Some(hex::encode(to_vpk.to_bytes())),
        to_keys: None,
        to_pk: None,
        amount: 100,
    });

    let result = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::TransactionExecuted { tx_hash } = result else {
        anyhow::bail!("Expected TransactionExecuted return value");
    };

    log::info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let tx = fetch_privacy_preserving_tx(ctx.sequencer_client(), tx_hash).await;

    let acc_1_balance = account_balance(&ctx, from).await?;

    for commitment in tx.message.execution.commitments() {
        assert!(verify_commitment_is_in_state(commitment, ctx.sequencer_client()).await);
    }

    // Privacy-preserving, so fee-exempt: the sender pays exactly the amount.
    assert_eq!(acc_1_balance, from_before - 100);

    log::info!("Successfully shielded transfer to foreign account");

    Ok(())
}

#[test]
#[ignore = "Flaky, TODO: #197"]
async fn private_transfer_to_owned_account_continuous_run_path() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    // NOTE: This test needs refactoring - continuous run mode doesn't work well with TestContext
    // The original implementation spawned wallet::cli::execute_continuous_run() in background
    // but this conflicts with TestContext's wallet management

    let from: AccountId = ctx.existing_private_accounts()[0];

    // Create a new private account
    let to_account_id = new_account(&mut ctx, true, None).await?;

    // Get the newly created account's keys
    let to = ctx
        .wallet()
        .storage()
        .key_chain()
        .private_account(to_account_id)
        .context("Failed to get private account")?;

    // Send transfer using nullifier and  viewing public keys
    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: private_mention(from),
        to: None,
        to_npk: Some(hex::encode(to.key_chain.nullifier_public_key.0)),
        to_vpk: Some(hex::encode(to.key_chain.viewing_public_key.to_bytes())),
        to_keys: None,
        to_pk: None,
        amount: 100,
    });

    let sub_ret = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::TransactionExecuted { tx_hash } = sub_ret else {
        anyhow::bail!("Failed to send transaction");
    };

    let tx = fetch_privacy_preserving_tx(ctx.sequencer_client(), tx_hash).await;

    log::info!("Waiting for next blocks to check if continuous run fetches account");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Verify commitments are in state
    for commitment in tx.message.execution.commitments() {
        assert!(verify_commitment_is_in_state(commitment, ctx.sequencer_client()).await);
    }

    // Sent by keys, the credit is pending until the owner receives it.
    receive_pending(&mut ctx).await?;
    let to_res_acc = ctx
        .wallet()
        .get_account_private(to_account_id)
        .context("Failed to get receiver account")?;

    assert_eq!(to_res_acc.data.native_balance().unwrap(), 100);

    Ok(())
}

#[test]
async fn private_transfer_using_from_label() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let from: AccountId = ctx.existing_private_accounts()[0];
    let to: AccountId = ctx.existing_private_accounts()[1];

    // Assign a label to the sender account
    let label = Label::new("private-sender-label");
    let command = Command::Account(AccountSubcommand::Label {
        account_id: private_mention(from),
        label: label.clone(),
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    // Send using the label instead of account ID
    send(
        &mut ctx,
        CliAccountMention::Label(label),
        private_mention(to),
        100,
    )
    .await?;

    log::info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    assert_private_commitment_in_state(&ctx, from, "sender").await?;
    assert_private_commitment_in_state(&ctx, to, "receiver").await?;

    log::info!("Successfully transferred privately using from_label");

    Ok(())
}

fn prove_init_with_commitment_root(
    ctx: &TestContext,
    commitment_root: lee_core::CommitmentSetDigest,
) -> Result<lee_core::PrivacyPreservingCircuitOutput> {
    let sender_id = ctx.existing_public_accounts()[0];

    let ask = lee_core::AuthorizationSecretKey([7; 32]);
    let nsk = lee_core::NullifierSecretKey::from(&ask);
    let npk = NullifierPublicKey::from(&nsk);
    let vpk = ViewingPublicKey::from_bytes(vec![4_u8; 1184]).unwrap();
    let recipient_account_id = AccountId::for_regular_private_account(&npk, &vpk);

    let sender = Actor::native_balance(sender_id);
    let (output, _) = execute_and_prove(
        ProvingInput {
            root: TransactionEntry::Call(RootCall {
                to: sender,
                message: Program::serialize_message(native_token::Message::Transfer {
                    to: recipient_account_id,
                    amount: 1,
                })?,
            }),
            context: PublicExecutionContext::new(vec![sender], [sender_id]),
            private_witnesses: vec![PrivateWitness {
                vpk,
                random_seed: [0; 32],
                kind: WitnessKind::Regular(RegularKey::Authorized(ask)),
                nullifier: NullifierWitness::Init { commitment_root },
                openings: BTreeSet::new(),
            }],
            dummy_inputs: Vec::new(),
            ciphertext_padding: None,
            recoveries: Vec::new(),
            private_cast_promotions: BTreeSet::new(),
        },
        &Simulation {
            // The proof is only inspected, never settled, so the snapshot states just enough
            // balance.
            public_actor_states: [(sender, native_token::encode_balance(1))].into(),
            admitted_accounts: None,
        },
        &ProgramCatalog::default(),
        |_| SenderPresentation::Canonical,
        |_, _| false,
        no_seal,
    )?;

    Ok(output)
}

#[test]
async fn init_with_dummy_commitment_root_produces_valid_root() -> Result<()> {
    let ctx = TestContext::new().await?;

    let (_, _, expected_digest) = ctx
        .sequencer_client()
        .get_proofs_and_root(vec![], None)
        .await?;

    let ask = lee_core::AuthorizationSecretKey([7; 32]);
    let nsk = lee_core::NullifierSecretKey::from(&ask);
    let npk = NullifierPublicKey::from(&nsk);
    let vpk = ViewingPublicKey::from_bytes(vec![4_u8; 1184]).unwrap();
    let recipient_account_id = AccountId::for_regular_private_account(&npk, &vpk);

    let output = prove_init_with_commitment_root(&ctx, expected_digest)?;

    assert_eq!(output.execution.private_actions.len(), 1);
    let action = &output.execution.private_actions[0];
    let (nullifier, digest) = (&action.nullifier, &action.root);
    assert_eq!(
        *nullifier,
        Nullifier::for_account_initialization(&recipient_account_id, &nsk)
    );
    assert_eq!(*digest, expected_digest);
    assert_ne!(*digest, DUMMY_COMMITMENT_HASH);

    Ok(())
}

#[test]
async fn init_nullifier_digest_is_bound_to_commitment_root() -> Result<()> {
    let ctx = TestContext::new().await?;

    let (_, _, expected_digest) = ctx
        .sequencer_client()
        .get_proofs_and_root(vec![], None)
        .await?;

    let output_with_root = prove_init_with_commitment_root(&ctx, expected_digest)?;
    let output_without_root = prove_init_with_commitment_root(&ctx, DUMMY_COMMITMENT_HASH)?;

    assert_eq!(
        output_with_root.execution.private_actions[0].root,
        expected_digest
    );
    assert_eq!(
        output_without_root.execution.private_actions[0].root,
        DUMMY_COMMITMENT_HASH
    );
    assert_ne!(
        output_with_root.execution.private_actions[0].root,
        output_without_root.execution.private_actions[0].root,
    );

    Ok(())
}
