use std::time::Duration;

use anyhow::{Context as _, Result};
use common::transaction::LeeTransaction;
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, account_balance,
    assert_private_commitment_in_state, fetch_privacy_preserving_tx, get_account, new_account,
    private_mention, public_mention, send, sync_private, verify_commitment_is_in_state,
};
use lee::{
    AccountId, execute_and_prove, privacy_preserving_transaction::circuit::ProgramWithDependencies,
    program::Program,
};
use lee_core::{
    DUMMY_COMMITMENT_HASH, InputAccountIdentity, Nullifier, NullifierPublicKey,
    account::{Account, AccountWithMetadata},
    encryption::ViewingPublicKey,
};
use log::info;
use sequencer_service_rpc::RpcClient as _;
use tokio::test;
use wallet::{
    account::Label,
    cli::{
        CliAccountMention, Command, SubcommandReturnValue,
        account::{AccountSubcommand, NewSubcommand},
        programs::native_token_transfer::AuthTransferSubcommand,
    },
};

#[test]
async fn private_transfer_to_owned_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let from: AccountId = ctx.existing_private_accounts()[0];
    let to: AccountId = ctx.existing_private_accounts()[1];

    send(&mut ctx, private_mention(from), private_mention(to), 100).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    assert_private_commitment_in_state(&ctx, from, "sender").await?;
    assert_private_commitment_in_state(&ctx, to, "receiver").await?;

    info!("Successfully transferred privately to owned account");

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
        to_identifier: Some(0),
        amount: 100,
    });

    let result = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::TransactionExecuted { tx_hash } = result else {
        anyhow::bail!("Expected TransactionExecuted return value");
    };

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let new_commitment1 = ctx
        .wallet()
        .get_private_account_commitment(from)
        .context("Failed to get private account commitment for sender")?;

    let tx = fetch_privacy_preserving_tx(ctx.sequencer_client(), tx_hash).await;
    assert_eq!(tx.message.new_commitments[0], new_commitment1);

    assert_eq!(tx.message.new_commitments.len(), 2);
    for commitment in tx.message.new_commitments {
        assert!(verify_commitment_is_in_state(commitment, ctx.sequencer_client()).await);
    }

    info!("Successfully transferred privately to foreign account");

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
    assert_eq!(from_acc.balance, 10000);

    send(&mut ctx, private_mention(from), public_mention(to), 100).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let from_acc = ctx
        .wallet()
        .get_account_private(from)
        .context("Failed to get sender's private account")?;
    assert_private_commitment_in_state(&ctx, from, "sender").await?;

    let acc_2_balance = account_balance(&ctx, to).await?;

    assert_eq!(from_acc.balance, 9900);
    assert_eq!(acc_2_balance, 20100);

    info!("Successfully deshielded transfer to public account");

    Ok(())
}

#[test]
async fn private_transfer_to_owned_account_using_claiming_path() -> Result<()> {
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

    // Send to this account using claiming path (using npk and vpk instead of account ID)
    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: private_mention(from),
        to: None,
        to_npk: Some(hex::encode(to.key_chain.nullifier_public_key.0)),
        to_vpk: Some(hex::encode(to.key_chain.viewing_public_key.to_bytes())),
        to_keys: None,
        to_identifier: Some(to.kind.identifier()),
        amount: 100,
    });

    let sub_ret = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::TransactionExecuted { tx_hash } = sub_ret else {
        anyhow::bail!("Expected TransactionExecuted return value");
    };

    let tx = fetch_privacy_preserving_tx(ctx.sequencer_client(), tx_hash).await;

    // Sync the wallet to claim the new account
    sync_private(&mut ctx).await?;

    let sender_commitment = ctx
        .wallet()
        .get_private_account_commitment(from)
        .context("Failed to get private account commitment for sender")?;
    assert_eq!(tx.message.new_commitments[0], sender_commitment);

    assert_eq!(tx.message.new_commitments.len(), 2);
    for commitment in tx.message.new_commitments {
        assert!(verify_commitment_is_in_state(commitment, ctx.sequencer_client()).await);
    }

    let to_res_acc = ctx
        .wallet()
        .get_account_private(to_account_id)
        .context("Failed to get recipient's private account")?;
    assert_eq!(to_res_acc.balance, 100);

    info!("Successfully transferred using claiming path");

    Ok(())
}

#[test]
async fn shielded_transfer_to_owned_private_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let from: AccountId = ctx.existing_public_accounts()[0];
    let to: AccountId = ctx.existing_private_accounts()[1];

    send(&mut ctx, public_mention(from), private_mention(to), 100).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let acc_to = ctx
        .wallet()
        .get_account_private(to)
        .context("Failed to get receiver's private account")?;
    assert_private_commitment_in_state(&ctx, to, "receiver").await?;

    let acc_from_balance = account_balance(&ctx, from).await?;

    assert_eq!(acc_from_balance, 9900);
    assert_eq!(acc_to.balance, 20100);

    info!("Successfully shielded transfer to owned private account");

    Ok(())
}

#[test]
async fn shielded_transfer_to_foreign_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let to_npk = NullifierPublicKey([42; 32]);
    let to_npk_string = hex::encode(to_npk.0);
    let to_vpk = ViewingPublicKey::from_seed(&[0_u8; 32], &[1_u8; 32]);
    let from: AccountId = ctx.existing_public_accounts()[0];

    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: public_mention(from),
        to: None,
        to_npk: Some(to_npk_string),
        to_vpk: Some(hex::encode(to_vpk.to_bytes())),
        to_keys: None,
        to_identifier: Some(0),
        amount: 100,
    });

    let result = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::TransactionExecuted { tx_hash } = result else {
        anyhow::bail!("Expected TransactionExecuted return value");
    };

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let tx = fetch_privacy_preserving_tx(ctx.sequencer_client(), tx_hash).await;

    let acc_1_balance = account_balance(&ctx, from).await?;

    assert!(
        verify_commitment_is_in_state(tx.message.new_commitments[0], ctx.sequencer_client()).await
    );

    assert_eq!(acc_1_balance, 9900);

    info!("Successfully shielded transfer to foreign account");

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
        to_identifier: Some(to.kind.identifier()),
        amount: 100,
    });

    let sub_ret = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::TransactionExecuted { tx_hash } = sub_ret else {
        anyhow::bail!("Failed to send transaction");
    };

    let tx = fetch_privacy_preserving_tx(ctx.sequencer_client(), tx_hash).await;

    info!("Waiting for next blocks to check if continuous run fetches account");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Verify commitments are in state
    assert_eq!(tx.message.new_commitments.len(), 2);
    for commitment in tx.message.new_commitments {
        assert!(verify_commitment_is_in_state(commitment, ctx.sequencer_client()).await);
    }

    // Verify receiver account balance
    let to_res_acc = ctx
        .wallet()
        .get_account_private(to_account_id)
        .context("Failed to get receiver account")?;

    assert_eq!(to_res_acc.balance, 100);

    Ok(())
}

#[test]
async fn initialize_private_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let account_id = new_account(&mut ctx, true, None).await?;

    let command = Command::AuthTransfer(AuthTransferSubcommand::Init {
        account_id: private_mention(account_id),
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    info!("Syncing private accounts");
    sync_private(&mut ctx).await?;

    assert_private_commitment_in_state(&ctx, account_id, "account").await?;

    let account = ctx
        .wallet()
        .get_account_private(account_id)
        .context("Failed to get private account")?;

    assert_eq!(
        account.program_owner,
        programs::authenticated_transfer().id()
    );
    assert_eq!(account.balance, 0);
    assert!(account.data.is_empty());

    info!("Successfully initialized private account");

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

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    assert_private_commitment_in_state(&ctx, from, "sender").await?;
    assert_private_commitment_in_state(&ctx, to, "receiver").await?;

    info!("Successfully transferred privately using from_label");

    Ok(())
}

#[test]
async fn initialize_private_account_using_label() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    // Create a new private account with a label
    let label = Label::new("init-private-label");
    let command = Command::Account(AccountSubcommand::New(NewSubcommand::Private {
        cci: None,
        label: Some(label.clone()),
    }));
    let result = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::RegisterAccount { account_id } = result else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Initialize using the label instead of account ID
    let command = Command::AuthTransfer(AuthTransferSubcommand::Init {
        account_id: label.into(),
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    sync_private(&mut ctx).await?;

    assert_private_commitment_in_state(&ctx, account_id, "account").await?;

    let account = ctx
        .wallet()
        .get_account_private(account_id)
        .context("Failed to get private account")?;

    assert_eq!(
        account.program_owner,
        programs::authenticated_transfer().id()
    );

    info!("Successfully initialized private account using label");

    Ok(())
}

#[test]
async fn shielded_transfers_to_two_identifiers_same_npk() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    // Both transfers below will target this same node with distinct identifiers.
    let chain_index = ctx.wallet_mut().create_private_accounts_key(None);
    let (npk, vpk) = {
        let key_chain = ctx
            .wallet()
            .storage()
            .key_chain()
            .private_account_key_chain_by_index(&chain_index)
            .expect("Failed to get private account key chain for chain index");
        (
            key_chain.nullifier_public_key,
            key_chain.viewing_public_key.clone(),
        )
    };

    let npk_hex = hex::encode(npk.0);
    let vpk_hex = hex::encode(vpk.to_bytes());

    let identifier_1 = 1_u128;
    let identifier_2 = 2_u128;

    let sender_0: AccountId = ctx.existing_public_accounts()[0];
    let sender_1: AccountId = ctx.existing_public_accounts()[1];

    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::AuthTransfer(AuthTransferSubcommand::Send {
            from: public_mention(sender_0),
            to: None,
            to_npk: Some(npk_hex.clone()),
            to_vpk: Some(vpk_hex.clone()),
            to_keys: None,
            to_identifier: Some(identifier_1),
            amount: 100,
        }),
    )
    .await?;

    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::AuthTransfer(AuthTransferSubcommand::Send {
            from: public_mention(sender_1),
            to: None,
            to_npk: Some(npk_hex),
            to_vpk: Some(vpk_hex),
            to_keys: None,
            to_identifier: Some(identifier_2),
            amount: 200,
        }),
    )
    .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    sync_private(&mut ctx).await?;

    // Both accounts must be discovered with the correct balances.
    let account_id_1 = AccountId::for_regular_private_account(&npk, &vpk, identifier_1);
    let acc_1 = ctx
        .wallet()
        .get_account_private(account_id_1)
        .context("account for identifier 1 not found after sync")?;
    assert_eq!(acc_1.balance, 100);

    let account_id_2 = AccountId::for_regular_private_account(&npk, &vpk, identifier_2);
    let acc_2 = ctx
        .wallet()
        .get_account_private(account_id_2)
        .context("account for identifier 2 not found after sync")?;
    assert_eq!(acc_2.balance, 200);

    // Both account ids must resolve to the same key node.
    let found_acc1 = ctx
        .wallet()
        .storage()
        .key_chain()
        .private_account(account_id_1)
        .context("account_id_1 not found in key chain")?;
    let found_acc2 = ctx
        .wallet()
        .storage()
        .key_chain()
        .private_account(account_id_2)
        .context("account_id_2 not found in key chain")?;
    assert_eq!(
        found_acc1.chain_index, found_acc2.chain_index,
        "identifiers 1 and 2 under the same NPK must share a single chain_index"
    );
    assert_eq!(
        found_acc1.chain_index,
        Some(chain_index),
        "both accounts must resolve to the key node created at the start of the test"
    );

    info!("Successfully transferred to two distinct identifiers under the same NPK");

    Ok(())
}

#[test]
async fn ppt_cant_chain_call_faucet() -> Result<()> {
    let ctx = TestContext::new().await?;

    let faucet_chain_caller = test_programs::faucet_chain_caller();
    let deploy_tx = LeeTransaction::ProgramDeployment(lee::ProgramDeploymentTransaction::new(
        lee::program_deployment_transaction::Message::new(faucet_chain_caller.elf().to_owned()),
    ));
    ctx.sequencer_client().send_transaction(deploy_tx).await?;

    info!("Waiting for deploy block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let faucet_account_id = system_accounts::faucet_account_id();
    let attacker_id = ctx.existing_public_accounts()[0];
    let faucet_program_id = programs::faucet().id();
    let vault_program_id = programs::vault().id();
    let auth_transfer_program_id = programs::authenticated_transfer().id();
    let nsk: lee_core::NullifierSecretKey = [3; 32];
    let npk = NullifierPublicKey::from(&nsk);
    let vpk = ViewingPublicKey::from_bytes(vec![4_u8; 1184]).unwrap();
    let attacker_vault_id = {
        let seed = vault_core::compute_vault_seed(attacker_id);
        AccountId::for_private_pda(&vault_program_id, &seed, &npk, &vpk, 1337)
    };
    let amount: u128 = 1;

    let faucet_pre = AccountWithMetadata::new(
        get_account(&ctx, faucet_account_id).await?,
        false,
        faucet_account_id,
    );
    let vault_pda_pre = AccountWithMetadata::new(
        get_account(&ctx, attacker_vault_id).await?,
        false,
        attacker_vault_id,
    );

    let program_with_deps = ProgramWithDependencies::new(
        faucet_chain_caller,
        [
            (faucet_program_id, programs::faucet()),
            (vault_program_id, programs::vault()),
            (auth_transfer_program_id, programs::authenticated_transfer()),
        ]
        .into(),
    );

    let instruction =
        Program::serialize_instruction((faucet_program_id, vault_program_id, attacker_id, amount))?;

    let res = execute_and_prove(
        vec![faucet_pre, vault_pda_pre],
        instruction,
        vec![
            InputAccountIdentity::Public,
            InputAccountIdentity::PrivatePdaInit {
                vpk,
                random_seed: [0; 32],
                npk,
                identifier: 1337,
                commitment_root: DUMMY_COMMITMENT_HASH,
                seed: None,
            },
        ],
        &program_with_deps,
    );

    assert!(res.is_err());

    Ok(())
}

async fn prove_init_with_commitment_root(
    ctx: &TestContext,
    commitment_root: lee_core::CommitmentSetDigest,
) -> Result<lee_core::PrivacyPreservingCircuitOutput> {
    let program = programs::authenticated_transfer();
    let sender_id = ctx.existing_public_accounts()[0];
    let sender_pre = AccountWithMetadata::new(
        ctx.sequencer_client().get_account(sender_id).await?,
        true,
        sender_id,
    );

    let nsk: lee_core::NullifierSecretKey = [7; 32];
    let npk = NullifierPublicKey::from(&nsk);
    let vpk = ViewingPublicKey::from_bytes(vec![4_u8; 1184]).unwrap();
    let recipient_account_id = AccountId::for_regular_private_account(&npk, &vpk, 0);
    let recipient = AccountWithMetadata::new(Account::default(), false, recipient_account_id);

    let (output, _) = execute_and_prove(
        vec![sender_pre, recipient],
        Program::serialize_instruction(authenticated_transfer_core::Instruction::Transfer {
            amount: 1,
        })?,
        vec![
            InputAccountIdentity::Public,
            InputAccountIdentity::PrivateForeignInit {
                vpk,
                random_seed: [0; 32],
                npk,
                identifier: 0,
                commitment_root,
            },
        ],
        &program.into(),
    )?;

    Ok(output)
}

#[test]
async fn init_with_dummy_commitment_root_produces_valid_root() -> Result<()> {
    let ctx = TestContext::new().await?;

    let (_, expected_digest) = ctx.sequencer_client().get_proofs_and_root(vec![]).await?;

    let nsk: lee_core::NullifierSecretKey = [7; 32];
    let npk = NullifierPublicKey::from(&nsk);
    let vpk = ViewingPublicKey::from_bytes(vec![4_u8; 1184]).unwrap();
    let recipient_account_id = AccountId::for_regular_private_account(&npk, &vpk, 0);

    let output = prove_init_with_commitment_root(&ctx, expected_digest).await?;

    assert_eq!(output.new_nullifiers.len(), 1);
    let (nullifier, digest) = &output.new_nullifiers[0];
    assert_eq!(
        *nullifier,
        Nullifier::for_account_initialization(&recipient_account_id)
    );
    assert_eq!(*digest, expected_digest);
    assert_ne!(*digest, DUMMY_COMMITMENT_HASH);

    Ok(())
}

#[test]
async fn init_nullifier_digest_is_bound_to_commitment_root() -> Result<()> {
    let ctx = TestContext::new().await?;

    let (_, expected_digest) = ctx.sequencer_client().get_proofs_and_root(vec![]).await?;

    let output_with_root = prove_init_with_commitment_root(&ctx, expected_digest).await?;
    let output_without_root = prove_init_with_commitment_root(&ctx, DUMMY_COMMITMENT_HASH).await?;

    assert_eq!(output_with_root.new_nullifiers[0].1, expected_digest);
    assert_eq!(
        output_without_root.new_nullifiers[0].1,
        DUMMY_COMMITMENT_HASH
    );
    assert_ne!(
        output_with_root.new_nullifiers[0].1,
        output_without_root.new_nullifiers[0].1,
    );

    Ok(())
}
