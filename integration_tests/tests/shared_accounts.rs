#![expect(
    clippy::tests_outside_test_module,
    reason = "Integration test file, not inside a #[cfg(test)] module"
)]
#![expect(
    clippy::shadow_unrelated,
    reason = "Sequential wallet commands naturally reuse the `command` binding"
)]

//! Shared account integration tests.
//!
//! Demonstrates:
//! 1. Group creation and GMS distribution via seal/unseal.
//! 2. Shared regular private account creation via `--for-gms`.
//! 3. Funding a shared account from a public account.
//! 4. Syncing discovers the funded shared account state.

use std::time::Duration;

use anyhow::{Context as _, Result};
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, private_mention, public_mention,
};
use log::info;
use tokio::test;
use wallet::{
    account::Label,
    cli::{
        Command, SubcommandReturnValue,
        account::{AccountSubcommand, NewSubcommand},
        group::GroupSubcommand,
        programs::native_token_transfer::AuthTransferSubcommand,
    },
};

/// Create a group, create a shared account from it, and verify registration.
#[test]
async fn group_create_and_shared_account_registration() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    // Create a group
    let command = Command::Group(GroupSubcommand::New {
        name: "test-group".into(),
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    // Verify group exists
    assert!(
        ctx.wallet()
            .storage()
            .key_chain()
            .group_key_holder(&Label::new("test-group"))
            .is_some()
    );

    // Create a shared regular private account from the group
    let command = Command::Account(AccountSubcommand::New(NewSubcommand::PrivateGms {
        group: "test-group".into(),
        label: Some("shared-acc".into()),
        pda: false,
        seed: None,
        program_id: None,
        identifier: None,
    }));

    let result = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: shared_account_id,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Verify shared account is registered in storage
    let entry = ctx
        .wallet()
        .storage()
        .key_chain()
        .shared_private_account(shared_account_id)
        .context("Shared account not found in storage")?;
    assert_eq!(entry.group_label, Label::new("test-group"));
    assert!(entry.pda_seed.is_none());

    info!("Shared account registered: {shared_account_id}");
    Ok(())
}

/// GMS seal/unseal round-trip via invite/join, verify key agreement.
#[test]
async fn group_invite_join_key_agreement() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    // Generate a sealing key
    let command = Command::Group(GroupSubcommand::NewSealingKey);
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    // Create a group
    let command = Command::Group(GroupSubcommand::New {
        name: "alice-group".into(),
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    // Seal GMS for ourselves (simulating invite to another wallet)
    let sealing_sk = ctx
        .wallet()
        .storage()
        .key_chain()
        .sealing_secret_key()
        .context("Sealing key not found")?;
    let sealing_pk =
        key_protocol::key_management::group_key_holder::SealingPublicKey::from_scalar(sealing_sk);

    let holder = ctx
        .wallet()
        .storage()
        .key_chain()
        .group_key_holder(&Label::new("alice-group"))
        .context("Group not found")?;
    let sealed = holder.seal_for(&sealing_pk);
    let sealed_hex = hex::encode(&sealed);

    // Join under a different name (simulating Bob receiving the sealed GMS)
    let command = Command::Group(GroupSubcommand::Join {
        name: "bob-copy".into(),
        sealed: sealed_hex,
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    // Both derive the same keys for the same derivation seed
    let alice_holder = ctx
        .wallet()
        .storage()
        .key_chain()
        .group_key_holder(&Label::new("alice-group"))
        .unwrap();
    let bob_holder = ctx
        .wallet()
        .storage()
        .key_chain()
        .group_key_holder(&Label::new("bob-copy"))
        .unwrap();

    let seed = [42_u8; 32];
    let alice_npk = alice_holder
        .derive_keys_for_shared_account(&seed)
        .generate_nullifier_public_key();
    let bob_npk = bob_holder
        .derive_keys_for_shared_account(&seed)
        .generate_nullifier_public_key();

    assert_eq!(
        alice_npk, bob_npk,
        "Key agreement: same GMS produces same keys"
    );

    info!("Key agreement verified via invite/join");
    Ok(())
}

/// Fund a shared account from a public account via auth-transfer, then sync.
/// TODO: Requires auth-transfer init to work with shared accounts (authorization flow).
#[test]
async fn fund_shared_account_from_public() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    // Create group and shared account
    let command = Command::Group(GroupSubcommand::New {
        name: "fund-group".into(),
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    let command = Command::Account(AccountSubcommand::New(NewSubcommand::PrivateGms {
        group: "fund-group".into(),
        label: None,
        pda: false,
        seed: None,
        program_id: None,
        identifier: None,
    }));
    let result = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: shared_id,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Initialize the shared account under auth-transfer
    let command = Command::AuthTransfer(AuthTransferSubcommand::Init {
        account_id: private_mention(shared_id),
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Sync private accounts
    let command = Command::Account(AccountSubcommand::SyncPrivate);
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    // Fund from a public account
    let from_public = ctx.existing_public_accounts()[0];
    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: public_mention(from_public),
        to: Some(private_mention(shared_id)),
        to_npk: None,
        to_vpk: None,
        to_identifier: None,
        amount: 100,
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Sync private accounts
    let command = Command::Account(AccountSubcommand::SyncPrivate);
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    // Verify the shared account was updated
    let entry = ctx
        .wallet()
        .storage()
        .key_chain()
        .shared_private_account(shared_id)
        .context("Shared account not found after sync")?;

    info!(
        "Shared account balance after funding: {}",
        entry.account.balance
    );
    assert_eq!(
        entry.account.balance, 100,
        "Shared account should have received 100"
    );

    Ok(())
}
