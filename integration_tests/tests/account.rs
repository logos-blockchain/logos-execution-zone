#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use anyhow::{Context as _, Result};
use integration_tests::{TestContext, private_mention};
use key_protocol::key_management::KeyChain;
use log::info;
use nssa::{Data, program::Program};
use nssa_core::account::Nonce;
use sequencer_service_rpc::RpcClient as _;
use tokio::test;
use wallet::{
    account::{AccountIdWithPrivacy, HumanReadableAccount, Label},
    cli::{
        Command, SubcommandReturnValue,
        account::{AccountSubcommand, ImportSubcommand, NewSubcommand},
        execute_subcommand,
    },
};

#[test]
async fn get_existing_account() -> Result<()> {
    let ctx = TestContext::new().await?;

    let account = ctx
        .sequencer_client()
        .get_account(ctx.existing_public_accounts()[0])
        .await?;

    assert_eq!(
        account.program_owner,
        Program::authenticated_transfer_program().id()
    );
    assert_eq!(account.balance, 10000);
    assert!(account.data.is_empty());
    assert_eq!(account.nonce.0, 1);

    info!("Successfully retrieved account with correct details");

    Ok(())
}

#[test]
async fn new_public_account_with_label() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let label = Label::new("my-test-public-account");
    let command = Command::Account(AccountSubcommand::New(NewSubcommand::Public {
        cci: None,
        label: Some(label.clone()),
    }));

    let result = execute_subcommand(ctx.wallet_mut(), command).await?;

    // Extract the account_id from the result
    let wallet::cli::SubcommandReturnValue::RegisterAccount { account_id } = result else {
        panic!("Expected RegisterAccount return value")
    };

    // Verify the label was stored
    let resolved = ctx.wallet().storage().resolve_label(&label);

    assert_eq!(resolved, Some(AccountIdWithPrivacy::Public(account_id)));

    info!("Successfully created public account with label");

    Ok(())
}

#[test]
async fn add_label_to_existing_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let account_id = ctx.existing_private_accounts()[0];
    let label = Label::new("my-test-private-account");
    let command = Command::Account(AccountSubcommand::Label {
        account_id: private_mention(account_id),
        label: label.clone(),
    });

    execute_subcommand(ctx.wallet_mut(), command).await?;

    let resolved = ctx.wallet().storage().resolve_label(&label);

    assert_eq!(resolved, Some(AccountIdWithPrivacy::Private(account_id)));

    info!("Successfully set label on existing private account");

    Ok(())
}

#[test]
async fn new_public_account_without_label() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let command = Command::Account(AccountSubcommand::New(NewSubcommand::Public {
        cci: None,
        label: None,
    }));

    let result = execute_subcommand(ctx.wallet_mut(), command).await?;

    // Extract the account_id from the result

    let wallet::cli::SubcommandReturnValue::RegisterAccount { account_id } = result else {
        panic!("Expected RegisterAccount return value")
    };

    // Verify no label was stored for the account id
    assert!(
        ctx.wallet()
            .storage()
            .labels_for_account(AccountIdWithPrivacy::Public(account_id))
            .next()
            .is_none(),
        "No label should be stored when not provided"
    );

    info!("Successfully created public account without label");

    Ok(())
}

#[test]
async fn import_public_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let private_key = nssa::PrivateKey::new_os_random();
    let account_id = nssa::AccountId::from(&nssa::PublicKey::new_from_private_key(&private_key));

    let command = Command::Account(AccountSubcommand::Import(ImportSubcommand::Public {
        private_key,
    }));
    let sub_ret = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::Empty = sub_ret else {
        anyhow::bail!("Expected Empty return value");
    };

    let imported_key = ctx
        .wallet()
        .storage()
        .key_chain()
        .pub_account_signing_key(account_id);
    assert!(
        imported_key.is_some(),
        "Imported public account should be present"
    );

    Ok(())
}

#[test]
async fn import_private_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let key_chain = KeyChain::new_os_random();
    let account_id = nssa::AccountId::from((&key_chain.nullifier_public_key, 0));
    let account = nssa::Account {
        program_owner: Program::authenticated_transfer_program().id(),
        balance: 777,
        data: Data::default(),
        nonce: Nonce::default(),
    };

    let key_chain_json = serde_json::to_string(&key_chain)
        .context("Failed to serialize key chain for private import")?;
    let account_state = HumanReadableAccount::from(account.clone());

    let command = Command::Account(AccountSubcommand::Import(ImportSubcommand::Private {
        key_chain_json,
        account_state,
        chain_index: None,
        identifier: 0,
    }));
    let sub_ret = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::Empty = sub_ret else {
        anyhow::bail!("Expected Empty return value");
    };

    let imported_acc = ctx
        .wallet()
        .storage()
        .key_chain()
        .private_account(account_id)
        .context("Imported private account should be present")?;

    assert_eq!(
        imported_acc.key_chain.secret_spending_key,
        key_chain.secret_spending_key
    );
    assert_eq!(
        imported_acc.key_chain.nullifier_public_key,
        key_chain.nullifier_public_key
    );
    assert_eq!(
        imported_acc.key_chain.viewing_public_key,
        key_chain.viewing_public_key
    );

    assert_eq!(imported_acc.chain_index, None);

    assert_eq!(imported_acc.identifier, 0);

    assert_eq!(imported_acc.account, &account);

    Ok(())
}

#[test]
async fn import_private_account_second_time_overrides_account_data() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let key_chain = KeyChain::new_os_random();
    let account_id = nssa::AccountId::from((&key_chain.nullifier_public_key, 0));
    let key_chain_json =
        serde_json::to_string(&key_chain).context("Failed to serialize key chain")?;

    let initial_account = nssa::Account {
        program_owner: Program::authenticated_transfer_program().id(),
        balance: 100,
        data: Data::default(),
        nonce: Nonce::default(),
    };

    // First import
    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::Import(ImportSubcommand::Private {
            key_chain_json: key_chain_json.clone(),
            account_state: HumanReadableAccount::from(initial_account),
            chain_index: None,
            identifier: 0,
        })),
    )
    .await?;

    let updated_account = nssa::Account {
        program_owner: Program::authenticated_transfer_program().id(),
        balance: 999,
        data: Data::default(),
        nonce: Nonce::default(),
    };

    // Second import with different account data (same key chain)
    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::Import(ImportSubcommand::Private {
            key_chain_json,
            account_state: HumanReadableAccount::from(updated_account.clone()),
            chain_index: None,
            identifier: 0,
        })),
    )
    .await?;

    let imported = ctx
        .wallet()
        .storage()
        .key_chain()
        .private_account(account_id)
        .context("Imported private account should be present")?;

    assert_eq!(
        imported.account, &updated_account,
        "Second import should override account data"
    );

    Ok(())
}
