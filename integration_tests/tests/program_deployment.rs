#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::time::Duration;

use anyhow::Result;
use common::transaction::LeeTransaction;
use integration_tests::{TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, get_account, new_account};
use sequencer_service_rpc::RpcClient as _;
use test_fixtures::{
    MultiZoneTestContextBuilder, ZoneTestContextBuilder, config::MultiNodeTestContextConfig,
    public_mention,
};
use tokio::test;
use wallet::{
    cli::{Command, programs::program_loader::ProgramLoaderSubcommand},
    config::WalletConfigOverrides,
};

#[test]
async fn deploy_and_execute_program() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let deployed = test_programs::data_writer();
    // Every account a deploy touches is freshly claimed and unfunded, so a genesis-funded wallet
    // account covers the fees instead (see `ProgramLoader::send`).
    let payer_id = ctx.existing_public_accounts()[0];

    // Deploy through `program_loader`: one segment per ELF chunk, then a header claims the chain.
    // Every account is freshly claimed, a permissionless write.
    let header_id = new_account(&mut ctx, false, None).await?;
    let mut segment_ids = Vec::new();
    for _ in deployed
        .elf()
        .chunks(program_loader_core::MAX_SEGMENT_DATA_LEN)
    {
        segment_ids.push(new_account(&mut ctx, false, None).await?);
    }
    let account_id = wallet::program_facades::program_loader::ProgramLoader(ctx.wallet())
        .deploy(
            header_id,
            &segment_ids,
            deployed.elf().to_vec(),
            true,
            Some(payer_id),
        )
        .await?;

    let target_id = new_account(&mut ctx, false, None).await?;

    // The claimed account holds nothing to fund the reserve with, so `payer_id` co-signs: its
    // nonce and signature go last, after the account list's own.
    let nonces = ctx
        .wallet_mut()
        .get_accounts_nonces(&[target_id, payer_id])
        .await?;
    let written: Vec<u8> = vec![9; 4];
    let message = lee::public_transaction::Message::try_new_with_fees(
        account_id,
        vec![target_id],
        nonces,
        written.clone(),
        common::test_utils::test_fee_declaration(payer_id),
    )?;
    let target_key = ctx
        .wallet()
        .get_account_public_signing_key(target_id)
        .unwrap();
    let payer_key = ctx
        .wallet()
        .get_account_public_signing_key(payer_id)
        .unwrap();
    let witness_set =
        lee::public_transaction::WitnessSet::for_message(&message, &[target_key, payer_key]);
    let transaction = lee::PublicTransaction::new(message, witness_set);
    let _response = ctx
        .sequencer_client()
        .send_transaction(LeeTransaction::Public(transaction))
        .await?;

    log::info!("Waiting for next block creation");
    // Waiting for long time as it may take some time for such a big transaction to be included in a
    // block
    tokio::time::sleep(Duration::from_secs(2 * TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let post_state_account = get_account(&ctx, target_id).await?;

    assert_eq!(post_state_account.program_owner, account_id);
    assert_eq!(post_state_account.balance, 0);
    assert_eq!(post_state_account.data.as_ref(), written.as_slice());
    assert_eq!(post_state_account.nonce.0, 1);

    log::info!("Successfully deployed and executed program");

    Ok(())
}

#[test]
async fn deploy_invalid_program_fails() -> Result<()> {
    // Invalid program bytecode is rejected when `program_loader`'s `CreateHeader` tries to
    // recompute the real `image_id` from the segment chain, so the deploy never lands. Shrink the
    // wallet's polling window so the command gives up quickly instead of waiting for the full
    // default timeout.

    let mut ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig::default())
                .with_wallet_config_overrides(WalletConfigOverrides {
                    seq_poll_timeout: Some(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)),
                    seq_tx_poll_max_blocks: Some(5),
                    seq_poll_max_retries: Some(2),
                    ..WalletConfigOverrides::default()
                }),
        )
        .build()
        .await?;

    let header_id = new_account(&mut ctx, false, None).await?;
    let segment_id = new_account(&mut ctx, false, None).await?;

    let mut tempfile = tempfile::NamedTempFile::new()?;
    std::io::Write::write_all(&mut tempfile, b"this is not a valid program binary")?;

    let command = Command::ProgramLoader(ProgramLoaderSubcommand::Deploy {
        elf: tempfile.path().to_owned(),
        header: public_mention(header_id),
        segments: vec![public_mention(segment_id)],
        immutable: true,
        payer: None,
    });

    let result = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await;

    assert!(
        result.is_err(),
        "Deploying an invalid program should fail, but got: {result:?}"
    );

    log::info!("Deploying an invalid program failed as expected");

    Ok(())
}
