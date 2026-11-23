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
    AccountIdentity, DryRunReport, ExecutionFailureKind,
    cli::{Command, programs::program_loader::ProgramLoaderSubcommand},
    config::WalletConfigOverrides,
    program_facades::program_loader::ProgramLoader,
};

mod system_upgrade;

#[test]
async fn deploy_and_execute_program() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let deployed = test_programs::scripted();
    // Every account a deploy touches is freshly claimed and unfunded, so a genesis-funded wallet
    // account covers the fees instead (see `ProgramLoader::send`).
    let payer_id = ctx.existing_public_accounts()[0];

    // Deploy through `program_loader`: one segment holds the (small, test-sized) program's
    // `user_elf`, then a header claims it. Both accounts are freshly claimed, permissionless
    // writes.
    let header_id = new_account(&mut ctx, false, None).await?;
    let mut segment_ids = Vec::new();
    for _ in deployed
        .user_elf()
        .expect("valid ProgramBinary")
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
            Vec::new(),
            Some(payer_id),
        )
        .await?;

    // A dry run of a call into the deployed program declares its metered cycles plus the 25%
    // margin; the fixture prices no headroom, so the cap is the reserve at head.
    ctx.wallet_mut().set_dry_run(true);
    let dry_run = ctx
        .wallet()
        .send_pub_tx(
            vec![AccountIdentity::Public(payer_id).select_program_actor_state(account_id)],
            0,
            lee::program::Program::serialize_message(test_guest_core::Script::write(vec![1]))?,
        )
        .await;
    ctx.wallet_mut().set_dry_run(false);
    let Err(ExecutionFailureKind::DryRun(report)) = dry_run else {
        panic!("a dry run reports instead of sending, got {dry_run:?}");
    };
    let DryRunReport::Public {
        fee,
        cycles,
        reserve_at_head,
        revert_reason,
        ..
    } = *report
    else {
        panic!("a public send reports a public dry run");
    };
    assert_eq!(revert_reason, None);
    assert!(cycles > 0, "a guest program call meters cycles");
    assert_eq!(fee.gas_limit, (cycles * 125).div_ceil(100));
    assert_eq!(fee.max_fee, reserve_at_head);

    let target_id = new_account(&mut ctx, false, None).await?;

    // The claimed account holds nothing to fund the reserve with, so `payer_id` co-signs.
    let signers = [target_id, payer_id];
    let nonces = signers
        .into_iter()
        .zip(ctx.wallet_mut().get_accounts_nonces(&signers).await?)
        .collect();
    let written: Vec<u8> = vec![9; 4];
    let target = lee::Actor::new(target_id, account_id);
    let message = lee::public_transaction::Message::try_new_with_fees(
        target,
        vec![target],
        nonces,
        test_guest_core::Script::write(written.clone()),
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

    tracing::info!("Waiting for next block creation");
    // Waiting for long time as it may take some time for such a big transaction to be included in a
    // block
    tokio::time::sleep(Duration::from_secs(2 * TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let post_state_account = get_account(&ctx, target_id).await?;

    assert_eq!(post_state_account.data.native_balance().unwrap(), 0);
    assert_eq!(
        post_state_account.data.actor_state(account_id).as_ref(),
        written.as_slice()
    );
    assert_eq!(post_state_account.nonce.0, 1);

    tracing::info!("Successfully deployed and executed program");

    Ok(())
}

#[test]
async fn deploy_and_update_env_var() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let deployed = test_programs::scripted();
    let payer_id = ctx.existing_public_accounts()[0];
    let user_elf = deployed.user_elf().expect("valid ProgramBinary");

    let mut segment_ids = Vec::new();
    for _ in 0..program_loader_core::segment_count(&user_elf) {
        segment_ids.push(new_account(&mut ctx, false, None).await?);
    }

    // Over the cap, nothing is uploaded.
    let refused_header = new_account(&mut ctx, false, None).await?;
    let refused = ProgramLoader(ctx.wallet())
        .deploy(
            refused_header,
            &segment_ids,
            deployed.elf().to_vec(),
            false,
            vec![0; program_loader_core::MAX_ENV_VAR_LEN + 1],
            Some(payer_id),
        )
        .await;
    assert!(
        matches!(
            refused
                .as_ref()
                .map_err(|err| err.downcast_ref::<ExecutionFailureKind>()),
            Err(Some(ExecutionFailureKind::EnvVarTooLong { .. }))
        ),
        "an oversized env_var should be refused before uploading, got {refused:?}"
    );
    let segment = get_account(&ctx, segment_ids[0]).await?;
    assert!(
        segment
            .data
            .actor_state(lee_core::program::PROGRAM_LOADER_ACCOUNT_ID)
            .is_empty(),
        "no segment should be uploaded for a refused deploy"
    );

    let header_id = new_account(&mut ctx, false, None).await?;
    ProgramLoader(ctx.wallet())
        .deploy(
            header_id,
            &segment_ids,
            deployed.elf().to_vec(),
            false,
            vec![1, 2, 3],
            Some(payer_id),
        )
        .await?;
    assert_eq!(env_var(&ctx, header_id).await?, vec![1, 2, 3]);

    // Without an env_var, an update keeps the header's current one.
    let kept = ProgramLoader(ctx.wallet())
        .update_header(header_id, segment_ids[0], false, None, Some(payer_id))
        .await
        .map_err(|err| anyhow::anyhow!("{err}"))?;
    ctx.wallet().poll_transaction(kept).await?;
    assert_eq!(env_var(&ctx, header_id).await?, vec![1, 2, 3]);

    let replaced = ProgramLoader(ctx.wallet())
        .update_header(
            header_id,
            segment_ids[0],
            false,
            Some(vec![4]),
            Some(payer_id),
        )
        .await
        .map_err(|err| anyhow::anyhow!("{err}"))?;
    ctx.wallet().poll_transaction(replaced).await?;
    assert_eq!(env_var(&ctx, header_id).await?, vec![4]);

    Ok(())
}

async fn env_var(ctx: &TestContext, header_id: lee::AccountId) -> Result<Vec<u8>> {
    Ok(ProgramLoader(ctx.wallet())
        .header(header_id)
        .await
        .map_err(|err| anyhow::anyhow!("{err}"))?
        .expect("the header is deployed")
        .env_var)
}

#[test]
async fn deploy_invalid_program_fails() -> Result<()> {
    // Invalid program bytecode is rejected when the wallet decodes it as a `ProgramBinary`
    // before uploading, so the deploy never lands. Shrink the wallet's polling window so the
    // command gives up quickly instead of waiting for the full default timeout.

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
        env_var_hex: None,
        payer: None,
    });

    let result = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await;

    assert!(
        result.is_err(),
        "Deploying an invalid program should fail, but got: {result:?}"
    );

    tracing::info!("Deploying an invalid program failed as expected");

    Ok(())
}
