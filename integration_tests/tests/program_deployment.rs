#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::{io::Write as _, time::Duration};

use anyhow::Result;
use common::transaction::LeeTransaction;
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, deploy_program, get_account, new_account,
};
use program_loader_core::MAX_PROGRAM_SEGMENTS;
use sequencer_service_rpc::RpcClient as _;
use test_fixtures::{
    MultiZoneTestContextBuilder, ZoneTestContextBuilder, config::MultiNodeTestContextConfig,
};
use tokio::test;
use wallet::{
    account::AccountIdWithPrivacy,
    cli::{CliAccountMention, Command, programs::program_loader::ProgramLoaderSubcommand},
};

#[test]
#[ignore = "blocked on fee support for claiming a fresh account under self-pay: the account being \
            claimed holds nothing to fund the reserve, third-party sponsorship was dropped, and \
            funding it first auto-claims it through the transfer guest, leaving the claimer nothing \
            to claim (fee subsystem interim policy)"]
async fn deploy_and_execute_program() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let claimer = test_programs::claimer();
    let payer = ctx.existing_public_accounts()[0];
    let header_id = deploy_program(&mut ctx, claimer, true, payer).await?;

    let account_id = new_account(&mut ctx, false, None).await?;

    let nonces = ctx.wallet_mut().get_accounts_nonces(&[account_id]).await?;
    // Self-pay: the account being claimed is its own fee payer, authorizing with
    // its own signature. See the `#[ignore]` above — a fresh account holds
    // nothing to fund the reserve with.
    let message = lee::public_transaction::Message::try_new_with_fees(
        header_id,
        vec![account_id],
        nonces,
        (),
        lee::FeeDeclaration::new(account_id, 2_000_000, 0, 100_000_000),
    )?;
    let private_key = ctx
        .wallet()
        .get_account_public_signing_key(account_id)
        .unwrap();
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[private_key]);
    let transaction = lee::PublicTransaction::new(message, witness_set);
    let _response = ctx
        .sequencer_client()
        .send_transaction(LeeTransaction::Public(transaction))
        .await?;

    log::info!("Waiting for next block creation");
    // Waiting for long time as it may take some time for such a big transaction to be included in a
    // block
    tokio::time::sleep(Duration::from_secs(2 * TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let post_state_account = get_account(&ctx, account_id).await?;

    let expected_data: &[u8] = &[];
    assert_eq!(post_state_account.program_owner, header_id);
    assert_eq!(post_state_account.balance, 0);
    assert_eq!(post_state_account.data.as_ref(), expected_data);
    assert_eq!(post_state_account.nonce.0, 1);

    log::info!("Successfully deployed and executed program");

    Ok(())
}

#[test]
async fn program_loader_new_segment_and_upload_header_deploys_program() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let claimer = test_programs::claimer();
    let elf = claimer.elf().to_vec();
    let chunks: Vec<&[u8]> = elf
        .chunks(program_loader_core::MAX_SEGMENT_DATA_LEN)
        .collect();
    assert!(!chunks.is_empty());

    let payer = ctx.existing_public_accounts()[0];
    let payer_mention = || Some(CliAccountMention::Id(AccountIdWithPrivacy::Public(payer)));

    let header_id = new_account(&mut ctx, false, None).await?;
    let mut segment_ids = Vec::with_capacity(chunks.len());
    for _ in 0..chunks.len() {
        segment_ids.push(new_account(&mut ctx, false, None).await?);
    }

    // Upload tail-to-head, one `NewSegment` transaction per chunk, matching program_loader's
    // linking requirement (each `next_segment` must already exist on-chain).
    for i in (0..chunks.len()).rev() {
        let next_segment = segment_ids.get(i.saturating_add(1)).copied();
        let mut tempfile = tempfile::NamedTempFile::new()?;
        tempfile.write_all(chunks[i])?;

        let command = Command::ProgramLoader(ProgramLoaderSubcommand::NewSegment {
            target: CliAccountMention::Id(AccountIdWithPrivacy::Public(segment_ids[i])),
            bytecode_file: tempfile.path().to_owned(),
            next_segment,
            payer: payer_mention(),
        });
        wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    }

    // Standalone `UploadHeader`, exercising the wallet's RPC segment-chain walk (only
    // `first_segment` is supplied, unlike `Deploy` which already has the whole chain).
    let command = Command::ProgramLoader(ProgramLoaderSubcommand::UploadHeader {
        target: CliAccountMention::Id(AccountIdWithPrivacy::Public(header_id)),
        first_segment: segment_ids[0],
        immutable: true,
        payer: payer_mention(),
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    let account_id = new_account(&mut ctx, false, None).await?;
    let payer_nonce = ctx.wallet_mut().get_accounts_nonces(&[payer]).await?[0];
    let mut nonces = ctx.wallet_mut().get_accounts_nonces(&[account_id]).await?;
    nonces.push(payer_nonce);
    let private_key = ctx
        .wallet()
        .get_account_public_signing_key(account_id)
        .unwrap();
    let payer_key = ctx.wallet().get_account_public_signing_key(payer).unwrap();
    // `account_id` is claiming itself and holds nothing, so `payer` (an existing funded
    // account) co-signs to cover the fee — see the `payer` co-signing pattern used throughout
    // this file's other tests.
    let message = lee::public_transaction::Message::try_new_with_fees(
        header_id,
        vec![account_id],
        nonces,
        (),
        common::test_utils::test_fee_declaration(payer),
    )?;
    let witness_set =
        lee::public_transaction::WitnessSet::for_message(&message, &[private_key, payer_key]);
    let transaction = lee::PublicTransaction::new(message, witness_set);
    ctx.sequencer_client()
        .send_transaction(LeeTransaction::Public(transaction))
        .await?;

    log::info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(2 * TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let post_state_account = get_account(&ctx, account_id).await?;
    assert_eq!(post_state_account.program_owner, header_id);

    Ok(())
}

#[test]
async fn program_loader_resolve_chain_rejects_overlong_chain() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let payer = ctx.existing_public_accounts()[0];

    // One more segment than the wallet's resolve_chain walk will follow.
    let segment_count = MAX_PROGRAM_SEGMENTS + 1;
    let mut segment_ids = Vec::with_capacity(segment_count);
    for _ in 0..segment_count {
        segment_ids.push(new_account(&mut ctx, false, None).await?);
    }

    // Upload tail-to-head with trivial one-byte bytecode per segment: resolve_chain never reads
    // segment content, so real ELF chunks aren't needed to exercise the cap.
    for i in (0..segment_count).rev() {
        let next_segment = segment_ids.get(i.saturating_add(1)).copied();
        let mut tempfile = tempfile::NamedTempFile::new()?;
        tempfile.write_all(&[0_u8])?;

        let command = Command::ProgramLoader(ProgramLoaderSubcommand::NewSegment {
            target: CliAccountMention::Id(AccountIdWithPrivacy::Public(segment_ids[i])),
            bytecode_file: tempfile.path().to_owned(),
            next_segment,
            payer: Some(CliAccountMention::Id(AccountIdWithPrivacy::Public(payer))),
        });
        wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    }

    // Standalone `UploadHeader` walks the chain over RPC via `resolve_chain`, which must give up
    // rather than follow all 21 hops.
    let header_id = new_account(&mut ctx, false, None).await?;
    let command = Command::ProgramLoader(ProgramLoaderSubcommand::UploadHeader {
        target: CliAccountMention::Id(AccountIdWithPrivacy::Public(header_id)),
        first_segment: segment_ids[0],
        immutable: true,
        payer: Some(CliAccountMention::Id(AccountIdWithPrivacy::Public(payer))),
    });
    let result = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await;

    let err = result.expect_err("UploadHeader should fail to resolve an over-long chain");
    assert!(
        err.to_string()
            .contains(&format!("{MAX_PROGRAM_SEGMENTS} hops")),
        "expected the chain-walk cap error, got: {err}"
    );

    // Nothing should have been sent: the header must still be a default/unclaimed account.
    let header_account = get_account(&ctx, header_id).await?;
    assert_eq!(header_account, lee::Account::default());

    log::info!("resolve_chain correctly rejected an over-long segment chain");

    Ok(())
}

#[test]
async fn program_loader_update_header_repoints_program() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let payer = ctx.existing_public_accounts()[0];
    let header_id = deploy_program(&mut ctx, test_programs::claimer(), false, payer).await?;

    // Segments are write-once, so updating always uploads a fresh chain.
    let authority_proxy = test_programs::authority_proxy();
    let new_elf = authority_proxy.elf().to_vec();
    let chunk_count = new_elf
        .chunks(program_loader_core::MAX_SEGMENT_DATA_LEN)
        .count()
        .max(1);

    let mut segment_ids = Vec::with_capacity(chunk_count);
    for _ in 0..chunk_count {
        segment_ids.push(new_account(&mut ctx, false, None).await?);
    }

    let mut tempfile = tempfile::NamedTempFile::new()?;
    tempfile.write_all(&new_elf)?;

    let command = Command::ProgramLoader(ProgramLoaderSubcommand::Update {
        elf: tempfile.path().to_owned(),
        header: CliAccountMention::Id(AccountIdWithPrivacy::Public(header_id)),
        segments: segment_ids
            .iter()
            .map(|id| CliAccountMention::Id(AccountIdWithPrivacy::Public(*id)))
            .collect(),
        immutable: false,
        payer: Some(CliAccountMention::Id(AccountIdWithPrivacy::Public(payer))),
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    let header_account = get_account(&ctx, header_id).await?;
    let header_data = program_loader_core::ProgramHeader::try_from(&header_account.data)
        .expect("updated header account data should decode as ProgramHeader");
    assert_eq!(header_data.image_id, authority_proxy.id());
    assert_eq!(header_data.program_first_segment, segment_ids[0]);

    log::info!("Successfully updated deployed program's header");

    Ok(())
}

#[test]
async fn program_loader_deploy_rejects_segment_count_mismatch() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let claimer = test_programs::claimer();
    let elf = claimer.elf().to_vec();
    let chunk_count = elf
        .chunks(program_loader_core::MAX_SEGMENT_DATA_LEN)
        .count()
        .max(1);

    let header_id = new_account(&mut ctx, false, None).await?;
    // Deliberately provide one extra segment account, regardless of the real chunk count.
    let mut segment_ids = Vec::with_capacity(chunk_count + 1);
    for _ in 0..=chunk_count {
        segment_ids.push(new_account(&mut ctx, false, None).await?);
    }

    let mut tempfile = tempfile::NamedTempFile::new()?;
    tempfile.write_all(&elf)?;

    let command = Command::ProgramLoader(ProgramLoaderSubcommand::Deploy {
        elf: tempfile.path().to_owned(),
        header: CliAccountMention::Id(AccountIdWithPrivacy::Public(header_id)),
        segments: segment_ids
            .into_iter()
            .map(|id| CliAccountMention::Id(AccountIdWithPrivacy::Public(id)))
            .collect(),
        immutable: true,
        // The mismatch is caught client-side before anything is sent, so no fee is ever charged.
        payer: None,
    });
    let result = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await;

    assert!(
        result.is_err(),
        "Deploy with a mismatched segment count should fail, but got: {result:?}"
    );

    // Nothing should have been sent: the header must still be a default/unclaimed account.
    let header_account = get_account(&ctx, header_id).await?;
    assert_eq!(header_account, lee::Account::default());

    log::info!("Deploy correctly rejected a segment-count mismatch before sending anything");

    Ok(())
}

#[test]
async fn deploy_invalid_program_fails() -> Result<()> {
    // An invalid program bytecode is rejected at the `UploadHeader` step, which recomputes
    // `image_id` from the chain — but a fee-charged failure still lands in a block as a reverted,
    // nonce-only no-op rather than being rejected outright (see `LeeError::is_chargeable`), so
    // `execute_subcommand` sees the transaction included and reports success. The real signal is
    // the header account: it must stay unclaimed, since the claim itself never took effect.

    let mut ctx = MultiZoneTestContextBuilder::default()
        .with_zone(ZoneTestContextBuilder::new(
            MultiNodeTestContextConfig::default(),
        ))
        .build()
        .await?;

    let payer = ctx.existing_public_accounts()[0];
    let invalid_bytecode = b"this is not a valid program binary".to_vec();
    let header_id = new_account(&mut ctx, false, None).await?;
    let segment_id = new_account(&mut ctx, false, None).await?;

    let mut tempfile = tempfile::NamedTempFile::new()?;
    tempfile.write_all(&invalid_bytecode)?;

    let command = Command::ProgramLoader(ProgramLoaderSubcommand::Deploy {
        elf: tempfile.path().to_owned(),
        header: CliAccountMention::Id(AccountIdWithPrivacy::Public(header_id)),
        segments: vec![CliAccountMention::Id(AccountIdWithPrivacy::Public(
            segment_id,
        ))],
        immutable: true,
        payer: Some(CliAccountMention::Id(AccountIdWithPrivacy::Public(payer))),
    });

    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    let header_account = get_account(&ctx, header_id).await?;
    assert_eq!(
        header_account,
        lee::Account {
            // A reverted claim still burns the signer's replay nonce — only the claim itself
            // (program_owner, data) never took effect.
            nonce: lee_core::account::Nonce(1),
            ..lee::Account::default()
        },
        "an invalid program's header must remain unclaimed"
    );

    log::info!("Deploying an invalid program failed as expected");

    Ok(())
}
