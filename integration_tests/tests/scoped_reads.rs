#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::{borrow::Cow, time::Duration};

use anyhow::Result;
use common::transaction::LeeTransaction;
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, private_mention, public_mention,
    utils::{
        account_balance, get_account, get_account_view, new_account, send,
        wait_for_indexer_to_catch_up,
    },
};
use lee::{
    AccountId, PrivateKey, ProgramShardSelector, PublicKey,
    privacy_preserving_transaction::circuit::ProgramWithDependencies, program::Program,
};
use lee_core::{account::Nonce, program::PROGRAM_LOADER_ACCOUNT_ID};
use program_loader_core::MAX_SEGMENT_DATA_LEN;
use sequencer_service_rpc::RpcClient as _;
use testnet_initial_state::{PublicAccountPrivateInitialData, initial_pub_accounts_private_keys};
use tokio::test;
use wallet::{
    AccountIdentity,
    cli::{Command, account::AccountSubcommand, execute_subcommand},
    program_facades::program_loader::ProgramLoader,
};

const BLOAT_SHARD_BYTES: usize = 700 * 1024;

const BLOAT_WRITERS: usize = 4;

fn is_oversized_response(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<sequencer_service_rpc::ClientError>(),
        Some(sequencer_service_rpc::ClientError::Call(object))
            if object.code() == jsonrpsee::types::error::OVERSIZED_RESPONSE_CODE
    )
}

fn fresh_key(seed: u8) -> (PrivateKey, AccountId) {
    let key = PrivateKey::try_new([seed; 32]).expect("seed is a valid private key");
    let account_id = AccountId::from(&PublicKey::new_from_private_key(&key));
    (key, account_id)
}

async fn submit(
    ctx: &TestContext,
    program: AccountId,
    shard_selectors: Vec<ProgramShardSelector>,
    nonces: Vec<Nonce>,
    instruction: impl borsh::BorshSerialize,
    payer: &PublicAccountPrivateInitialData,
    extra_signers: &[&PrivateKey],
) -> Result<()> {
    let message = lee::public_transaction::Message::try_new_with_fees(
        program,
        shard_selectors,
        nonces,
        instruction,
        common::test_utils::test_fee_declaration(payer.account_id),
    )?;
    let mut keys = extra_signers.to_vec();
    keys.push(&payer.pub_sign_key);
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &keys);

    ctx.sequencer_client()
        .send_transaction(LeeTransaction::Public(lee::PublicTransaction::new(
            message,
            witness_set,
        )))
        .await?;

    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;
    Ok(())
}

// The fixture wallet holds only the fixture seed keys; the loader facade signs fee declarations
// with keys the wallet holds, so the genesis payer's key is imported before it pays.
fn genesis_payer(ctx: &mut TestContext) -> PublicAccountPrivateInitialData {
    let payer = initial_pub_accounts_private_keys().swap_remove(0);
    ctx.wallet_mut()
        .storage_mut()
        .key_chain_mut()
        .add_imported_public_account(payer.pub_sign_key.clone());
    payer
}

async fn fresh_segments(ctx: &mut TestContext, byte_len: usize) -> Result<Vec<AccountId>> {
    let mut segments = Vec::new();
    for _ in 0..byte_len.div_ceil(MAX_SEGMENT_DATA_LEN) {
        segments.push(new_account(ctx, false, None).await?);
    }
    Ok(segments)
}

async fn deploy_at_bijection(
    ctx: &mut TestContext,
    payer: AccountId,
    program: &Program,
) -> Result<AccountId> {
    let segments = fresh_segments(ctx, program.elf().len()).await?;

    ProgramLoader(ctx.wallet())
        .deploy(
            program.id().into(),
            &segments,
            program.elf().to_vec(),
            true,
            Some(payer),
        )
        .await
}

async fn bloat_account(ctx: &mut TestContext, victim: AccountId) -> Result<[AccountId; 4]> {
    let payer = &genesis_payer(ctx);
    let writer = test_programs::data_writer();

    let segments = fresh_segments(ctx, writer.elf().len()).await?;
    let first_header = new_account(ctx, false, None).await?;
    ProgramLoader(ctx.wallet())
        .deploy(
            first_header,
            &segments,
            writer.elf().to_vec(),
            true,
            Some(payer.account_id),
        )
        .await?;

    let mut writers = vec![first_header];
    while writers.len() < BLOAT_WRITERS {
        let header = new_account(ctx, false, None).await?;
        ProgramLoader(ctx.wallet())
            .create_header(header, segments[0], &segments, true, Some(payer.account_id))
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        writers.push(header);
    }

    for writer_id in &writers {
        let payer_nonce = get_account(ctx, payer.account_id).await?.nonce;
        submit(
            ctx,
            *writer_id,
            vec![ProgramShardSelector::new(victim, *writer_id)],
            vec![payer_nonce],
            vec![0xFF_u8; BLOAT_SHARD_BYTES],
            payer,
            &[],
        )
        .await?;
    }

    writers
        .try_into()
        .map_err(|_ignored| anyhow::anyhow!("writer count is BLOAT_WRITERS by construction"))
}

#[test]
async fn a_bloated_account_defeats_the_whole_account_read_but_not_the_scoped_one() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let victim = ctx.existing_public_accounts()[0];

    let height_before_bloat = ctx.sequencer_client().get_last_block_id().await?;
    let writers = bloat_account(&mut ctx, victim).await?;

    let error = get_account(&ctx, victim)
        .await
        .expect_err("the whole-account read must fail once the account is bloated");
    assert!(
        is_oversized_response(&error),
        "the read must fail on response size specifically, not on any error: {error:?}"
    );

    for (index, writer) in writers.iter().enumerate() {
        assert!(
            !writers[..index].contains(writer),
            "every bloat writer must be a distinct address"
        );
        let view = get_account_view(&ctx, ProgramShardSelector::new(victim, *writer)).await?;
        assert_eq!(view.data.shards.len(), 1, "a scoped read carries one shard");
        assert_eq!(view.data.shards[writer].as_ref().len(), BLOAT_SHARD_BYTES);
    }

    let balance_only = get_account_view(&ctx, ProgramShardSelector::balance_only(victim)).await?;
    assert!(balance_only.data.shards.is_empty());

    let last_writer = writers[BLOAT_WRITERS - 1];
    let scoped_get = |program_account_id: Option<AccountId>, all_shards: bool, raw: bool| {
        Command::Account(AccountSubcommand::Get {
            raw,
            keys: false,
            account_id: public_mention(victim),
            program_account_id,
            all_shards,
        })
    };
    execute_subcommand(ctx.wallet_mut(), scoped_get(None, false, false)).await?;
    execute_subcommand(
        ctx.wallet_mut(),
        scoped_get(Some(last_writer), false, false),
    )
    .await?;
    execute_subcommand(ctx.wallet_mut(), scoped_get(Some(last_writer), false, true)).await?;
    let cli_error = execute_subcommand(ctx.wallet_mut(), scoped_get(None, true, false))
        .await
        .expect_err("--all-shards must stay a whole-account read");
    assert!(
        is_oversized_response(&cli_error),
        "--all-shards must fail on response size specifically: {cli_error:?}"
    );

    let indexer_height = wait_for_indexer_to_catch_up(&ctx).await?;
    let selector: indexer_service_protocol::ProgramShardSelector =
        ProgramShardSelector::new(victim, last_writer).into();
    let last_writer_key: indexer_service_protocol::AccountId = last_writer.into();

    let indexer = &**ctx.indexer_client();
    let expected_shard = vec![0xFF_u8; BLOAT_SHARD_BYTES];

    let current = indexer_service_rpc::RpcClient::get_account_view(indexer, selector).await?;
    assert_eq!(
        current.data.shards.len(),
        1,
        "the indexer view must carry only the selected shard"
    );
    assert_eq!(current.data.shards[&last_writer_key].0, expected_shard);
    assert_eq!(current.data.balance, balance_only.data.balance);
    assert_eq!(current.nonce, balance_only.nonce.0);

    let before_population = indexer_service_rpc::RpcClient::get_account_view_at_block(
        indexer,
        selector,
        height_before_bloat,
    )
    .await?;
    assert!(
        before_population.data.shards[&last_writer_key].0.is_empty(),
        "the historical view must predate the shard, not mirror current state"
    );
    assert_eq!(
        before_population.data.balance, balance_only.data.balance,
        "the historical view must be the real account at that height, not a default"
    );

    let after_population = indexer_service_rpc::RpcClient::get_account_view_at_block(
        indexer,
        selector,
        indexer_height,
    )
    .await?;
    assert_eq!(
        after_population.data.shards[&last_writer_key].0, expected_shard,
        "the historical view must serve real shard data, not always empty"
    );
    assert_eq!(after_population.data.balance, balance_only.data.balance);
    assert_eq!(after_population.nonce, balance_only.nonce.0);

    let missing = indexer_service_rpc::RpcClient::get_account_view(
        indexer,
        ProgramShardSelector::balance_only(AccountId::new([0x5A; 32])).into(),
    )
    .await?;
    assert_eq!(missing.data.balance, 0);
    assert_eq!(missing.nonce, 0);
    assert!(missing.data.shards.is_empty());

    assert!(
        indexer_service_rpc::RpcClient::get_account_view_at_block(
            indexer,
            selector,
            indexer_height + 1_000_000,
        )
        .await
        .is_err(),
        "a height the indexer has not reached must error rather than serve current state"
    );

    Ok(())
}

#[test]
async fn public_transfer_survives_a_bloated_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let accounts = ctx.existing_public_accounts();
    let victim = accounts[0];
    let counterparty = accounts[1];

    bloat_account(&mut ctx, victim).await?;

    let counterparty_before = account_balance(&ctx, counterparty).await?;

    send(
        &mut ctx,
        public_mention(victim),
        public_mention(counterparty),
        100,
    )
    .await?;

    assert_eq!(
        account_balance(&ctx, counterparty).await?,
        counterparty_before + 100
    );

    let victim_before_return = account_balance(&ctx, victim).await?;

    send(
        &mut ctx,
        public_mention(counterparty),
        public_mention(victim),
        100,
    )
    .await?;

    assert_eq!(
        account_balance(&ctx, victim).await?,
        victim_before_return + 100,
        "the return transfer must have credited the victim, not merely been included"
    );

    Ok(())
}

#[test]
async fn private_deshield_into_a_bloated_account_survives() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let victim = ctx.existing_public_accounts()[0];
    let sender = ctx.existing_private_accounts()[0];

    bloat_account(&mut ctx, victim).await?;

    let victim_before = account_balance(&ctx, victim).await?;

    send(
        &mut ctx,
        private_mention(sender),
        public_mention(victim),
        100,
    )
    .await?;

    assert_eq!(account_balance(&ctx, victim).await?, victim_before + 100);

    Ok(())
}

#[test]
async fn loader_reads_survive_a_bloated_segment_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let payer = &genesis_payer(&mut ctx);

    let (segment_key, segment_id) = fresh_key(0xD0);
    let payer_nonce = get_account(&ctx, payer.account_id).await?.nonce;
    submit(
        &ctx,
        PROGRAM_LOADER_ACCOUNT_ID,
        vec![ProgramShardSelector::new(
            segment_id,
            PROGRAM_LOADER_ACCOUNT_ID,
        )],
        vec![Nonce(0), payer_nonce],
        program_loader_core::Instruction::WriteSegment {
            bytecode: test_programs::data_writer().elf().to_vec(),
            next_segment: None,
        },
        payer,
        &[&segment_key],
    )
    .await?;

    bloat_account(&mut ctx, segment_id).await?;

    assert!(
        get_account(&ctx, segment_id).await.is_err(),
        "the segment account must be past the whole-account response limit"
    );

    let loader = ProgramLoader(ctx.wallet());

    let chain = loader.resolve_chain(segment_id).await?;
    assert_eq!(chain, vec![segment_id]);

    let (_, head_id) = fresh_key(0xD1);
    loader
        .write_segment(
            head_id,
            test_programs::data_writer().elf().to_vec(),
            Some(segment_id),
            Some(payer.account_id),
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let chain_from_head = loader.resolve_chain(head_id).await?;
    assert_eq!(chain_from_head, vec![head_id, segment_id]);

    Ok(())
}

#[test]
async fn a_chained_call_resolves_a_shard_the_mention_never_named() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let payer = &genesis_payer(&mut ctx);
    let account_id = ctx.existing_public_accounts()[0];

    let q = test_programs::data_writer();
    let p = Program::new_unchecked(
        test_methods::SHARD_FORWARDER_ID,
        Cow::Borrowed(test_methods::SHARD_FORWARDER_ELF),
    );
    let q_id = deploy_at_bijection(&mut ctx, payer.account_id, &q).await?;
    let p_id = deploy_at_bijection(&mut ctx, payer.account_id, &p).await?;

    let existing = vec![0xAB_u8; 32];
    let payer_nonce = get_account(&ctx, payer.account_id).await?.nonce;
    submit(
        &ctx,
        q_id,
        vec![ProgramShardSelector::new(account_id, q_id)],
        vec![payer_nonce],
        existing.clone(),
        payer,
        &[],
    )
    .await?;

    let before = get_account_view(&ctx, ProgramShardSelector::new(account_id, q_id)).await?;
    assert_eq!(before.data.shards[&q_id].as_ref(), existing.as_slice());

    let rewritten = vec![0xCD_u8; 48];
    let program = ProgramWithDependencies::new(p, p_id, [(q_id, q)].into());

    ctx.wallet()
        .send_privacy_preserving_tx(
            vec![AccountIdentity::Public(account_id).select_program_shard(p_id)],
            Program::serialize_instruction((
                None::<(AccountId, Vec<u8>)>,
                vec![(
                    q_id,
                    ProgramShardSelector::new(account_id, q_id),
                    Program::serialize_instruction(rewritten.clone())?,
                )],
            ))?,
            &program,
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let after = get_account_view(&ctx, ProgramShardSelector::new(account_id, q_id)).await?;
    assert_eq!(
        after.data.shards[&q_id].as_ref(),
        rewritten.as_slice(),
        "the chained call must have rewritten the shard it opened"
    );

    Ok(())
}
