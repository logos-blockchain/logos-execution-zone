#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::borrow::Cow;

use anyhow::Result;
use common::transaction::LeeTransaction;
use integration_tests::{
    TestContext, private_mention, public_mention,
    utils::{
        account_balance, create_token, get_account, get_account_view, new_account, send,
        wait_for_indexer_to_catch_up, wait_until,
    },
};
use lee::{
    AccountId, PrivateKey, ProgramShardSelector, PublicKey,
    privacy_preserving_transaction::circuit::ProgramWithDependencies, program::Program,
};
use lee_core::{
    account::Nonce, native_token::NATIVE_TOKEN_PROGRAM_ID, program::PROGRAM_LOADER_ACCOUNT_ID,
};
use program_loader_core::MAX_SEGMENT_DATA_LEN;
use sequencer_service_rpc::RpcClient as _;
use testnet_initial_state::{PublicAccountPrivateInitialData, initial_pub_accounts_private_keys};
use tokio::test;
use wallet::{
    AccountIdentity,
    cli::{
        Command,
        account::{AccountSubcommand, ReadScope},
        execute_subcommand,
    },
    program_facades::program_loader::ProgramLoader,
};

const BLOAT_SHARD_BYTES: usize = 96 * 1024;

const BLOAT_WRITERS: usize = 30;

// This test only exercises chain *resolution* under a bloated account, never `CreateHeader`,
// so `bytecode` is never decoded or validated as a real program - arbitrary filler well under
// `MAX_SEGMENT_DATA_LEN` stands in for "a segment's content", same as `bloat_account`'s own
// shard writes use plain filler rather than real program data.
const SEGMENT_FILLER_BYTES: usize = 1024;

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
        // A bloat shard write costs far more than `test_fee_declaration`'s 2M cycle cap,
        // and an over-cap call is a charged revert: it settles and writes nothing.
        lee::FeeDeclaration::new(
            payer.account_id,
            fee_core::market::MAX_GAS_EXEC,
            0,
            u128::MAX >> 1,
        ),
    )?;
    let mut keys = extra_signers.to_vec();
    keys.push(&payer.pub_sign_key);
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &keys);

    let tx_hash = ctx
        .sequencer_client()
        .send_transaction(LeeTransaction::Public(lee::PublicTransaction::new(
            message,
            witness_set,
        )))
        .await?;

    // Wait for real inclusion rather than a block's worth of sleep. Every caller reads
    // the payer's nonce for the next submission and the bloat writers name programs the
    // previous submission deployed, so proceeding on a transaction that never settled
    // produces a nonce mismatch or an unknown program several steps later.
    wait_until(&format!("transaction {tx_hash} to be included"), || async {
        Ok(ctx
            .sequencer_client()
            .get_transaction(tx_hash)
            .await?
            .is_some())
    })
    .await?;
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

/// Segments hold `user_elf` alone, the kernel is re-attached on read, so size the chain off
/// that rather than the full ELF or the loader rejects the count.
async fn fresh_segments(ctx: &mut TestContext, program: &Program) -> Result<Vec<AccountId>> {
    let byte_len = program.user_elf().expect("a test program decodes").len();
    let mut segments = Vec::new();
    for _ in 0..byte_len.div_ceil(MAX_SEGMENT_DATA_LEN) {
        segments.push(new_account(ctx, false, None).await?);
    }
    Ok(segments)
}

async fn deploy_fresh_program(
    ctx: &mut TestContext,
    payer: AccountId,
    program: &Program,
) -> Result<AccountId> {
    let segments = fresh_segments(ctx, program).await?;
    let header = new_account(ctx, false, None).await?;

    ProgramLoader(ctx.wallet())
        .deploy(header, &segments, program.elf().to_vec(), true, Some(payer))
        .await
}

async fn bloat_account(
    ctx: &mut TestContext,
    victim: AccountId,
) -> Result<[AccountId; BLOAT_WRITERS]> {
    let payer = &genesis_payer(ctx);
    let writer = test_programs::data_writer();

    let segments = fresh_segments(ctx, &writer).await?;
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
        // `deploy` polls each of its own steps, but `create_header` hands back the hash
        // and returns. Three in a row would each build on a payer nonce the previous one
        // has not spent yet, and the sequencer rejects the later two on nonce mismatch.
        let payer_nonce_before = get_account(ctx, payer.account_id).await?.nonce;
        ProgramLoader(ctx.wallet())
            .create_header(header, segments[0], &segments, true, Some(payer.account_id))
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        wait_until(&format!("header {header} to be created"), || async {
            Ok(get_account(ctx, payer.account_id).await?.nonce != payer_nonce_before)
        })
        .await?;
        writers.push(header);
    }

    let shard = vec![0xFF_u8; BLOAT_SHARD_BYTES];
    for writer_id in &writers {
        let payer_nonce = get_account(ctx, payer.account_id).await?.nonce;
        submit(
            ctx,
            *writer_id,
            vec![ProgramShardSelector::new(victim, *writer_id)],
            vec![payer_nonce],
            shard.clone(),
            payer,
            &[],
        )
        .await?;
        let view = get_account_view(ctx, ProgramShardSelector::new(victim, *writer_id)).await?;
        assert_eq!(
            view.data.shards[writer_id].as_ref(),
            shard.as_slice(),
            "the bloat write must have taken effect, not merely been included"
        );
    }

    writers
        .try_into()
        .map_err(|_ignored| anyhow::anyhow!("writer count is BLOAT_WRITERS by construction"))
}

#[test]
async fn a_bloated_account_defeats_the_whole_account_read_but_not_the_scoped_one() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let victim = ctx.existing_public_accounts()[0];

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
    }

    let balance_only = get_account_view(&ctx, ProgramShardSelector::balance(victim)).await?;
    assert_eq!(
        balance_only.data.shards.keys().copied().collect::<Vec<_>>(),
        vec![NATIVE_TOKEN_PROGRAM_ID],
        "a balance view carries exactly the native shard"
    );

    let last_writer = writers[BLOAT_WRITERS - 1];
    let scoped_get = |scope: ReadScope, raw: bool| {
        Command::Account(AccountSubcommand::Get {
            raw,
            keys: false,
            account_id: public_mention(victim),
            scope,
        })
    };
    execute_subcommand(ctx.wallet_mut(), scoped_get(ReadScope::Balance, false)).await?;
    execute_subcommand(
        ctx.wallet_mut(),
        scoped_get(ReadScope::Shard(last_writer), false),
    )
    .await?;
    execute_subcommand(
        ctx.wallet_mut(),
        scoped_get(ReadScope::Shard(last_writer), true),
    )
    .await?;
    let cli_error = execute_subcommand(ctx.wallet_mut(), scoped_get(ReadScope::All, false))
        .await
        .expect_err("--scope all must stay a whole-account read");
    assert!(
        is_oversized_response(&cli_error),
        "--scope all must fail on response size specifically: {cli_error:?}"
    );

    Ok(())
}

/// The indexer's view of a bloated account: scoped reads and the summary keep working.
#[test]
#[ignore = "the indexer cannot keep up with 2.8 MB blocks, #901"]
async fn a_bloated_account_stays_readable_through_the_indexer() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let victim = ctx.existing_public_accounts()[0];

    let height_before_bloat = ctx.sequencer_client().get_last_block_id().await?;
    let writers = bloat_account(&mut ctx, victim).await?;
    let last_writer = writers[BLOAT_WRITERS - 1];
    let balance_only = get_account_view(&ctx, ProgramShardSelector::balance(victim)).await?;

    let indexer_height = wait_for_indexer_to_catch_up(&ctx).await?;
    let selector: indexer_service_protocol::ProgramShardSelector =
        ProgramShardSelector::new(victim, last_writer).into();
    let native_selector: indexer_service_protocol::ProgramShardSelector =
        ProgramShardSelector::balance(victim).into();
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
    let native_before = indexer_service_rpc::RpcClient::get_account_view_at_block(
        indexer,
        native_selector,
        height_before_bloat,
    )
    .await?;
    assert_eq!(
        native_before.data.balance().unwrap(),
        balance_only.data.balance().unwrap(),
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
    assert_eq!(after_population.nonce, balance_only.nonce.0);
    let native_after = indexer_service_rpc::RpcClient::get_account_view_at_block(
        indexer,
        native_selector,
        indexer_height,
    )
    .await?;
    assert_eq!(
        native_after.data.balance().unwrap(),
        balance_only.data.balance().unwrap()
    );

    // The explorer renders shard counts and sizes, so it needs to enumerate shards on
    // an account a scoped read cannot enumerate and a whole-account read can no longer
    // return. The summary answers that without carrying the bytes.
    let victim_key: indexer_service_protocol::AccountId = victim.into();
    assert!(
        indexer_service_rpc::RpcClient::get_account(indexer, victim_key)
            .await
            .is_err(),
        "the whole-account indexer read must fail on the bloated account"
    );
    let expected_shard_len =
        u64::try_from(BLOAT_SHARD_BYTES).expect("the bloat shard size fits in u64");
    let summary = indexer_service_rpc::RpcClient::get_account_summary(indexer, victim_key).await?;
    let native_key = indexer_service_protocol::AccountId::native_token_program();
    assert_eq!(
        summary.shards.len(),
        writers.len() + 1,
        "the summary must list every shard the bloat wrote, plus the native balance shard"
    );
    assert!(
        summary
            .shards
            .iter()
            .filter(|shard| shard.program_account_id != native_key)
            .all(|shard| shard.len == expected_shard_len),
        "the summary must carry each shard's real size"
    );
    assert_eq!(summary.balance, balance_only.data.balance().ok());
    assert_eq!(summary.nonce, balance_only.nonce.0);

    let missing = indexer_service_rpc::RpcClient::get_account_view(
        indexer,
        ProgramShardSelector::balance(AccountId::new([0x5A; 32])).into(),
    )
    .await?;
    assert_eq!(missing.data.balance().unwrap(), 0);
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
async fn an_application_scoped_call_still_finds_its_funded_payer() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let supply = ctx.existing_public_accounts()[0];
    let definition = new_account(&mut ctx, false, None).await?;

    assert_eq!(
        account_balance(&ctx, definition).await?,
        0,
        "the definition account must start unfunded for this to exercise payer selection"
    );
    let supply_before = account_balance(&ctx, supply).await?;

    create_token(
        &mut ctx,
        public_mention(definition),
        public_mention(supply),
        "ScopedPayer",
        1_000,
    )
    .await?;

    let token_program_id = programs::token_account_id();
    let definition_view = get_account_view(
        &ctx,
        ProgramShardSelector::new(definition, token_program_id),
    )
    .await?;
    assert!(
        !definition_view.data.shard(token_program_id).is_empty(),
        "the definition must have been written, so the transaction was admitted and settled"
    );
    assert!(
        account_balance(&ctx, supply).await? < supply_before,
        "the funded signer paid the fee, not the empty definition account"
    );
    assert_eq!(
        account_balance(&ctx, definition).await?,
        0,
        "the unfunded signer was never selected as payer"
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
            bytecode: vec![0xAB_u8; SEGMENT_FILLER_BYTES],
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
    let tx_hash = loader
        .write_segment(
            head_id,
            vec![0xAB_u8; SEGMENT_FILLER_BYTES],
            Some(segment_id),
            Some(payer.account_id),
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    ctx.wallet().poll_transaction(tx_hash).await?;

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
    let q_id = deploy_fresh_program(&mut ctx, payer.account_id, &q).await?;
    let p_id = deploy_fresh_program(&mut ctx, payer.account_id, &p).await?;

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

    let (tx_hash, _) = ctx
        .wallet()
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
    ctx.wallet().poll_transaction(tx_hash).await?;

    let after = get_account_view(&ctx, ProgramShardSelector::new(account_id, q_id)).await?;
    assert_eq!(
        after.data.shards[&q_id].as_ref(),
        rewritten.as_slice(),
        "the chained call must have rewritten the shard it opened"
    );

    Ok(())
}
