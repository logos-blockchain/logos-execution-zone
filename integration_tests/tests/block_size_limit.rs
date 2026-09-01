#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::time::Duration;

use anyhow::Result;
use bytesize::ByteSize;
use common::transaction::LeeTransaction;
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, config::SequencerPartialConfig, deploy_program_transactions,
    encoded_tx_size,
};
use lee::{AccountId, PrivateKey};
use lee_core::program::PROGRAM_LOADER_ACCOUNT_ID;
use sequencer_service_rpc::RpcClient as _;
use test_fixtures::{
    MultiZoneTestContextBuilder, ZoneTestContextBuilder, config::MultiNodeTestContextConfig,
};
use tokio::test;

#[test]
async fn reject_oversized_transaction() -> Result<()> {
    // Unsigned: the size check this test exercises runs before any signature/authorization
    // check, so there's nothing to gain from a real key here.
    let bytecode = test_programs::claimer().elf().to_vec();
    let message = lee::public_transaction::Message::try_new(
        PROGRAM_LOADER_ACCOUNT_ID,
        vec![AccountId::new([1; 32])],
        vec![],
        program_loader_core::Instruction::WriteSegment {
            bytecode,
            next_segment: None,
        },
    )?;
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = LeeTransaction::Public(lee::PublicTransaction::new(message, witness_set));
    let tx_size = encoded_tx_size(&tx);

    let ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig::default())
                .with_sequencer_partial_config(SequencerPartialConfig {
                    max_num_tx_in_block: 100,
                    max_block_size: ByteSize::b(tx_size),
                    mempool_max_size: 1000,
                    block_create_timeout: Duration::from_secs(10),
                    priority_fee: sequencer_core::config::default_priority_fee(),
                }),
        )
        .build()
        .await?;

    // Try to submit the transaction and expect an error
    let result = ctx.sequencer_client().send_transaction(tx).await;

    assert!(
        result.is_err(),
        "Expected error when submitting oversized transaction"
    );

    let err = result.unwrap_err();
    let err_str = format!("{err:?}");

    // Check if the error contains information about transaction being too large
    assert!(
        err_str.contains("TransactionTooLarge") || err_str.contains("too large"),
        "Expected TransactionTooLarge error, got: {err_str}"
    );

    Ok(())
}

#[test]
async fn accept_transaction_within_limit() -> Result<()> {
    // One real segment-sized chunk of a guest binary: a whole real program no longer fits in one
    // segment under the current cap. Unsigned, like `reject_oversized_transaction` above —
    // `send_transaction`'s Ok/Err here reflects size and signature-shape checks only, not
    // authorization, which is only checked at actual state execution.
    let bytecode =
        test_programs::claimer().elf()[..program_loader_core::MAX_SEGMENT_DATA_LEN].to_vec();
    let message = lee::public_transaction::Message::try_new(
        PROGRAM_LOADER_ACCOUNT_ID,
        vec![AccountId::new([2; 32])],
        vec![],
        program_loader_core::Instruction::WriteSegment {
            bytecode,
            next_segment: None,
        },
    )?;
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = LeeTransaction::Public(lee::PublicTransaction::new(message, witness_set));
    let tx_size = encoded_tx_size(&tx);

    let ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig::default())
                .with_sequencer_partial_config(SequencerPartialConfig {
                    max_num_tx_in_block: 100,
                    // TOFIX: should be `ByteSize::mib(1)` again once the program-as-account
                    // migration is finished.
                    max_block_size: ByteSize::b(tx_size + 10 * 1024),
                    mempool_max_size: 1000,
                    block_create_timeout: Duration::from_secs(10),
                    priority_fee: sequencer_core::config::default_priority_fee(),
                }),
        )
        .build()
        .await?;

    // This should succeed
    let result = ctx.sequencer_client().send_transaction(tx).await;

    assert!(
        result.is_ok(),
        "Expected successful submission of small transaction, got error: {:?}",
        result.as_ref().unwrap_err()
    );

    Ok(())
}

/// A deploy is several transactions now (one `NewSegment` per chunk, plus `UploadHeader`), so
/// deferral has to be exercised — and checked — at that granularity: the block size below fits
/// every transaction of `claimer`'s deploy but not chain_caller's first, so the whole first
/// deploy lands in block 1 and the whole second is deferred to block 2 intact.
#[test]
async fn transaction_deferred_to_next_block_when_current_full() -> Result<()> {
    let claimer = test_programs::claimer();
    let chain_caller = test_programs::chain_caller();

    let claimer_key = PrivateKey::try_new([3; 32]).unwrap();
    let (_claimer_header, claimer_txs) =
        deploy_program_transactions(claimer.elf(), 10, &claimer_key);
    let claimer_txs: Vec<LeeTransaction> = claimer_txs.into_iter().map(LeeTransaction::Public).collect();

    let chain_caller_key = PrivateKey::try_new([4; 32]).unwrap();
    let (_chain_caller_header, chain_caller_txs) = deploy_program_transactions(
        chain_caller.elf(),
        40,
        &chain_caller_key,
    );
    let chain_caller_txs: Vec<LeeTransaction> = chain_caller_txs
        .into_iter()
        .map(LeeTransaction::Public)
        .collect();

    let claimer_total_size: u64 = claimer_txs.iter().map(encoded_tx_size).sum();
    let block_size = ByteSize::b(claimer_total_size + 10 * 1024);

    let ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig::default())
                .with_sequencer_partial_config(SequencerPartialConfig {
                    max_num_tx_in_block: 100,
                    max_block_size: block_size,
                    mempool_max_size: 1000,
                    block_create_timeout: Duration::from_secs(10),
                    priority_fee: sequencer_core::config::default_priority_fee(),
                }),
        )
        .build()
        .await?;

    let initial_block_height = ctx.sequencer_client().get_last_block_id().await?;

    for tx in claimer_txs.iter().chain(chain_caller_txs.iter()).cloned() {
        ctx.sequencer_client().send_transaction(tx).await?;
    }

    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;
    let block1 = ctx
        .sequencer_client()
        .get_block(initial_block_height + 1)
        .await?
        .unwrap();

    assert_eq!(
        program_loader_txs(&block1),
        as_sorted_bytes(&claimer_txs),
        "block 1 should hold exactly claimer's full deploy"
    );

    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;
    let block2 = ctx
        .sequencer_client()
        .get_block(initial_block_height + 2)
        .await?
        .unwrap();

    assert_eq!(
        program_loader_txs(&block2),
        as_sorted_bytes(&chain_caller_txs),
        "block 2 should hold exactly chain_caller's full deploy, deferred whole from block 1"
    );

    Ok(())
}

/// `program_loader` transactions in `block`, borsh-encoded and sorted — order-independent so it
/// can be compared directly against [`as_sorted_bytes`] of an expected transaction set.
fn program_loader_txs(block: &common::block::Block) -> Vec<Vec<u8>> {
    as_sorted_bytes(block.body.transactions.iter().filter(|tx| {
        matches!(tx, LeeTransaction::Public(public_tx)
            if public_tx.message.program_account_id == PROGRAM_LOADER_ACCOUNT_ID)
    }))
}

fn as_sorted_bytes<'a>(txs: impl IntoIterator<Item = &'a LeeTransaction>) -> Vec<Vec<u8>> {
    let mut bytes: Vec<Vec<u8>> = txs
        .into_iter()
        .map(|tx| borsh::to_vec(tx).expect("transaction should serialize"))
        .collect();
    bytes.sort();
    bytes
}
