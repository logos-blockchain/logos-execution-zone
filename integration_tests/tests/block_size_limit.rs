#![expect(
    clippy::as_conversions,
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::time::Duration;

use anyhow::Result;
use bytesize::ByteSize;
use common::transaction::LeeTransaction;
use integration_tests::{TIME_TO_WAIT_FOR_BLOCK_SECONDS, config::SequencerPartialConfig};
use lee::{AccountId, PrivateKey, ProgramShardSelector, PublicKey};
use lee_core::account::Nonce;
use sequencer_service_rpc::RpcClient as _;
use test_fixtures::{
    MultiZoneTestContextBuilder, ZoneTestContextBuilder, config::MultiNodeTestContextConfig,
};
use testnet_initial_state::initial_pub_accounts_private_keys;
use tokio::test;

#[test]
async fn reject_oversized_transaction() -> Result<()> {
    let ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig::default())
                .with_sequencer_partial_config(SequencerPartialConfig {
                    max_num_tx_in_block: 100,
                    max_block_size: ByteSize::mib(1),
                    mempool_max_size: 1000,
                    block_create_timeout: Duration::from_secs(10),
                    priority_fee_percent: sequencer_core::config::default_priority_fee_percent(),
                    channel_params: test_fixtures::config::SequencerPartialConfig::default()
                        .channel_params,
                }),
        )
        .build()
        .await?;

    // Create a transaction that's definitely too large. Block size is 1 MiB (1,048,576 bytes),
    // minus ~200 bytes for header = ~1,048,376 bytes max tx. Create a 1.1 MiB binary to ensure
    // it exceeds the limit. The size check runs before any signature/fee check (see
    // `gossip::validation::evaluate_transaction`), so an unsigned, unfunded `WriteSegment` is
    // enough to exercise it.
    let oversized_binary = vec![0_u8; 1100 * 1024]; // 1.1 MiB binary
    let segment_id = AccountId::from(&PublicKey::new_from_private_key(
        &PrivateKey::try_new([220; 32]).unwrap(),
    ));
    let message = lee::public_transaction::Message::try_new(
        lee_core::program::PROGRAM_LOADER_ACCOUNT_ID,
        vec![ProgramShardSelector::new(
            segment_id,
            lee_core::program::PROGRAM_LOADER_ACCOUNT_ID,
        )],
        vec![lee_core::account::Nonce(0)],
        program_loader_core::Instruction::WriteSegment {
            bytecode: oversized_binary,
            next_segment: None,
        },
    )?;
    let tx = LeeTransaction::Public(lee::PublicTransaction::new(
        message,
        lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
    ));

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
    let ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig::default())
                .with_sequencer_partial_config(SequencerPartialConfig {
                    max_num_tx_in_block: 100,
                    max_block_size: ByteSize::mib(1),
                    mempool_max_size: 1000,
                    block_create_timeout: Duration::from_secs(10),
                    priority_fee_percent: sequencer_core::config::default_priority_fee_percent(),
                    channel_params: test_fixtures::config::SequencerPartialConfig::default()
                        .channel_params,
                }),
        )
        .build()
        .await?;

    // Create a small `WriteSegment` that should fit well within the limit, this time signed and
    // fee-paying so admission accepts it outright rather than just clearing the size check.
    let small_binary = vec![0_u8; 1024]; // 1 KiB binary
    let payer = &initial_pub_accounts_private_keys()[0];
    let segment_key = PrivateKey::try_new([221; 32]).unwrap();
    let segment_id = AccountId::from(&PublicKey::new_from_private_key(&segment_key));
    let payer_nonce = integration_tests::get_account(&ctx, payer.account_id)
        .await?
        .nonce;

    let message = lee::public_transaction::Message::try_new_with_fees(
        lee_core::program::PROGRAM_LOADER_ACCOUNT_ID,
        vec![ProgramShardSelector::new(
            segment_id,
            lee_core::program::PROGRAM_LOADER_ACCOUNT_ID,
        )],
        vec![lee_core::account::Nonce(0), payer_nonce],
        program_loader_core::Instruction::WriteSegment {
            bytecode: small_binary,
            next_segment: None,
        },
        common::test_utils::test_fee_declaration(payer.account_id),
    )?;
    let witness_set = lee::public_transaction::WitnessSet::for_message(
        &message,
        &[&segment_key, &payer.pub_sign_key],
    );
    let tx = LeeTransaction::Public(lee::PublicTransaction::new(message, witness_set));

    // This should succeed
    let result = ctx.sequencer_client().send_transaction(tx).await;

    assert!(
        result.is_ok(),
        "Expected successful submission of small transaction, got error: {:?}",
        result.as_ref().unwrap_err()
    );

    Ok(())
}

#[test]
async fn transaction_deferred_to_next_block_when_current_full() -> Result<()> {
    // Two `WriteSegment` payloads, distinguished by fill byte rather than by being real
    // programs: this test is only about block-size-driven packing/deferral, not about a
    // segment ever resolving into a real deployed program, so a same-sized synthetic filler
    // under `program_loader_core::MAX_SEGMENT_DATA_LEN` stands in for "a program deployment".
    let filler_len = 40 * 1024; // 40 KiB, comfortably under the 96 KiB segment cap
    let filler_a = vec![0xAA_u8; filler_len];
    let filler_b = vec![0xBB_u8; filler_len];

    // Calculate block size to fit only one of the two transactions, leaving some room for
    // headers (e.g., 10 KiB).
    let block_size = ByteSize::b((filler_len + 10 * 1024) as u64);

    let ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig::default())
                .with_sequencer_partial_config(SequencerPartialConfig {
                    max_num_tx_in_block: 100,
                    max_block_size: block_size,
                    mempool_max_size: 1000,
                    block_create_timeout: Duration::from_secs(10),
                    priority_fee_percent: sequencer_core::config::default_priority_fee_percent(),
                    channel_params: test_fixtures::config::SequencerPartialConfig::default()
                        .channel_params,
                }),
        )
        .build()
        .await?;

    let initial_block_height = ctx.sequencer_client().get_last_block_id().await?;

    let payer = &initial_pub_accounts_private_keys()[0];
    let segment_key_a = PrivateKey::try_new([222; 32]).unwrap();
    let segment_id_a = AccountId::from(&PublicKey::new_from_private_key(&segment_key_a));
    let segment_key_b = PrivateKey::try_new([223; 32]).unwrap();
    let segment_id_b = AccountId::from(&PublicKey::new_from_private_key(&segment_key_b));
    let payer_nonce = integration_tests::get_account(&ctx, payer.account_id)
        .await?
        .nonce;

    let build_tx = |segment_key: &PrivateKey,
                    segment_id: AccountId,
                    bytecode: Vec<u8>,
                    nonce_for_payer: Nonce| {
        let message = lee::public_transaction::Message::try_new_with_fees(
            lee_core::program::PROGRAM_LOADER_ACCOUNT_ID,
            vec![ProgramShardSelector::new(
                segment_id,
                lee_core::program::PROGRAM_LOADER_ACCOUNT_ID,
            )],
            vec![lee_core::account::Nonce(0), nonce_for_payer],
            program_loader_core::Instruction::WriteSegment {
                bytecode,
                next_segment: None,
            },
            common::test_utils::test_fee_declaration(payer.account_id),
        )
        .expect("WriteSegment instruction data should always be serializable");
        let witness_set = lee::public_transaction::WitnessSet::for_message(
            &message,
            &[segment_key, &payer.pub_sign_key],
        );
        LeeTransaction::Public(lee::PublicTransaction::new(message, witness_set))
    };

    // Submit both segment writes back to back, before either lands.
    ctx.sequencer_client()
        .send_transaction(build_tx(
            &segment_key_a,
            segment_id_a,
            filler_a.clone(),
            payer_nonce,
        ))
        .await?;
    ctx.sequencer_client()
        .send_transaction(build_tx(
            &segment_key_b,
            segment_id_b,
            filler_b.clone(),
            Nonce(payer_nonce.0 + 1),
        ))
        .await?;

    // Wait for first block
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let block1 = ctx
        .sequencer_client()
        .get_block(initial_block_height + 1)
        .await?
        .unwrap();

    // Which segment-write landed in a given block, identified by its target account id.
    let segment_ids_in_block = |block: &common::block::Block| -> Vec<AccountId> {
        block
            .body
            .transactions
            .iter()
            .filter_map(|tx| {
                let LeeTransaction::Public(public_tx) = tx else {
                    return None;
                };
                if public_tx.message.program_account_id
                    != lee_core::program::PROGRAM_LOADER_ACCOUNT_ID
                {
                    return None;
                }
                let instruction: program_loader_core::Instruction =
                    borsh::from_slice(&public_tx.message.instruction_data).ok()?;
                matches!(
                    instruction,
                    program_loader_core::Instruction::WriteSegment { .. }
                )
                .then(|| public_tx.message.shard_selectors[0].account_id)
            })
            .collect()
    };

    let block1_segment_ids = segment_ids_in_block(&block1);

    // The first segment write should be in block 1, but not both due to block size limit.
    assert_eq!(
        block1_segment_ids.len(),
        1,
        "Expected exactly one segment write in block 1"
    );
    assert_eq!(
        block1_segment_ids[0], segment_id_a,
        "Expected the first segment write to be in block 1"
    );

    // Wait for second block
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let block2 = ctx
        .sequencer_client()
        .get_block(initial_block_height + 2)
        .await?
        .unwrap();
    let block2_segment_ids = segment_ids_in_block(&block2);

    // The other segment write should be in block 2.
    assert_eq!(
        block2_segment_ids.len(),
        1,
        "Expected exactly one segment write in block 2"
    );
    assert_eq!(
        block2_segment_ids[0], segment_id_b,
        "Expected the second segment write to be deferred to block 2"
    );

    Ok(())
}
