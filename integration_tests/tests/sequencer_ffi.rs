//! Sequecner FFI tests.

#![expect(
    clippy::tests_outside_test_module,
    reason = "Integration tests live at crate root and don't care about these lints"
)]
#![expect(
    clippy::shadow_unrelated,
    clippy::cast_possible_truncation,
    clippy::as_conversions,
    reason = "We don't care about it in tests"
)]

use std::time::Duration;

use anyhow::{Context as _, Result};
use common::transaction::LeeTransaction;
use integration_tests::{get_account, new_account};
use lee::AccountId;
use lee_core::program::{InstructionData, ProgramEvent};
use log::info;
use logos_blockchain_zone_sdk::adapter::Node as _;
use sequencer_core::block_publisher::Ed25519Key;
use sequencer_ffi::api::types::{FfiOption, transaction::FfiTransactionKind};
use sequencer_service_rpc::RpcClient as _;
use test_fixtures::{TIME_TO_WAIT_FOR_BLOCK_SECONDS, config::bedrock_channel_id};

use crate::sequencer_ffi_helpers::sequencer_ffi_query_events;

#[path = "sequencer_ffi_helpers/mod.rs"]
mod sequencer_ffi_helpers;

#[test]
fn sequencer_ffi_join_setup_and_simple_queries_test() -> Result<()> {
    let (ctx, node, ownership_id, sequencer_ffi_res) = sequencer_ffi_helpers::joining_setup()?;

    let sequencer_ffi =
    // SAFETY: sequencer_ffi_helpers::joining_setup guarantees validity.
    unsafe {&*sequencer_ffi_res.value} ;

    let joining_sequencer_key =
        Ed25519Key::from_bytes(&sequencer_ffi_helpers::JOINER_SIGNING_KEY).public_key();

    let joined_at = ctx.block_on(|ctx| ctx.sequencer_client().get_last_block_id())?;
    sequencer_ffi_helpers::wait_for_sequencer_ffi_block(sequencer_ffi, joined_at)?;
    info!("Joining sequencer synced to block {joined_at}");

    // A tip past `joined_at` under the joining key is a block this node built.
    let mut poll_flag = false;
    for _ in 0..180 {
        let state = ctx
            .runtime()
            .block_on(node.channel_state(bedrock_channel_id()))
            .context("Failed to read Bedrock channel state")?
            .context("Bedrock channel does not exist")?;

        let turn = state
            .accredited_keys
            .get(usize::from(state.tip_sequencer))
            .copied();

        if turn == Some(joining_sequencer_key)
            && ctx.block_on(|ctx| ctx.sequencer_client().get_last_block_id())? > joined_at
        {
            poll_flag = true;
            break;
        }

        std::thread::sleep(Duration::from_secs(1));
    }

    if !poll_flag {
        anyhow::bail!("The joining sequencer failed to build a block on its turn");
    }
    info!("Joining sequencer produced a block on its round-robin turn");

    // Both nodes agree, block for block, over everything they share.
    let common = ctx
        .block_on(|ctx| ctx.sequencer_client().get_last_block_id())?
        .min({
            let res =
            // SAFETY: sequencer_ffi created by FFI, it is valid.
            unsafe {
                sequencer_ffi_helpers::sequencer_ffi_query_last_block(std::ptr::from_ref(sequencer_ffi))
            };
            if res.error.is_ok() && res.is_some {
                Ok(res.block_id)
            } else {
                Err(anyhow::anyhow!("Failed to get last block id from FFI"))
            }
        }?);
    for id in 1..=common {
        let leader_block = ctx.block_on(|ctx| async {
            ctx.sequencer_client()
                .get_block(id)
                .await?
                .with_context(|| format!("Leader is missing block {id}"))
        })?;

        let joiner_block_hash = {
            let joiner_block_res =
            // SAFETY: sequencer_ffi created by FFI, it is valid.
            unsafe {
                sequencer_ffi_helpers::sequencer_ffi_query_block(std::ptr::from_ref(sequencer_ffi), id)
            };
            if joiner_block_res.error.is_ok() {
                let joiner_block_opt =
                // SAFETY: FFI ensures validity of value.
                unsafe { joiner_block_res.value.read() };

                let ffi_hash = if joiner_block_opt.is_some {
                    Ok(
                        // SAFETY: FFI ensures validity of value.
                        unsafe { joiner_block_opt.value.read().header.hash },
                    )
                } else {
                    Err(anyhow::anyhow!("Block is missing in FFI"))
                };

                // SAFETY: FFI ensures validity of value.
                unsafe {
                    sequencer_ffi_helpers::sequencer_ffi_free_ffi_block_opt(joiner_block_res.value);
                };

                ffi_hash
            } else {
                Err(anyhow::anyhow!("Failed to get last block from FFI"))
            }
        }?;
        anyhow::ensure!(
            leader_block.header.hash.0 == joiner_block_hash.data,
            "Chain divergence at block {id}: leader {:?} vs joiner {:?}",
            leader_block.header.hash.0,
            joiner_block_hash.data
        );
    }
    info!("Leader and joining sequencer agree on all {common} shared blocks");

    let ownership_account = ctx.block_on(|ctx| async {
        get_account(ctx, ownership_id)
            .await
            .context("Failed to read the stake ownership account")
    })?;

    let joined_ownership_account =
    // SAFETY: sequencer_ffi created by FFI, it is valid.
    unsafe {
        sequencer_ffi_helpers::sequencer_ffi_query_account(
            std::ptr::from_ref(sequencer_ffi),
            ownership_id.into(),
        )
    };

    assert!(
        joined_ownership_account.error.is_ok(),
        "Failed to fetch ownership account"
    );

    let joined_ownership_account_cast =
    // SAFETY: FFI ensures validity of value.
    unsafe {
        joined_ownership_account
            .value
            .read()
            .try_into()
            .expect("Data must fit")
    };

    assert_eq!(ownership_account, joined_ownership_account_cast);

    info!("Leader and joining sequencer agree on {ownership_id} account");

    // SAFETY: sequencer_ffi created by FFI, it is valid.
    unsafe {
        sequencer_ffi_helpers::sequencer_ffi_stop_sequencer(sequencer_ffi_res.value);
    }

    Ok(())
}

#[test]
fn sequencer_ffi_acc_id_to_tx_map() -> Result<()> {
    let (ctx, node, owner_id, sequencer_ffi_res) = sequencer_ffi_helpers::joining_setup()?;

    let sequencer_ffi =
    // SAFETY: sequencer_ffi_helpers::joining_setup guarantees validity.
    unsafe {&*sequencer_ffi_res.value} ;

    let joining_sequencer_key =
        Ed25519Key::from_bytes(&sequencer_ffi_helpers::JOINER_SIGNING_KEY).public_key();

    let joined_at = ctx.block_on(|ctx| ctx.sequencer_client().get_last_block_id())?;
    sequencer_ffi_helpers::wait_for_sequencer_ffi_block(sequencer_ffi, joined_at)?;
    info!("Joining sequencer synced to block {joined_at}");

    // A tip past `joined_at` under the joining key is a block this node built.
    let mut poll_flag = false;
    for _ in 0..180 {
        let state = ctx
            .runtime()
            .block_on(node.channel_state(bedrock_channel_id()))
            .context("Failed to read Bedrock channel state")?
            .context("Bedrock channel does not exist")?;

        let turn = state
            .accredited_keys
            .get(usize::from(state.tip_sequencer))
            .copied();

        if turn == Some(joining_sequencer_key)
            && ctx.block_on(|ctx| ctx.sequencer_client().get_last_block_id())? > joined_at
        {
            poll_flag = true;
            break;
        }

        std::thread::sleep(Duration::from_secs(1));
    }

    if !poll_flag {
        anyhow::bail!("The joining sequencer failed to build a block on its turn");
    }
    info!("Joining sequencer produced a block on its round-robin turn");

    // Both nodes agree, block for block, over everything they share.
    let common = ctx
        .block_on(|ctx| ctx.sequencer_client().get_last_block_id())?
        .min({
            let res =
            // SAFETY: sequencer_ffi created by FFI, it is valid.
            unsafe {
                sequencer_ffi_helpers::sequencer_ffi_query_last_block(std::ptr::from_ref(sequencer_ffi))
            };
            if res.error.is_ok() && res.is_some {
                Ok(res.block_id)
            } else {
                Err(anyhow::anyhow!("Failed to get last block id from FFI"))
            }
        }?);

    // Reading block vector, then re-reading blocks from hashes to test ffi functionality.

    let joiner_block_vec_res =
            // SAFETY: FFI ensures validity of value.
            unsafe {
                sequencer_ffi_helpers::sequencer_ffi_query_block_vec(sequencer_ffi,
                FfiOption::from_value(common), common )
            };

    assert!(
        joiner_block_vec_res.error.is_ok(),
        "Block vec fetch must be successfull"
    );

    let joiner_block_vec =
    // SAFETY: FFI ensures validity of value.
    unsafe { joiner_block_vec_res.value.read() };

    for i in 0..(common.saturating_sub(1) as usize) {
        let ffi_block =
        // SAFETY: FFI ensures validity of value.
        unsafe{joiner_block_vec.get(i)};

        let ffi_block_hash = ffi_block.header.hash;

        let ffi_block_got_by_hash_res =
        // SAFETY: FFI ensures validity of value.
        unsafe{
            sequencer_ffi_helpers::sequencer_ffi_query_block_by_hash(sequencer_ffi, ffi_block_hash)
        };

        assert!(
            ffi_block_got_by_hash_res.error.is_ok(),
            "Block fetch must be successfull"
        );

        let ffi_block_got_by_hash_opt =
        // SAFETY: FFI ensures validity of value.
        unsafe{ ffi_block_got_by_hash_res.value.read() };

        assert!(ffi_block_got_by_hash_opt.is_some, "Block must be present");

        let ffi_block_got_by_hash =
        // SAFETY: FFI ensures validity of value.
        unsafe{ ffi_block_got_by_hash_opt.value.read() };

        assert_eq!(
            ffi_block_got_by_hash.header.hash.data, ffi_block_hash.data,
            "Block hashes of blocks fetched by id and hash must be the same"
        );

        // SAFETY: FFI ensures validity of value.
        unsafe {
            sequencer_ffi_helpers::sequencer_ffi_free_ffi_block_opt(
                ffi_block_got_by_hash_res.value,
            );
        }

        let leader_block = ctx.block_on(|ctx| async {
            ctx.sequencer_client()
                .get_block((i + 1) as u64)
                .await?
                .with_context(|| format!("Leader is missing block {}", i + 1))
        })?;

        anyhow::ensure!(
            leader_block.header.hash.0 == ffi_block_hash.data,
            "Chain divergence at block {}: leader {:?} vs joiner {:?}",
            i + 1,
            leader_block.header.hash.0,
            ffi_block_hash.data
        );
    }
    info!("Leader and joining sequencer agree on all {common} shared blocks");

    // Get first `common` transactions of a owner_id.

    let owner_id_transactions_res =
    // SAFETY: FFI ensures validity of value.
    unsafe{
        sequencer_ffi_helpers::sequencer_ffi_query_transactions_by_account(
            sequencer_ffi,
            owner_id.into(),
            0,
            common
        )
    };

    assert!(
        owner_id_transactions_res.error.is_ok(),
        "Transaction vec fetch must be successfull"
    );

    let owner_id_transactions =
    // SAFETY: FFI ensures validity of value.
    unsafe{ owner_id_transactions_res.value.read() };

    // Sanity check, there should be exactly 2 transaction
    // and it must affect owner_id.

    assert_eq!(owner_id_transactions.len, 2);

    let owner_id_tx =
        // SAFETY: FFI ensures validity of value.
        unsafe{ owner_id_transactions.get(0) };

    match owner_id_tx.kind {
        FfiTransactionKind::Public => {
            let ffi_acc_ids =
                // SAFETY: FfiTransactionKind ensures validity of value.
                unsafe { owner_id_tx.body.public_body.read().message.shard_selectors };

            let second_ffi_acc =
                // SAFETY: FfiTransactionKind ensures validity of value.
                unsafe { ffi_acc_ids.get(1).account_id.data };

            assert_eq!(second_ffi_acc, *owner_id.value());
        }
        FfiTransactionKind::Private => {
            return Err(anyhow::anyhow!("All owner_id transactions must be public"));
        }
    }

    let owner_id_tx =
        // SAFETY: FFI ensures validity of value.
        unsafe{ owner_id_transactions.get(1) };

    match owner_id_tx.kind {
        FfiTransactionKind::Public => {
            let ffi_acc_ids =
                // SAFETY: FfiTransactionKind ensures validity of value.
                unsafe { owner_id_tx.body.public_body.read().message.shard_selectors };

            let forth_ffi_acc =
                // SAFETY: FfiTransactionKind ensures validity of value.
                unsafe { ffi_acc_ids.get(3).account_id.data };

            assert_eq!(forth_ffi_acc, *owner_id.value());
        }
        FfiTransactionKind::Private => {
            return Err(anyhow::anyhow!("All owner_id transactions must be public"));
        }
    }

    // SAFETY: FFI ensures validity of value.
    unsafe {
        sequencer_ffi_helpers::sequencer_ffi_free_ffi_block_vec(joiner_block_vec_res.value);
    }

    // SAFETY: FFI ensures validity of value.
    unsafe {
        sequencer_ffi_helpers::sequencer_ffi_free_ffi_transaction_vec(
            owner_id_transactions_res.value,
        );
    }

    // SAFETY: sequencer_ffi created by FFI, it is valid.
    unsafe {
        sequencer_ffi_helpers::sequencer_ffi_stop_sequencer(sequencer_ffi_res.value);
    }

    Ok(())
}

#[test]
fn sequencer_ffi_event_test() -> Result<()> {
    let (mut ctx, node, _, sequencer_ffi_res) = sequencer_ffi_helpers::joining_setup()?;

    let sequencer_ffi =
    // SAFETY: sequencer_ffi_helpers::joining_setup guarantees validity.
    unsafe {&*sequencer_ffi_res.value} ;

    let joining_sequencer_key =
        Ed25519Key::from_bytes(&sequencer_ffi_helpers::JOINER_SIGNING_KEY).public_key();

    let joined_at = ctx.block_on(|ctx| ctx.sequencer_client().get_last_block_id())?;
    sequencer_ffi_helpers::wait_for_sequencer_ffi_block(sequencer_ffi, joined_at)?;
    info!("Joining sequencer synced to block {joined_at}");

    // A tip past `joined_at` under the joining key is a block this node built.
    let mut poll_flag = false;
    for _ in 0..180 {
        let state = ctx
            .runtime()
            .block_on(node.channel_state(bedrock_channel_id()))
            .context("Failed to read Bedrock channel state")?
            .context("Bedrock channel does not exist")?;

        let turn = state
            .accredited_keys
            .get(usize::from(state.tip_sequencer))
            .copied();

        if turn == Some(joining_sequencer_key)
            && ctx.block_on(|ctx| ctx.sequencer_client().get_last_block_id())? > joined_at
        {
            poll_flag = true;
            break;
        }

        std::thread::sleep(Duration::from_secs(1));
    }

    if !poll_flag {
        anyhow::bail!("The joining sequencer failed to build a block on its turn");
    }
    info!("Joining sequencer produced a block on its round-robin turn");

    // Deploying event emitter

    let deployed = test_programs::event_emitter();
    // Every account a deploy touches is freshly claimed and unfunded, so a genesis-funded wallet
    // account covers the fees instead (see `ProgramLoader::send`).
    let payer_id = ctx.ctx().existing_public_accounts()[0];

    // Deploy through `program_loader`: one segment holds the (small, test-sized) program's
    // `user_elf`, then a header claims it. Both accounts are freshly claimed, permissionless
    // writes.
    let header_id = ctx.block_on_mut(|ctx| new_account(ctx, false, None))?;
    let mut segment_ids = Vec::new();
    for _ in deployed
        .user_elf()
        .expect("valid ProgramBinary")
        .chunks(program_loader_core::MAX_SEGMENT_DATA_LEN)
    {
        segment_ids.push(ctx.block_on_mut(|ctx| new_account(ctx, false, None))?);
    }
    let account_id = ctx.block_on(|ctx| async {
        wallet::program_facades::program_loader::ProgramLoader(ctx.wallet())
            .deploy(
                header_id,
                &segment_ids,
                deployed.elf().to_vec(),
                true,
                Some(payer_id),
            )
            .await
    })?;

    // The claimed account holds nothing to fund the reserve with, so `payer_id` co-signs: its
    // nonce and signature go last, after the account list's own.
    let nonces = ctx.block_on_mut(|ctx| async {
        ctx.wallet_mut()
            .get_accounts_nonces(&[payer_id])
            .await
    })?;
    let message = lee::public_transaction::Message::try_new_with_fees(
        account_id,
        vec![lee::ProgramShardSelector::balance(payer_id)],
        nonces,
        EmitterInstruction {
                events: vec![emitted(5)],
                chain: vec![],
            },
        common::test_utils::test_fee_declaration(payer_id),
    )?;
    let payer_key = ctx
        .ctx()
        .wallet()
        .get_account_public_signing_key(payer_id)
        .unwrap();
    let witness_set =
        lee::public_transaction::WitnessSet::for_message(&message, &[payer_key]);
    let transaction = lee::PublicTransaction::new(message, witness_set);
    let _response = ctx.block_on(|ctx| {
        ctx.sequencer_client()
            .send_transaction(LeeTransaction::Public(transaction))
    })?;

    log::info!("Waiting for next block creation");
    // Waiting for long time as it may take some time for such a big transaction to be included in a
    // block
    std::thread::sleep(Duration::from_secs(2 * TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    let next_id_after_deploy_res = unsafe {
                sequencer_ffi_helpers::sequencer_ffi_query_last_block(std::ptr::from_ref(sequencer_ffi))
            };
    
    let next_id_after_deploy = if next_id_after_deploy_res.is_some && next_id_after_deploy_res.error.is_ok() {
        next_id_after_deploy_res.block_id
    } else {
        anyhow::bail!("After deploy next id failure");
    };

    let events_vec_res = unsafe{ sequencer_ffi_query_events(sequencer_ffi, 
        1, FfiOption::from_value(next_id_after_deploy), std::ptr::null(), 
        std::ptr::null(), std::ptr::null()) };

    assert!(events_vec_res.error.is_ok(), "Event fetch must be successfull");

    let events_vec = unsafe { events_vec_res.value.read() };
    let event_1 = unsafe{events_vec.get(0)};

    log::info!("EVENT RECORD IS {event_1:#?}");

    log::info!("Successfully deployed and executed program");

    // SAFETY: sequencer_ffi created by FFI, it is valid.
    unsafe {
        sequencer_ffi_helpers::sequencer_ffi_stop_sequencer(sequencer_ffi_res.value);
    }

    Ok(())
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
    struct EmitterInstruction {
        events: Vec<ProgramEvent>,
        chain: Vec<(AccountId, InstructionData)>,
    }

fn emitted(n: u8) -> ProgramEvent {
        ProgramEvent {
            selector: [n; 8],
            data: vec![n; 4],
        }
    }
