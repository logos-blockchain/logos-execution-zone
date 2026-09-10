//! Sequecner FFI tests.

#![expect(
    clippy::tests_outside_test_module,
    reason = "Integration tests live at crate root and don't care about these lints"
)]

use std::time::Duration;

use anyhow::{Context as _, Result};
use integration_tests::get_account;
use log::info;
use logos_blockchain_zone_sdk::adapter::Node as _;
use sequencer_core::block_publisher::Ed25519Key;
use sequencer_service_rpc::RpcClient as _;
use test_fixtures::config::bedrock_channel_id;

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
