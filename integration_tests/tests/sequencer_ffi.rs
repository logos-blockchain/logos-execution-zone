//! Sequecner FFI tests.

#![expect(
    clippy::tests_outside_test_module,
    reason = "Integration tests live at crate root and don't care about these lints"
)]
#![expect(
    clippy::cast_possible_truncation,
    clippy::as_conversions,
    reason = "We don't care about it in tests"
)]

use std::time::Duration;

use anyhow::{Context as _, Result};
use integration_tests::get_account;
use log::info;
use logos_blockchain_key_management_system_service::keys::Ed25519Key;
use logos_blockchain_zone_sdk::adapter::Node as _;
use sequencer_ffi::api::types::{
    FfiOption,
    transaction::{FfiTransaction, FfiTransactionKind},
};
use sequencer_service_rpc::RpcClient as _;
use test_fixtures::config::bedrock_channel_id;

#[path = "sequencer_ffi_helpers/mod.rs"]
mod sequencer_ffi_helpers;

#[test]
fn sequencer_ffi_join_setup_and_simple_queries_test() -> Result<()> {
    let sequencer_ffi_helpers::JoiningSetup {
        ctx,
        node,
        ownership_id,
        sequencer_ffi: sequencer_ffi_res,
        sequencer_home: _sequencer_home,
    } = sequencer_ffi_helpers::joining_setup()?;

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
    let sequencer_ffi_helpers::JoiningSetup {
        ctx,
        node,
        ownership_id: owner_id,
        sequencer_ffi: sequencer_ffi_res,
        sequencer_home: _sequencer_home,
    } = sequencer_ffi_helpers::joining_setup()?;

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

    // Every block the joining sequencer produces distributes fees to its payout
    // account, which is this ownership account, so the number of transactions
    // indexed against it grows for as long as the node runs. `common` bounds it:
    // there is at most one such transaction per block.

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

    // Which selector names the account is what the transaction is: the Stake
    // that opened the record, or one of the block rewards that followed it.
    let mut stake_txs = 0_usize;
    let mut reward_txs = 0_usize;
    for i in 0..owner_id_transactions.len {
        let owner_id_tx =
        // SAFETY: `i` is below the vector's length.
        unsafe { owner_id_transactions.get(i) };

        match owner_id_selector_position(owner_id_tx, *owner_id.value())? {
            // Stake: funding, ownership, funds, config.
            Some(1) => stake_txs += 1,
            // Fee distribution: fee state, escrow, inbox, producer payout.
            Some(3) => reward_txs += 1,
            position => anyhow::bail!(
                "Transaction {i} names {owner_id} at selector {position:?}, which is neither the \
                 Stake transaction nor a block reward"
            ),
        }
    }

    // One Stake opened the record, and re-reading the channel must not index it
    // a second time.
    assert_eq!(
        stake_txs, 1,
        "expected exactly one Stake transaction against {owner_id}, got {stake_txs}"
    );
    // The test waited for a block of the joining sequencer's own, so its payout
    // account has been credited at least once.
    assert!(
        reward_txs >= 1,
        "expected at least one block reward against {owner_id}, got none"
    );
    info!("Joining sequencer's ownership account indexes 1 Stake and {reward_txs} block reward(s)");

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

/// Which shard selector of `tx` names `account`, if any.
fn owner_id_selector_position(tx: &FfiTransaction, account: [u8; 32]) -> Result<Option<usize>> {
    let FfiTransactionKind::Public = tx.kind else {
        return Err(anyhow::anyhow!("All owner_id transactions must be public"));
    };

    let shard_selectors =
        // SAFETY: the kind says the public body is the live union member.
        unsafe { tx.body.public_body.read().message.shard_selectors };

    Ok((0..shard_selectors.len).find(|&i| {
        // SAFETY: `i` is below the vector's length.
        unsafe { shard_selectors.get(i).account_id.data == account }
    }))
}
