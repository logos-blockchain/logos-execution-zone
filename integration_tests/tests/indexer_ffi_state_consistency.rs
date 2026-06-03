#![expect(
    clippy::shadow_unrelated,
    clippy::tests_outside_test_module,
    clippy::undocumented_unsafe_blocks,
    reason = "We don't care about these in tests"
)]

use std::time::Duration;

use anyhow::{Context as _, Result};
use indexer_ffi::Runtime;
use indexer_service_protocol::Account;
use integration_tests::{
    L2_TO_L1_TIMEOUT, TIME_TO_WAIT_FOR_BLOCK_SECONDS, private_mention, public_mention,
    verify_commitment_is_in_state,
};
use lee::AccountId;
use log::info;
use wallet::cli::{Command, programs::native_token_transfer::AuthTransferSubcommand};

#[path = "indexer_ffi_helpers/mod.rs"]
mod indexer_ffi_helpers;

#[test]
fn indexer_ffi_state_consistency() -> Result<()> {
    let (mut ctx, indexer_ffi, _indexer_dir) = indexer_ffi_helpers::setup()?;

    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: public_mention(ctx.ctx().existing_public_accounts()[0]),
        to: Some(public_mention(ctx.ctx().existing_public_accounts()[1])),
        to_npk: None,
        to_vpk: None,
        to_keys: None,
        amount: 100,
        to_identifier: Some(0),
    });

    ctx.block_on_mut(|ctx| wallet::cli::execute_subcommand(ctx.wallet_mut(), command))?;

    info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    info!("Checking correct balance move");
    let acc_1_balance = ctx.block_on(|ctx| {
        sequencer_service_rpc::RpcClient::get_account_balance(
            ctx.sequencer_client(),
            ctx.existing_public_accounts()[0],
        )
    })?;
    let acc_2_balance = ctx.block_on(|ctx| {
        sequencer_service_rpc::RpcClient::get_account_balance(
            ctx.sequencer_client(),
            ctx.existing_public_accounts()[1],
        )
    })?;

    info!("Balance of sender: {acc_1_balance:#?}");
    info!("Balance of receiver: {acc_2_balance:#?}");

    assert_eq!(acc_1_balance, 9900);
    assert_eq!(acc_2_balance, 20100);

    let from: AccountId = ctx.ctx().existing_private_accounts()[0];
    let to: AccountId = ctx.ctx().existing_private_accounts()[1];

    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: private_mention(from),
        to: Some(private_mention(to)),
        to_npk: None,
        to_vpk: None,
        to_keys: None,
        amount: 100,
        to_identifier: Some(0),
    });

    ctx.block_on_mut(|ctx| wallet::cli::execute_subcommand(ctx.wallet_mut(), command))?;

    info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    let new_commitment1 = ctx
        .ctx()
        .wallet()
        .get_private_account_commitment(from)
        .context("Failed to get private account commitment for sender")?;
    let commitment_check1 =
        ctx.block_on(|ctx| verify_commitment_is_in_state(new_commitment1, ctx.sequencer_client()));
    assert!(commitment_check1);

    let new_commitment2 = ctx
        .ctx()
        .wallet()
        .get_private_account_commitment(to)
        .context("Failed to get private account commitment for receiver")?;
    let commitment_check2 =
        ctx.block_on(|ctx| verify_commitment_is_in_state(new_commitment2, ctx.sequencer_client()));
    assert!(commitment_check2);

    info!("Successfully transferred privately to owned account");

    // WAIT
    info!("Waiting for indexer to parse blocks");
    std::thread::sleep(L2_TO_L1_TIMEOUT);

    // Safety: ctx runtime is valid for the lifetime of the returned Runtime
    let runtime = unsafe { Runtime::from_borrowed(ctx.runtime()) };
    let acc1_ind_state_ffi = unsafe {
        indexer_ffi_helpers::query_account(
            &raw const runtime,
            &raw const indexer_ffi,
            (&ctx.ctx().existing_public_accounts()[0]).into(),
        )
    };

    assert!(acc1_ind_state_ffi.error.is_ok());

    let acc1_ind_state_pre = unsafe { &*acc1_ind_state_ffi.value };
    let acc1_ind_state: Account = acc1_ind_state_pre.into();

    let acc2_ind_state_ffi = unsafe {
        indexer_ffi_helpers::query_account(
            &raw const runtime,
            &raw const indexer_ffi,
            (&ctx.ctx().existing_public_accounts()[1]).into(),
        )
    };

    assert!(acc2_ind_state_ffi.error.is_ok());

    let acc2_ind_state_pre = unsafe { &*acc2_ind_state_ffi.value };
    let acc2_ind_state: Account = acc2_ind_state_pre.into();

    info!("Checking correct state transition");
    let acc1_seq_state = ctx.block_on(|ctx| {
        sequencer_service_rpc::RpcClient::get_account(
            ctx.sequencer_client(),
            ctx.existing_public_accounts()[0],
        )
    })?;
    let acc2_seq_state = ctx.block_on(|ctx| {
        sequencer_service_rpc::RpcClient::get_account(
            ctx.sequencer_client(),
            ctx.existing_public_accounts()[1],
        )
    })?;

    assert_eq!(acc1_ind_state, acc1_seq_state.into());
    assert_eq!(acc2_ind_state, acc2_seq_state.into());

    // ToDo: Check private state transition

    Ok(())
}
