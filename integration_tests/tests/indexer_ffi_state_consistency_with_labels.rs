#![expect(
    clippy::shadow_unrelated,
    clippy::tests_outside_test_module,
    clippy::undocumented_unsafe_blocks,
    reason = "We don't care about these in tests"
)]

use std::time::Duration;

use anyhow::Result;
use indexer_ffi::Runtime;
use indexer_service_protocol::Account;
use integration_tests::{L2_TO_L1_TIMEOUT, TIME_TO_WAIT_FOR_BLOCK_SECONDS, public_mention};
use log::info;
use wallet::{
    account::Label,
    cli::{Command, programs::native_token_transfer::AuthTransferSubcommand},
};

#[path = "indexer_ffi_helpers/mod.rs"]
mod indexer_ffi_helpers;

#[test]
fn indexer_ffi_state_consistency_with_labels() -> Result<()> {
    let (mut ctx, indexer_ffi, _indexer_dir) = indexer_ffi_helpers::setup()?;

    // Assign labels to both accounts
    let from_label = Label::new("idx-sender-label");
    let to_label = Label::new("idx-receiver-label");

    let label_cmd = Command::Account(wallet::cli::account::AccountSubcommand::Label {
        account_id: public_mention(ctx.ctx().existing_public_accounts()[0]),
        label: from_label.clone(),
    });
    ctx.block_on_mut(|ctx| wallet::cli::execute_subcommand(ctx.wallet_mut(), label_cmd))?;

    let label_cmd = Command::Account(wallet::cli::account::AccountSubcommand::Label {
        account_id: public_mention(ctx.ctx().existing_public_accounts()[1]),
        label: to_label.clone(),
    });
    ctx.block_on_mut(|ctx| wallet::cli::execute_subcommand(ctx.wallet_mut(), label_cmd))?;

    // Send using labels instead of account IDs
    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: from_label.into(),
        to: Some(to_label.into()),
        to_npk: None,
        to_vpk: None,
        to_keys: None,
        amount: 100,
        to_identifier: Some(0),
    });

    ctx.block_on_mut(|ctx| wallet::cli::execute_subcommand(ctx.wallet_mut(), command))?;

    info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

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

    assert_eq!(acc_1_balance, 9900);
    assert_eq!(acc_2_balance, 20100);

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

    let acc1_seq_state = ctx.block_on(|ctx| {
        sequencer_service_rpc::RpcClient::get_account(
            ctx.sequencer_client(),
            ctx.existing_public_accounts()[0],
        )
    })?;

    assert_eq!(acc1_ind_state, acc1_seq_state.into());

    info!("Indexer state is consistent after label-based transfer");

    Ok(())
}
