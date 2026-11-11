#![expect(
    clippy::redundant_test_prefix,
    reason = "Otherwise names interfere with ffi bindings"
)]
#![expect(
    clippy::tests_outside_test_module,
    clippy::undocumented_unsafe_blocks,
    clippy::multiple_unsafe_ops_per_block,
    clippy::shadow_unrelated,
    clippy::as_conversions,
    reason = "We don't care about these in tests"
)]

use std::{ffi::CStr, time::Duration};

use anyhow::Result;
use common::HashType;
use core_ffi::{
    primitives::types::{FfiBytes32, account::FfiAccount},
    wallet::{
        FfiAccountIdentity, FfiAccountMention,
        generic_transaction::{FfiDependency, FfiProgramCatalog, FfiTransactionResult},
        lifecycle::FfiCreateWalletOutput,
    },
};
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS,
    config::{INITIAL_PRIVATE_BALANCES_FOR_WALLET, min_private_fee},
    ffi_helpers::{sequencer as sequencer_ffi_helpers, wallet::*},
};
use lee::{Account, program::Program};
use lee_core::native_token::NATIVE_TOKEN_PROGRAM_ID;
use wallet::DEFAULT_MAX_FEE;

#[test]
fn test_wallet_ffi_transfer_generic_public() -> Result<()> {
    let sequencer_ffi_helpers::JoiningSetup {
        ctx,
        node: _,
        ownership_id: _,
        sequencer_ffi: sequencer_ffi_res,
        sequencer_home,
    } = sequencer_ffi_helpers::joining_setup(true)?;

    log::info!("Joining sequencer home: {sequencer_home:?}");

    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path(), sequencer_ffi_res.value)?;
    let from: FfiBytes32 = ctx.ctx().existing_public_accounts()[0].into();
    let to_id = ctx.ctx().existing_public_accounts()[1];
    let to: FfiBytes32 = to_id.into();
    let amount = 100_u128;

    let from_before = ffi_balance(wallet_ffi_handle, &from, true);
    let to_before = ffi_balance(wallet_ffi_handle, &to, true);

    let mut transaction_result = FfiTransactionResult::default();

    let mut from_account_identity = FfiAccountIdentity::default();
    let mut to_account_identity = FfiAccountIdentity::default();

    unsafe {
        wallet_ffi_resolve_public_account(from, true, &raw mut from_account_identity).unwrap();
    }

    unsafe {
        wallet_ffi_resolve_public_account(to, true, &raw mut to_account_identity).unwrap();
    }

    let ffi_accs = vec![
        mention(
            from_account_identity,
            lee_core::native_token::NATIVE_TOKEN_PROGRAM_ID,
        ),
        mention(
            to_account_identity,
            lee_core::native_token::NATIVE_TOKEN_PROGRAM_ID,
        ),
    ];
    let account_mentions_size = ffi_accs.len();
    let account_mentions = Box::into_raw(ffi_accs.into_boxed_slice()) as *const FfiAccountMention;

    // The sender's native actor, mention 0, is the root.
    let message =
        Program::serialize_message(lee_core::native_token::Message::Transfer { to: to_id, amount })
            .unwrap();
    let message_size = message.len();
    let message_ptr = Box::into_raw(message.into_boxed_slice()) as *const u8;

    unsafe {
        wallet_ffi_send_generic_public_transaction(
            wallet_ffi_handle,
            account_mentions,
            account_mentions_size,
            0,
            message_ptr,
            message_size,
            std::ptr::null(),
            &raw mut transaction_result,
        )
        .unwrap();
    }

    log::info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    // The sleep is barely longer than one block period, so on a loaded machine the
    // transfer may still be unconfirmed. Balances only move once the transaction is
    // in a block, so wait for it rather than reading a pre-transfer state.
    let tx_hash: HashType = unsafe { CStr::from_ptr(transaction_result.tx_hash) }
        .to_str()?
        .parse()?;
    let mut is_included = false;
    unsafe {
        wallet_ffi_poll_transaction_status(
            wallet_ffi_handle,
            FfiBytes32::from_bytes(tx_hash.0),
            &raw mut is_included,
        )
        .unwrap();
    }
    assert!(is_included, "the transfer transaction must land");

    let from_balance = ffi_balance(wallet_ffi_handle, &from, true);

    let to_balance = ffi_balance(wallet_ffi_handle, &to, true);

    // Charged public transfer: the recipient gains exactly the amount; the
    // sender pays the amount plus a fee bounded by the protocol ceiling.
    assert_eq!(
        to_balance,
        to_before + 100,
        "recipient gains exactly the transferred amount"
    );
    let fee = from_before
        .checked_sub(100)
        .and_then(|rest| rest.checked_sub(from_balance))
        .expect("sender must be debited at least the transferred amount");
    assert!(
        fee > 0 && fee <= DEFAULT_MAX_FEE,
        "a charged transfer pays a positive fee within the ceiling, got {fee}"
    );

    unsafe {
        let mentions = account_mentions.cast_mut();
        wallet_ffi_free_account_identity(&raw mut (*mentions).identity);
        wallet_ffi_free_account_identity(&raw mut (*mentions.add(1)).identity);

        let message = std::slice::from_raw_parts_mut(message_ptr.cast_mut(), message_size);
        drop(Box::from_raw(std::ptr::from_mut(message)));

        wallet_ffi_free_transaction_result(&raw mut transaction_result);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    // SAFETY: sequencer_ffi created by FFI, it is valid.
    unsafe {
        sequencer_ffi_helpers::sequencer_ffi_stop_sequencer(sequencer_ffi_res.value);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_transfer_generic_private() -> Result<()> {
    let sequencer_ffi_helpers::JoiningSetup {
        ctx,
        node: _,
        ownership_id: _,
        sequencer_ffi: sequencer_ffi_res,
        sequencer_home,
    } = sequencer_ffi_helpers::joining_setup(true)?;

    log::info!("Joining sequencer home: {sequencer_home:?}");

    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path(), sequencer_ffi_res.value)?;
    let from = ctx.ctx().existing_private_accounts()[0].into();
    let to_id = ctx.ctx().existing_private_accounts()[1];
    let to: FfiBytes32 = to_id.into();
    let native_token_program = NATIVE_TOKEN_PROGRAM_ID;
    let native_transfer_amount = 100_u128;

    let mut transaction_result = FfiTransactionResult::default();

    let mut from_account_identity = FfiAccountIdentity::default();
    let mut to_account_identity = FfiAccountIdentity::default();

    unsafe {
        wallet_ffi_resolve_private_account(wallet_ffi_handle, from, &raw mut from_account_identity)
            .unwrap();
    }

    unsafe {
        wallet_ffi_resolve_private_account(wallet_ffi_handle, to, &raw mut to_account_identity)
            .unwrap();
    }

    let ffi_accs = vec![
        mention(from_account_identity, native_token_program),
        mention(to_account_identity, native_token_program),
    ];
    let account_mentions_size = ffi_accs.len();
    let account_mentions = Box::into_raw(ffi_accs.into_boxed_slice()) as *const FfiAccountMention;

    // The sender, mention 0, is the root; its transfer credits the recipient, mention 1.
    let message = Program::serialize_message(lee_core::native_token::Message::Transfer {
        to: to_id,
        amount: native_transfer_amount,
    })
    .unwrap();
    let message_size = message.len();
    let message_ptr = Box::into_raw(message.into_boxed_slice()) as *const u8;

    let ffi_programs: Vec<FfiDependency> = vec![];
    let programs_size = ffi_programs.len();
    let programs_ptr = Box::into_raw(ffi_programs.into_boxed_slice()) as *const FfiDependency;
    let programs = FfiProgramCatalog {
        programs: programs_ptr,
        programs_size,
    };

    unsafe {
        wallet_ffi_send_generic_private_transaction(
            wallet_ffi_handle,
            account_mentions,
            account_mentions_size,
            0,
            message_ptr,
            message_size,
            &raw const programs,
            &raw mut transaction_result,
        )
        .unwrap();
    }

    assert_eq!(transaction_result.secrets_size, 2);

    let tx_hash: HashType = unsafe { CStr::from_ptr(transaction_result.tx_hash) }
        .to_str()?
        .parse()?;
    let mut is_included = false;
    unsafe {
        wallet_ffi_poll_transaction_status(
            wallet_ffi_handle,
            FfiBytes32::from_bytes(tx_hash.0),
            &raw mut is_included,
        )
        .unwrap();
    }
    assert!(is_included, "the transfer must land");

    // Sync private account local storage with onchain encrypted state
    unsafe {
        let mut current_height = 0;
        wallet_ffi_get_current_block_height(wallet_ffi_handle, &raw mut current_height).unwrap();
        wallet_ffi_sync_to_block(wallet_ffi_handle, current_height).unwrap();
    };

    let mut out_from = FfiAccount::default();
    let mut out_to = FfiAccount::default();
    let (from_account, to_account): (Account, Account) = unsafe {
        wallet_ffi_get_account_private(wallet_ffi_handle, &raw const from, &raw mut out_from)
            .unwrap();
        wallet_ffi_get_account_private(wallet_ffi_handle, &raw const to, &raw mut out_to).unwrap();
        (
            (&out_from).try_into().unwrap(),
            (&out_to).try_into().unwrap(),
        )
    };

    let new_from_balance = from_account.data.native_balance().expect("Must fit");
    let new_to_balance = to_account.data.native_balance().expect("Must fit");

    // The private sender pays the amount and the in-proof fee.
    assert_eq!(
        new_from_balance,
        INITIAL_PRIVATE_BALANCES_FOR_WALLET[0] - 100 - min_private_fee()
    );
    assert_eq!(new_to_balance, INITIAL_PRIVATE_BALANCES_FOR_WALLET[1] + 100);

    unsafe {
        let mentions = account_mentions.cast_mut();
        wallet_ffi_free_account_identity(&raw mut (*mentions).identity);
        wallet_ffi_free_account_identity(&raw mut (*mentions.add(1)).identity);

        let message = std::slice::from_raw_parts_mut(message_ptr.cast_mut(), message_size);
        drop(Box::from_raw(std::ptr::from_mut(message)));

        wallet_ffi_free_transaction_result(&raw mut transaction_result);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    // SAFETY: sequencer_ffi created by FFI, it is valid.
    unsafe {
        sequencer_ffi_helpers::sequencer_ffi_stop_sequencer(sequencer_ffi_res.value);
    }

    Ok(())
}
