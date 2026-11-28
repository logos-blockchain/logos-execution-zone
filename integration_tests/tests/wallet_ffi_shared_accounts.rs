#![expect(
    clippy::redundant_test_prefix,
    reason = "Otherwise names interfere with ffi bindings"
)]
#![expect(
    clippy::tests_outside_test_module,
    clippy::undocumented_unsafe_blocks,
    clippy::multiple_unsafe_ops_per_block,
    clippy::shadow_unrelated,
    reason = "We don't care about these in tests"
)]

use std::{ffi::CString, str::FromStr as _, time::Duration};

use anyhow::Result;
use core_ffi::{
    error,
    primitives::types::{FfiBytes32, FfiPrivateAccountKeys, account::FfiAccount},
    wallet::{FfiTransferResult, lifecycle::FfiCreateWalletOutput},
};
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS,
    ffi_helpers::{
        primitives as primitives_ffi_helpers, sequencer as sequencer_ffi_helpers, wallet::*,
    },
};

#[test]
fn test_wallet_ffi_create_shared_account_and_sealing_key() -> Result<()> {
    let sequencer_ffi_helpers::JoiningSetup {
        ctx,
        node: _,
        ownership_id: _,
        sequencer_ffi: sequencer_ffi_res,
        sequencer_home,
    } = sequencer_ffi_helpers::joining_setup(false)?;

    tracing::info!(?sequencer_home, "Joining sequencer home");

    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path(), sequencer_ffi_res.value)?;

    let mut out_sealing_public_key = CString::from_str("KEYPLACEHOLDER").unwrap().into_raw();

    let err = unsafe {
        wallet_ffi_create_sealing_key(wallet_ffi_handle, &raw mut out_sealing_public_key)
    };

    assert_eq!(err, error::FfiOperationError::Success);

    let sealing_public_key_hex =
        unsafe { CString::from_raw(out_sealing_public_key) }.into_string()?;
    let sealing_public_key = hex::decode(sealing_public_key_hex)?;
    assert_eq!(sealing_public_key.len(), 1184);

    let lab_1_c = CString::from_str("LABEL1S").unwrap().into_raw();

    let err = unsafe { wallet_ffi_create_new_group(wallet_ffi_handle, lab_1_c.cast_const()) };

    assert_eq!(err, error::FfiOperationError::Success);

    tracing::info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    let mut out_account_id = FfiBytes32 { data: [0; 32] };
    let mut out_keys = FfiPrivateAccountKeys::default();

    let err = unsafe {
        wallet_ffi_create_private_shared_account(
            wallet_ffi_handle,
            lab_1_c.cast_const(),
            FfiBytes32 { data: [42; 32] },
            &raw mut out_account_id,
            &raw mut out_keys,
        )
    };

    assert_eq!(err, error::FfiOperationError::Success);
    // Can be cast into valid key
    assert!(out_keys.vpk().is_ok());

    let mut out_account = FfiAccount::default();

    let err = unsafe {
        wallet_ffi_get_account_private(
            wallet_ffi_handle,
            &raw const out_account_id,
            &raw mut out_account,
        )
    };

    assert_eq!(err, error::FfiOperationError::Success);

    unsafe {
        primitives_ffi_helpers::primitives_ffi_free_cstring(lab_1_c);
        primitives_ffi_helpers::primitives_ffi_free_private_account_keys(&raw mut out_keys);
        wallet_ffi_free_account_data(&raw mut out_account);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    // SAFETY: sequencer_ffi created by FFI, it is valid.
    unsafe {
        sequencer_ffi_helpers::sequencer_ffi_stop_sequencer(sequencer_ffi_res.value);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_invite_and_join() -> Result<()> {
    let sequencer_ffi_helpers::JoiningSetup {
        ctx,
        node: _,
        ownership_id: _,
        sequencer_ffi: sequencer_ffi_res,
        sequencer_home,
    } = sequencer_ffi_helpers::joining_setup(false)?;

    tracing::info!(?sequencer_home, "Joining sequencer home");

    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path(), sequencer_ffi_res.value)?;

    let mut out_sealing_public_key = CString::from_str("KEYPLACEHOLDER").unwrap().into_raw();

    let err = unsafe {
        wallet_ffi_create_sealing_key(wallet_ffi_handle, &raw mut out_sealing_public_key)
    };

    assert_eq!(err, error::FfiOperationError::Success);

    let lab_1_c = CString::from_str("LABEL1A").unwrap().into_raw();

    let err = unsafe { wallet_ffi_create_new_group(wallet_ffi_handle, lab_1_c.cast_const()) };

    assert_eq!(err, error::FfiOperationError::Success);
    tracing::info!("Created first label");

    tracing::info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    let lab_2_c = CString::from_str("LABEL1B").unwrap().into_raw();

    let mut out_sealed_message = CString::from_str("MESSAGEPLACEHOLDER").unwrap().into_raw();

    let err = unsafe {
        wallet_ffi_invite_shared_account(
            wallet_ffi_handle,
            out_sealing_public_key.cast_const(),
            lab_1_c.cast_const(),
            &raw mut out_sealed_message,
        )
    };

    assert_eq!(err, error::FfiOperationError::Success);

    let err = unsafe {
        wallet_ffi_join_shared_account(
            wallet_ffi_handle,
            out_sealed_message.cast_const(),
            lab_2_c.cast_const(),
        )
    };

    assert_eq!(err, error::FfiOperationError::Success);

    let derivation_id = FfiBytes32 { data: [42; 32] };

    let mut out_account_id_1 = FfiBytes32 { data: [0; 32] };
    let mut out_keys_1 = FfiPrivateAccountKeys::default();

    let err = unsafe {
        wallet_ffi_create_private_shared_account(
            wallet_ffi_handle,
            lab_1_c.cast_const(),
            derivation_id,
            &raw mut out_account_id_1,
            &raw mut out_keys_1,
        )
    };

    assert_eq!(err, error::FfiOperationError::Success);

    tracing::info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    let mut out_account_id_2 = FfiBytes32 { data: [0; 32] };
    let mut out_keys_2 = FfiPrivateAccountKeys::default();

    let err = unsafe {
        wallet_ffi_create_private_shared_account(
            wallet_ffi_handle,
            lab_1_c.cast_const(),
            derivation_id,
            &raw mut out_account_id_2,
            &raw mut out_keys_2,
        )
    };

    assert_eq!(err, error::FfiOperationError::Success);

    tracing::info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    assert_eq!(out_keys_1.npk(), out_keys_2.npk());

    unsafe {
        primitives_ffi_helpers::primitives_ffi_free_cstring(lab_1_c);
        primitives_ffi_helpers::primitives_ffi_free_cstring(lab_2_c);
        primitives_ffi_helpers::primitives_ffi_free_cstring(out_sealing_public_key);
        primitives_ffi_helpers::primitives_ffi_free_cstring(out_sealed_message);
        primitives_ffi_helpers::primitives_ffi_free_private_account_keys(&raw mut out_keys_1);
        primitives_ffi_helpers::primitives_ffi_free_private_account_keys(&raw mut out_keys_2);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    // SAFETY: sequencer_ffi created by FFI, it is valid.
    unsafe {
        sequencer_ffi_helpers::sequencer_ffi_stop_sequencer(sequencer_ffi_res.value);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_fund_shared_account_from_public() -> Result<()> {
    let sequencer_ffi_helpers::JoiningSetup {
        ctx,
        node: _,
        ownership_id: _,
        sequencer_ffi: sequencer_ffi_res,
        sequencer_home,
    } = sequencer_ffi_helpers::joining_setup(true)?;

    tracing::info!(?sequencer_home, "Joining sequencer home");

    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path(), sequencer_ffi_res.value)?;

    let mut out_sealing_public_key = CString::from_str("KEYPLACEHOLDER").unwrap().into_raw();

    let err = unsafe {
        wallet_ffi_create_sealing_key(wallet_ffi_handle, &raw mut out_sealing_public_key)
    };

    assert_eq!(err, error::FfiOperationError::Success);

    let lab_1_c = CString::from_str("LABEL1A").unwrap().into_raw();

    let err = unsafe { wallet_ffi_create_new_group(wallet_ffi_handle, lab_1_c.cast_const()) };

    assert_eq!(err, error::FfiOperationError::Success);
    tracing::info!("Created first label");

    tracing::info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    let derivation_id = FfiBytes32 { data: [42; 32] };

    let mut out_account_id_1 = FfiBytes32 { data: [0; 32] };
    let mut out_keys_1 = FfiPrivateAccountKeys::default();

    let err = unsafe {
        wallet_ffi_create_private_shared_account(
            wallet_ffi_handle,
            lab_1_c.cast_const(),
            derivation_id,
            &raw mut out_account_id_1,
            &raw mut out_keys_1,
        )
    };

    // Sync private account local storage with onchain encrypted state
    unsafe {
        let mut current_height = 0;
        wallet_ffi_get_current_block_height(wallet_ffi_handle, &raw mut current_height).unwrap();
        wallet_ffi_sync_to_block(wallet_ffi_handle, current_height).unwrap();
    };

    assert_eq!(err, error::FfiOperationError::Success);

    tracing::info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    let from: FfiBytes32 = ctx.ctx().existing_public_accounts()[0].into();
    let amount: [u8; 16] = 100_u128.to_le_bytes();
    let from_before = ffi_balance(wallet_ffi_handle, &from, true);
    let mut transfer_result = FfiTransferResult::default();
    unsafe {
        wallet_ffi_transfer_shielded(
            wallet_ffi_handle,
            &raw const from,
            &raw const out_keys_1,
            &raw const amount,
            std::ptr::null(),
            &raw mut transfer_result,
        )
        .unwrap();
    }

    tracing::info!("================================== Waiting for inclusion");
    wait_for_inclusion(wallet_ffi_handle, &transfer_result);

    // Sync private account local storage with onchain encrypted state
    unsafe {
        let mut current_height = 0;
        wallet_ffi_get_current_block_height(wallet_ffi_handle, &raw mut current_height).unwrap();
        wallet_ffi_sync_to_block(wallet_ffi_handle, current_height).unwrap();
    };
    // Sent by keys, the credit is pending until the owner receives it.
    receive_pending(wallet_ffi_handle);

    let from_balance = ffi_balance(wallet_ffi_handle, &from, true);

    let to_balance = unsafe {
        let mut out_balance: [u8; 16] = [0; 16];
        let _result = wallet_ffi_get_balance(
            wallet_ffi_handle,
            &raw const out_account_id_1,
            false,
            &raw mut out_balance,
        );
        u128::from_le_bytes(out_balance)
    };

    // The fresh private recipient holds nothing, so a funded private account of the wallet pays
    // the in-proof fee and the public sender pays exactly the amount.
    assert_eq!(from_balance, from_before.saturating_sub(100));
    assert_eq!(to_balance, 100);

    unsafe {
        primitives_ffi_helpers::primitives_ffi_free_cstring(lab_1_c);
        primitives_ffi_helpers::primitives_ffi_free_cstring(out_sealing_public_key);
        primitives_ffi_helpers::primitives_ffi_free_private_account_keys(&raw mut out_keys_1);
        wallet_ffi_free_transfer_result(&raw mut transfer_result);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    // SAFETY: sequencer_ffi created by FFI, it is valid.
    unsafe {
        sequencer_ffi_helpers::sequencer_ffi_stop_sequencer(sequencer_ffi_res.value);
    }

    Ok(())
}
