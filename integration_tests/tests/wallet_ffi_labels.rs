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

use std::{
    ffi::{CStr, CString},
    str::FromStr as _,
    time::Duration,
};

use anyhow::Result;
use core_ffi::{
    error,
    primitives::types::FfiBytes32,
    wallet::{FfiAccountIdWithPrivacy, lifecycle::FfiCreateWalletOutput},
};
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS,
    ffi_helpers::{
        primitives as primitives_ffi_helpers, sequencer as sequencer_ffi_helpers, wallet::*,
    },
};

#[test]
fn test_wallet_ffi_single_label() -> Result<()> {
    let sequencer_ffi_helpers::JoiningSetup {
        ctx,
        node: _,
        ownership_id: _,
        sequencer_ffi: sequencer_ffi_res,
        sequencer_home,
    } = sequencer_ffi_helpers::joining_setup(false)?;

    log::info!("Joining sequencer home: {sequencer_home:?}");

    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path(), sequencer_ffi_res.value)?;

    let mut out_account_id_1 = FfiBytes32::from_bytes([0; 32]);
    unsafe {
        wallet_ffi_create_account_public(wallet_ffi_handle, &raw mut out_account_id_1).unwrap();
    }

    log::info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    let lab_1 = CString::from_str("LABEL1").unwrap().into_raw();

    let lab_1_availability = unsafe { wallet_ffi_check_label_available(wallet_ffi_handle, lab_1) };

    assert_eq!(lab_1_availability.error, error::FfiOperationError::Success);
    assert!(lab_1_availability.is_available);

    let acc_1_id_with_privacy = FfiAccountIdWithPrivacy {
        account_id: out_account_id_1,
        is_private: false,
    };

    let err = unsafe { wallet_ffi_add_label(wallet_ffi_handle, lab_1, acc_1_id_with_privacy) };

    assert_eq!(err, error::FfiOperationError::Success);

    let lab_1_availability = unsafe { wallet_ffi_check_label_available(wallet_ffi_handle, lab_1) };

    assert!(!lab_1_availability.is_available);

    let acc_resolved = unsafe { wallet_ffi_resolve_label(wallet_ffi_handle, lab_1) };

    assert_eq!(acc_resolved.account_id, acc_1_id_with_privacy);

    unsafe {
        primitives_ffi_helpers::primitives_ffi_free_cstring(lab_1);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    // SAFETY: sequencer_ffi created by FFI, it is valid.
    unsafe {
        sequencer_ffi_helpers::sequencer_ffi_stop_sequencer(sequencer_ffi_res.value);
    }

    Ok(())
}

#[test]
fn test_wallet_ffi_more_labels() -> Result<()> {
    let sequencer_ffi_helpers::JoiningSetup {
        ctx,
        node: _,
        ownership_id: _,
        sequencer_ffi: sequencer_ffi_res,
        sequencer_home,
    } = sequencer_ffi_helpers::joining_setup(false)?;

    log::info!("Joining sequencer home: {sequencer_home:?}");

    let home = tempfile::tempdir()?;
    let FfiCreateWalletOutput {
        wallet: wallet_ffi_handle,
        mnemonic: _,
    } = new_wallet_ffi_with_test_context_config(&ctx, home.path(), sequencer_ffi_res.value)?;

    let mut out_account_id_1 = FfiBytes32::from_bytes([0; 32]);
    unsafe {
        wallet_ffi_create_account_public(wallet_ffi_handle, &raw mut out_account_id_1).unwrap();
    }

    log::info!("Waiting for next block creation");
    std::thread::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS));

    let lab_1 = CString::from_str("LABEL1").unwrap().into_raw();
    let lab_2 = CString::from_str("LABEL2").unwrap().into_raw();
    let lab_3 = CString::from_str("LABEL3").unwrap().into_raw();

    let acc_1_id_with_privacy = FfiAccountIdWithPrivacy {
        account_id: out_account_id_1,
        is_private: false,
    };

    let err = unsafe { wallet_ffi_add_label(wallet_ffi_handle, lab_1, acc_1_id_with_privacy) };

    assert_eq!(err, error::FfiOperationError::Success);

    let err = unsafe { wallet_ffi_add_label(wallet_ffi_handle, lab_2, acc_1_id_with_privacy) };

    assert_eq!(err, error::FfiOperationError::Success);

    let err = unsafe { wallet_ffi_add_label(wallet_ffi_handle, lab_3, acc_1_id_with_privacy) };

    assert_eq!(err, error::FfiOperationError::Success);

    let mut label_list_for_out_acc =
        unsafe { wallet_ffi_get_all_labels_for_account(wallet_ffi_handle, acc_1_id_with_privacy) };

    assert_eq!(
        label_list_for_out_acc.error,
        error::FfiOperationError::Success
    );
    assert_eq!(label_list_for_out_acc.labels_size, 3);

    let lab_ref_1 = unsafe { &*label_list_for_out_acc.labels_data.add(0) };
    let lab_ref_c_str_1 = unsafe { CStr::from_ptr(*lab_ref_1) };

    assert_eq!(lab_ref_c_str_1.to_str().unwrap(), "LABEL1");

    let lab_ref_2 = unsafe { &*label_list_for_out_acc.labels_data.add(1) };
    let lab_ref_c_str_2 = unsafe { CStr::from_ptr(*lab_ref_2) };

    assert_eq!(lab_ref_c_str_2.to_str().unwrap(), "LABEL2");

    let lab_ref_3 = unsafe { &*label_list_for_out_acc.labels_data.add(2) };
    let lab_ref_c_str_3 = unsafe { CStr::from_ptr(*lab_ref_3) };

    assert_eq!(lab_ref_c_str_3.to_str().unwrap(), "LABEL3");

    let err = unsafe { wallet_ffi_free_label_list(&raw mut label_list_for_out_acc) };

    assert_eq!(err, error::FfiOperationError::Success);

    unsafe {
        primitives_ffi_helpers::primitives_ffi_free_cstring(lab_1);
        primitives_ffi_helpers::primitives_ffi_free_cstring(lab_2);
        primitives_ffi_helpers::primitives_ffi_free_cstring(lab_3);
        wallet_ffi_destroy(wallet_ffi_handle);
    }

    // SAFETY: sequencer_ffi created by FFI, it is valid.
    unsafe {
        sequencer_ffi_helpers::sequencer_ffi_stop_sequencer(sequencer_ffi_res.value);
    }

    Ok(())
}
