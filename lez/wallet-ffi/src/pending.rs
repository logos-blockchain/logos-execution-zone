//! Discovery and receipt of messages cast to this wallet's accounts.

use std::{ffi::CString, ptr};

use crate::{
    block_on,
    error::{print_error, WalletFfiError},
    map_execution_error,
    types::{FfiPendingMessage, FfiPendingMessageList, FfiTransferResult, WalletHandle},
    wallet::get_wallet,
};

/// List the messages cast to this wallet's accounts that it has not received yet.
///
/// A credit to a private account the sender cannot witness stays pending until its owner receives
/// it with `wallet_ffi_receive_pending_message`.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `out_list`: Output pointer for the pending message list
///
/// # Returns
/// - `Success` on successful listing
/// - `NetworkError` if the sequencer could not be queried
/// - Error code on other failures
///
/// # Memory
/// The returned list must be freed with `wallet_ffi_free_pending_message_list()`.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `out_list` must be a valid pointer to a `FfiPendingMessageList` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_list_pending_messages(
    handle: *mut WalletHandle,
    out_list: *mut FfiPendingMessageList,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if out_list.is_null() {
        print_error("Null output pointer for pending message list");
        return WalletFfiError::NullPointer;
    }

    let mut wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    let pending = match block_on(wallet.owned_pending_messages()) {
        Ok(pending) => pending,
        Err(e) => {
            print_error(format!("Failed to list pending messages: {e}"));
            return WalletFfiError::NetworkError;
        }
    };

    let entries: Box<[FfiPendingMessage]> = pending
        .into_iter()
        .map(|pending| {
            let message = pending.body.message.into_boxed_slice();
            let message_len = message.len();
            FfiPendingMessage {
                position: pending.position,
                receiving_account: pending.recipient.account_id().into(),
                from_account: pending.body.from.account_id.into(),
                from_program: pending.body.from.program_account_id.into(),
                to_program: pending.body.to.program_account_id.into(),
                message: Box::into_raw(message).cast::<u8>(),
                message_len,
            }
        })
        .collect();

    unsafe {
        (*out_list).count = entries.len();
        (*out_list).entries = if entries.is_empty() {
            ptr::null_mut()
        } else {
            Box::into_raw(entries).cast::<FfiPendingMessage>()
        };
    }

    WalletFfiError::Success
}

/// Free a pending message list returned by `wallet_ffi_list_pending_messages`.
///
/// # Safety
/// The list must be either null or a valid list returned by `wallet_ffi_list_pending_messages`.
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_free_pending_message_list(list: *mut FfiPendingMessageList) {
    if list.is_null() {
        return;
    }

    unsafe {
        let list = &*list;
        if !list.entries.is_null() && list.count > 0 {
            let entries = Box::from_raw(std::ptr::from_mut::<[FfiPendingMessage]>(
                std::slice::from_raw_parts_mut(list.entries, list.count),
            ));
            for entry in &entries {
                if !entry.message.is_null() {
                    drop(Box::from_raw(std::ptr::from_mut::<[u8]>(
                        std::slice::from_raw_parts_mut(entry.message.cast_mut(), entry.message_len),
                    )));
                }
            }
        }
    }
}

/// Receive a pending native or token credit cast to one of this wallet's accounts.
///
/// Proves and submits the receipt. Once it is included, syncing shows the credited account.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `position`: The pending message's position, as `wallet_ffi_list_pending_messages` lists it
/// - `out_result`: Output pointer for the receipt's transaction result
///
/// # Returns
/// - `Success` if the receipt was submitted successfully
/// - `MessageNotFound` if no pending message of this wallet is published at `position`
/// - Error code on other failures
///
/// # Memory
/// The result must be freed with `wallet_ffi_free_transfer_result()`.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `out_result` must be a valid pointer to a `FfiTransferResult` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_receive_pending_message(
    handle: *mut WalletHandle,
    position: u64,
    out_result: *mut FfiTransferResult,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if out_result.is_null() {
        print_error("Null output pointer for the receipt result");
        return WalletFfiError::NullPointer;
    }

    let mut wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    let pending = match block_on(wallet.find_pending_message(position)) {
        Ok(Some(pending)) => pending,
        Ok(None) => {
            print_error(format!("No pending message at position {position}"));
            return WalletFfiError::MessageNotFound;
        }
        Err(e) => {
            print_error(format!("Failed to find the pending message: {e}"));
            return WalletFfiError::NetworkError;
        }
    };
    match block_on(wallet.receive_pending_message(pending)) {
        Ok((tx_hash, _)) => {
            unsafe {
                (*out_result).tx_hash =
                    CString::new(tx_hash.to_string()).map_or(ptr::null_mut(), CString::into_raw);
                (*out_result).success = true;
            }
            WalletFfiError::Success
        }
        Err(e) => {
            print_error(format!("Receipt failed: {e:?}"));
            unsafe {
                (*out_result).tx_hash = ptr::null_mut();
                (*out_result).success = false;
            }
            map_execution_error(e)
        }
    }
}
