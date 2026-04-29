//! Block synchronization functions.

use sequencer_service_rpc::RpcClient as _;

use crate::{
    block_on,
    error::{print_error, WalletFfiError},
    types::WalletHandle,
    wallet::get_wallet,
};

/// Synchronize private accounts to a specific block.
///
/// This scans the blockchain from the last synced block to the specified block,
/// updating private account balances based on any relevant transactions.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `block_id`: Target block number to sync to
///
/// # Returns
/// - `Success` if synchronization completed
/// - `SyncError` if synchronization failed
/// - Error code on other failures
///
/// # Note
/// This operation can take a while for large block ranges. The wallet
/// internally uses a progress bar which may output to stdout.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_sync_to_block(
    handle: *mut WalletHandle,
    block_id: u64,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    let mut wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    match block_on(wallet.sync_to_block(block_id)) {
        Ok(()) => WalletFfiError::Success,
        Err(e) => {
            print_error(format!("Sync failed: {e}"));
            WalletFfiError::SyncError
        }
    }
}

/// Get the last synced block number.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `out_block_id`: Output pointer for the block number
///
/// # Returns
/// - `Success` on success
/// - Error code on failure
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `out_block_id` must be a valid pointer to a `u64`
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_get_last_synced_block(
    handle: *mut WalletHandle,
    out_block_id: *mut u64,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if out_block_id.is_null() {
        print_error("Null output pointer");
        return WalletFfiError::NullPointer;
    }

    let wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    unsafe {
        *out_block_id = wallet.last_synced_block;
    }

    WalletFfiError::Success
}

/// Get the current block height from the sequencer.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `out_block_height`: Output pointer for the current block height
///
/// # Returns
/// - `Success` on success
/// - `NetworkError` if the sequencer is unreachable
/// - Error code on other failures
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `out_block_height` must be a valid pointer to a `u64`
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_get_current_block_height(
    handle: *mut WalletHandle,
    out_block_height: *mut u64,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if out_block_height.is_null() {
        print_error("Null output pointer");
        return WalletFfiError::NullPointer;
    }

    let wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    match block_on(wallet.sequencer_client.get_last_block_id()) {
        Ok(last_block_id) => {
            unsafe {
                *out_block_height = last_block_id;
            }
            WalletFfiError::Success
        }
        Err(e) => {
            print_error(format!("Failed to get block height: {e:?}"));
            WalletFfiError::NetworkError
        }
    }
}
