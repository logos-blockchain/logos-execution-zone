//! Bridge program functions (deposit/withdraw between L1 Bedrock and L2).

use std::{ffi::CString, ptr};

use lee::AccountId;
use wallet::program_facades::bridge::Bridge;

use crate::{
    primitives::types::FfiBytes32,
    wallet::{
        block_on,
        error::{WalletFfiError, print_error},
        lifecycle::get_wallet,
        map_execution_error,
        types::{FfiTransferResult, WalletHandle},
    },
};

/// Withdraw native tokens from a public account to Bedrock (L1) through the bridge.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `from`: Source public account ID (must be owned by this wallet). Bridge withdrawals only
///   support public sender accounts.
/// - `amount`: Amount of native tokens to withdraw
/// - `bedrock_account_pk`: Recipient's Bedrock (L1) public key, 32 bytes
/// - `out_result`: Output pointer for the withdraw result
///
/// # Returns
/// - `Success` if the withdraw transaction was submitted successfully
/// - `InsufficientFunds` if the source account doesn't have enough balance
/// - `KeyNotFound` if the source account's signing key is not in this wallet
/// - Error code on other failures
///
/// # Memory
/// The result must be freed with `wallet_ffi_free_transfer_result()`.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `from` must be a valid pointer to a `FfiBytes32` struct
/// - `bedrock_account_pk` must be a valid pointer to a `FfiBytes32` struct
/// - `out_result` must be a valid pointer to a `FfiTransferResult` struct
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_ffi_bridge_withdraw(
    handle: *mut WalletHandle,
    from: *const FfiBytes32,
    amount: u64,
    bedrock_account_pk: *const FfiBytes32,
    out_result: *mut FfiTransferResult,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if from.is_null() || bedrock_account_pk.is_null() || out_result.is_null() {
        print_error("Null pointer argument");
        return WalletFfiError::NullPointer;
    }

    let wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    let from_id = AccountId::new(unsafe { (*from).data });
    let bedrock_account_pk = unsafe { (*bedrock_account_pk).data };

    let bridge = Bridge(&wallet);

    match block_on(bridge.send_withdraw(from_id, amount, bedrock_account_pk)) {
        Ok(tx_hash) => {
            let tx_hash = CString::new(tx_hash.to_string())
                .map_or(ptr::null_mut(), std::ffi::CString::into_raw);

            unsafe {
                (*out_result).tx_hash = tx_hash;
                (*out_result).success = true;
            }
            WalletFfiError::Success
        }
        Err(e) => {
            print_error(format!("Bridge withdraw failed: {e:?}"));
            unsafe {
                (*out_result).tx_hash = ptr::null_mut();
                (*out_result).success = false;
            }
            map_execution_error(e)
        }
    }
}
