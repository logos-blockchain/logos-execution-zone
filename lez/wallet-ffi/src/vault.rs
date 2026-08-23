//! Bridge vault claim functions.
//!
//! L1 Bedrock deposits are minted into a per-owner vault PDA account by the bridge program, not
//! directly into the owner's account (see `bridge.rs`). The owner must separately claim the
//! deposited funds from their vault into their own account with a signed transaction.

use std::{ffi::CString, ptr};

use lee::AccountId;
use wallet::program_facades::vault::Vault;

use crate::{
    block_on,
    error::{print_error, WalletFfiError},
    map_execution_error,
    types::{FfiBytes32, FfiTransferResult, WalletHandle},
    wallet::get_wallet,
};

/// Get the claimable balance held in an account's bridge vault.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `owner`: The account ID whose vault balance to query
/// - `out_balance`: Output for balance as little-endian [u8; 16]
///
/// # Returns
/// - `Success` on successful query
/// - Error code on failure
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `owner` must be a valid pointer to a `FfiBytes32` struct
/// - `out_balance` must be a valid pointer to a `[u8; 16]` array
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_get_vault_balance(
    handle: *mut WalletHandle,
    owner: *const FfiBytes32,
    out_balance: *mut [u8; 16],
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if owner.is_null() || out_balance.is_null() {
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

    let owner_id = AccountId::new(unsafe { (*owner).data });
    let vault_id =
        vault_core::compute_vault_account_id(programs::vault().deployed_account_id(), owner_id);

    let balance = match block_on(wallet.get_account_balance(vault_id)) {
        Ok(b) => b,
        Err(e) => {
            print_error(format!("Failed to get vault balance: {e}"));
            return WalletFfiError::NetworkError;
        }
    };

    unsafe {
        *out_balance = balance.to_le_bytes();
    }

    WalletFfiError::Success
}

/// Claim native tokens from a public owner's vault into their account.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `owner`: Owner account ID (must be owned by this wallet, public)
/// - `amount`: Amount to claim as little-endian [u8; 16]
/// - `out_result`: Output pointer for the claim result
///
/// # Returns
/// - `Success` if the claim was submitted successfully
/// - `InsufficientFunds` if the vault doesn't have enough balance
/// - `KeyNotFound` if the owner's signing key is not in this wallet
/// - Error code on other failures
///
/// # Memory
/// The result must be freed with `wallet_ffi_free_transfer_result()`.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `owner` must be a valid pointer to a `FfiBytes32` struct
/// - `amount` must be a valid pointer to a `[u8; 16]` array
/// - `out_result` must be a valid pointer to a `FfiTransferResult` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_vault_claim(
    handle: *mut WalletHandle,
    owner: *const FfiBytes32,
    amount: *const [u8; 16],
    out_result: *mut FfiTransferResult,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if owner.is_null() || amount.is_null() || out_result.is_null() {
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

    let owner_id = AccountId::new(unsafe { (*owner).data });
    let amount = u128::from_le_bytes(unsafe { *amount });

    match block_on(Vault(&wallet).send_claim(owner_id, amount)) {
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
            print_error(format!("Vault claim failed: {e:?}"));
            unsafe {
                (*out_result).tx_hash = ptr::null_mut();
                (*out_result).success = false;
            }
            map_execution_error(e)
        }
    }
}

/// Claim native tokens from a private owner's vault into their account.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `owner`: Owner account ID (must be owned by this wallet, private)
/// - `amount`: Amount to claim as little-endian [u8; 16]
/// - `out_result`: Output pointer for the claim result
///
/// # Returns
/// - `Success` if the claim was submitted successfully
/// - `InsufficientFunds` if the vault doesn't have enough balance
/// - `KeyNotFound` if the owner's signing key is not in this wallet
/// - Error code on other failures
///
/// # Memory
/// The result must be freed with `wallet_ffi_free_transfer_result()`.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `owner` must be a valid pointer to a `FfiBytes32` struct
/// - `amount` must be a valid pointer to a `[u8; 16]` array
/// - `out_result` must be a valid pointer to a `FfiTransferResult` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_vault_claim_private(
    handle: *mut WalletHandle,
    owner: *const FfiBytes32,
    amount: *const [u8; 16],
    out_result: *mut FfiTransferResult,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if owner.is_null() || amount.is_null() || out_result.is_null() {
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

    let owner_id = AccountId::new(unsafe { (*owner).data });
    let amount = u128::from_le_bytes(unsafe { *amount });

    match block_on(Vault(&wallet).send_claim_private_owner(owner_id, amount)) {
        Ok((tx_hash, _shared_key)) => {
            let tx_hash = CString::new(tx_hash.to_string())
                .map_or(ptr::null_mut(), std::ffi::CString::into_raw);

            unsafe {
                (*out_result).tx_hash = tx_hash;
                (*out_result).success = true;
            }
            WalletFfiError::Success
        }
        Err(e) => {
            print_error(format!("Vault claim failed: {e:?}"));
            unsafe {
                (*out_result).tx_hash = ptr::null_mut();
                (*out_result).success = false;
            }
            map_execution_error(e)
        }
    }
}
