//! Key retrieval functions.

use std::ptr;

use nssa::{AccountId, PublicKey};

use crate::{
    error::{print_error, WalletFfiError},
    types::{FfiBytes32, FfiPrivateAccountKeys, FfiPublicAccountKey, WalletHandle},
    wallet::get_wallet,
};

/// Get the public key for a public account.
///
/// This returns the public key derived from the account's signing key.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `account_id`: The account ID (32 bytes)
/// - `out_public_key`: Output pointer for the public key
///
/// # Returns
/// - `Success` on successful retrieval
/// - `KeyNotFound` if the account's key is not in this wallet
/// - Error code on other failures
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `account_id` must be a valid pointer to a `FfiBytes32` struct
/// - `out_public_key` must be a valid pointer to a `FfiPublicAccountKey` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_get_public_account_key(
    handle: *mut WalletHandle,
    account_id: *const FfiBytes32,
    out_public_key: *mut FfiPublicAccountKey,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if account_id.is_null() || out_public_key.is_null() {
        print_error("Null pointer argument");
        return WalletFfiError::NullPointer;
    }

    let wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {}", e));
            return WalletFfiError::InternalError;
        }
    };

    let account_id = AccountId::new(unsafe { (*account_id).data });

    let private_key = match wallet.get_account_public_signing_key(account_id) {
        Some(k) => k,
        None => {
            print_error("Public account key not found in wallet");
            return WalletFfiError::KeyNotFound;
        }
    };

    let public_key = PublicKey::new_from_private_key(private_key);

    unsafe {
        *out_public_key = public_key.into();
    }

    WalletFfiError::Success
}

/// Get keys for a private account.
///
/// Returns the nullifier public key (NPK) and viewing public key (VPK)
/// for the specified private account. These keys are safe to share publicly.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `account_id`: The account ID (32 bytes)
/// - `out_keys`: Output pointer for the key data
///
/// # Returns
/// - `Success` on successful retrieval
/// - `AccountNotFound` if the private account is not in this wallet
/// - Error code on other failures
///
/// # Memory
/// The keys structure must be freed with `wallet_ffi_free_private_account_keys()`.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `account_id` must be a valid pointer to a `FfiBytes32` struct
/// - `out_keys` must be a valid pointer to a `FfiPrivateAccountKeys` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_get_private_account_keys(
    handle: *mut WalletHandle,
    account_id: *const FfiBytes32,
    out_keys: *mut FfiPrivateAccountKeys,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if account_id.is_null() || out_keys.is_null() {
        print_error("Null pointer argument");
        return WalletFfiError::NullPointer;
    }

    let wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {}", e));
            return WalletFfiError::InternalError;
        }
    };

    let account_id = AccountId::new(unsafe { (*account_id).data });

    let (key_chain, _account) = match wallet.storage().user_data.get_private_account(account_id) {
        Some(k) => k,
        None => {
            print_error("Private account not found in wallet");
            return WalletFfiError::AccountNotFound;
        }
    };

    // NPK is a 32-byte array
    let npk_bytes = key_chain.nullifier_public_key.0;

    // VPK is a compressed secp256k1 point (33 bytes)
    let vpk_bytes = key_chain.viewing_public_key.to_bytes();
    let vpk_len = vpk_bytes.len();
    let vpk_vec = vpk_bytes.to_vec();
    let vpk_boxed = vpk_vec.into_boxed_slice();
    let vpk_ptr = Box::into_raw(vpk_boxed) as *const u8;

    unsafe {
        (*out_keys).nullifier_public_key.data = npk_bytes;
        (*out_keys).viewing_public_key = vpk_ptr;
        (*out_keys).viewing_public_key_len = vpk_len;
    }

    WalletFfiError::Success
}

/// Free private account keys returned by `wallet_ffi_get_private_account_keys`.
///
/// # Safety
/// The keys must be either null or valid keys returned by
/// `wallet_ffi_get_private_account_keys`.
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_free_private_account_keys(keys: *mut FfiPrivateAccountKeys) {
    if keys.is_null() {
        return;
    }

    unsafe {
        let keys = &*keys;
        if !keys.viewing_public_key.is_null() && keys.viewing_public_key_len > 0 {
            let slice = std::slice::from_raw_parts_mut(
                keys.viewing_public_key as *mut u8,
                keys.viewing_public_key_len,
            );
            drop(Box::from_raw(slice as *mut [u8]));
        }
    }
}

/// Convert an account ID to a Base58 string.
///
/// # Parameters
/// - `account_id`: The account ID (32 bytes)
///
/// # Returns
/// - Pointer to null-terminated Base58 string on success
/// - Null pointer on error
///
/// # Memory
/// The returned string must be freed with `wallet_ffi_free_string()`.
///
/// # Safety
/// - `account_id` must be a valid pointer to a `FfiBytes32` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_account_id_to_base58(
    account_id: *const FfiBytes32,
) -> *mut std::ffi::c_char {
    if account_id.is_null() {
        print_error("Null account_id pointer");
        return ptr::null_mut();
    }

    let account_id = AccountId::new(unsafe { (*account_id).data });
    let base58_str = account_id.to_string();

    match std::ffi::CString::new(base58_str) {
        Ok(s) => s.into_raw(),
        Err(e) => {
            print_error(format!("Failed to create C string: {}", e));
            ptr::null_mut()
        }
    }
}

/// Parse a Base58 string into an account ID.
///
/// # Parameters
/// - `base58_str`: Null-terminated Base58 string
/// - `out_account_id`: Output pointer for the account ID (32 bytes)
///
/// # Returns
/// - `Success` on successful parsing
/// - `InvalidAccountId` if the string is not valid Base58
/// - Error code on other failures
///
/// # Safety
/// - `base58_str` must be a valid pointer to a null-terminated C string
/// - `out_account_id` must be a valid pointer to a `FfiBytes32` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_account_id_from_base58(
    base58_str: *const std::ffi::c_char,
    out_account_id: *mut FfiBytes32,
) -> WalletFfiError {
    if base58_str.is_null() || out_account_id.is_null() {
        print_error("Null pointer argument");
        return WalletFfiError::NullPointer;
    }

    let c_str = unsafe { std::ffi::CStr::from_ptr(base58_str) };
    let str_slice = match c_str.to_str() {
        Ok(s) => s,
        Err(e) => {
            print_error(format!("Invalid UTF-8: {}", e));
            return WalletFfiError::InvalidUtf8;
        }
    };

    let account_id: AccountId = match str_slice.parse() {
        Ok(id) => id,
        Err(e) => {
            print_error(format!("Invalid Base58 account ID: {}", e));
            return WalletFfiError::InvalidAccountId;
        }
    };

    unsafe {
        (*out_account_id).data = *account_id.value();
    }

    WalletFfiError::Success
}
