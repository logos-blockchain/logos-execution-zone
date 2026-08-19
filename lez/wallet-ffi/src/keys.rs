//! Key retrieval functions.

use std::{ffi::CString, ptr};

use lee::{AccountId, PublicKey};
use wallet::AccountIdentity;

use crate::{
    error::{print_error, WalletFfiError},
    types::{FfiBytes32, FfiPrivateAccountKeys, FfiPublicAccountKey, WalletHandle},
    wallet::get_wallet,
    FfiAccountIdentity,
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
            print_error(format!("Failed to lock wallet: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    let account_id = AccountId::new(unsafe { (*account_id).data });

    let Some(private_key) = wallet.get_account_public_signing_key(account_id) else {
        print_error("Public account key not found in wallet");
        return WalletFfiError::KeyNotFound;
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
            print_error(format!("Failed to lock wallet: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    let account_id = AccountId::new(unsafe { (*account_id).data });

    let Some(acc) = wallet.storage().key_chain().private_account(account_id) else {
        print_error("Private account not found in wallet");
        return WalletFfiError::AccountNotFound;
    };
    let key_chain = acc.key_chain;

    // NPK is a 32-byte array
    let npk_bytes = key_chain.nullifier_public_key.0;

    // VPK is an ML-KEM-768 encapsulation key (1184 bytes)
    let vpk_bytes = key_chain.viewing_public_key.to_bytes();
    let vpk_len = vpk_bytes.len();
    let vpk_vec = vpk_bytes.to_vec();
    let vpk_boxed = vpk_vec.into_boxed_slice();
    #[expect(
        clippy::as_conversions,
        reason = "We need to convert the boxed slice into a raw pointer for FFI"
    )]
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
                keys.viewing_public_key.cast_mut(),
                keys.viewing_public_key_len,
            );
            drop(Box::from_raw(std::ptr::from_mut::<[u8]>(slice)));
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
            print_error(format!("Failed to create C string: {e}"));
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
            print_error(format!("Invalid UTF-8: {e}"));
            return WalletFfiError::InvalidUtf8;
        }
    };

    let account_id: AccountId = match str_slice.parse() {
        Ok(id) => id,
        Err(e) => {
            print_error(format!("Invalid Base58 account ID: {e}"));
            return WalletFfiError::InvalidAccountId;
        }
    };

    unsafe {
        (*out_account_id).data = *account_id.value();
    }

    WalletFfiError::Success
}

/// Resolve public account.
///
/// # Parameters
/// - `account_id`: 32 bytes of the public account ID
/// - `needs_sign`: whether the account needs signing
/// - `out_account_identity`: valid pointer, where output will be written
///
/// # Returns
/// - `Success` on successful retrieval
///
/// # Safety
/// - `out_account_identity` must be a valid pointer to a `FfiAccountIdentity` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_resolve_public_account(
    account_id: FfiBytes32,
    needs_sign: bool,
    out_account_identity: *mut FfiAccountIdentity,
) -> WalletFfiError {
    if out_account_identity.is_null() {
        print_error("Null pointer argument");
        return WalletFfiError::NullPointer;
    }

    let resolved_account = if needs_sign {
        AccountIdentity::Public(account_id.into())
    } else {
        AccountIdentity::PublicNoSign(account_id.into())
    };

    unsafe {
        *out_account_identity = resolved_account.into();
    }

    WalletFfiError::Success
}

/// Resolve private account.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `account_id`: 32 bytes of the public account ID
/// - `out_account_identity`: valid pointer, where output will be written
///
/// # Returns
/// - `Success` on successful retrieval
/// - `InternalError` if failed to lock wallet
/// - `AccountNotFound` if the account is not found
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `out_account_identity` must be a valid pointer to a `FfiAccountIdentity` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_resolve_private_account(
    handle: *mut WalletHandle,
    account_id: FfiBytes32,
    out_account_identity: *mut FfiAccountIdentity,
) -> WalletFfiError {
    if out_account_identity.is_null() {
        print_error("Null pointer argument");
        return WalletFfiError::NullPointer;
    }

    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    let wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    let account_id = account_id.into();

    let Some(resolved_account) = wallet.resolve_private_account(account_id) else {
        print_error("Account not found");
        return WalletFfiError::AccountNotFound;
    };

    unsafe {
        *out_account_identity = resolved_account.into();
    }

    WalletFfiError::Success
}

/// Free account identity returned by `wallet_ffi_resolve_private_account` or
/// `wallet_ffi_resolve_public_account`.
///
/// # Safety
/// The account must be either null or a valid account returned by
/// `wallet_ffi_resolve_private_account` or `wallet_ffi_resolve_public_account`.
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_free_account_identity(
    account_identity: *mut FfiAccountIdentity,
) {
    if account_identity.is_null() {
        return;
    }

    unsafe {
        let FfiAccountIdentity {
            kind: _,
            account_id: _,
            key_path,
            authorization_secret_key: _,
            nullifier_secret_key: _,
            nullifier_public_key: _,
            viewing_public_key,
            viewing_public_key_len,
            identifier: _,
        } = *account_identity;

        if !viewing_public_key.is_null() {
            let slice = std::slice::from_raw_parts_mut(
                viewing_public_key.cast_mut(),
                viewing_public_key_len,
            );
            drop(Box::from_raw(std::ptr::from_mut::<[u8]>(slice)));
        }

        if !key_path.is_null() {
            let key_path_cstring = CString::from_raw(key_path);
            drop(key_path_cstring);
        }
    }
}

#[cfg(test)]
mod tests {
    use lee::AccountId;
    use wallet::AccountIdentity;

    use crate::{keys::wallet_ffi_free_account_identity, FfiAccountIdentity};

    #[test]
    fn acc_identity_correct_free() {
        let acc_identity = AccountIdentity::Public(AccountId::new([42; 32]));
        let mut ffi_acc_identity: FfiAccountIdentity = acc_identity.into();

        unsafe {
            wallet_ffi_free_account_identity(&raw mut ffi_acc_identity);
        }

        assert!(ffi_acc_identity.viewing_public_key.is_null());
    }
}
