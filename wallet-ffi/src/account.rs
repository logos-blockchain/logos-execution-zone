//! Account management functions.

use std::ptr;

use nssa::AccountId;

use crate::{
    block_on,
    error::{print_error, WalletFfiError},
    types::{FfiAccount, FfiAccountList, FfiAccountListEntry, FfiBytes32, WalletHandle},
    wallet::get_wallet,
};

/// Create a new public account.
///
/// Public accounts use standard transaction signing and are suitable for
/// non-private operations.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `out_account_id`: Output pointer for the new account ID (32 bytes)
///
/// # Returns
/// - `Success` on successful creation
/// - Error code on failure
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `out_account_id` must be a valid pointer to a `FfiBytes32` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_create_account_public(
    handle: *mut WalletHandle,
    out_account_id: *mut FfiBytes32,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if out_account_id.is_null() {
        print_error("Null output pointer for account_id");
        return WalletFfiError::NullPointer;
    }

    let mut wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    let (account_id, _chain_index) = wallet.create_new_account_public(None);

    unsafe {
        (*out_account_id).data = *account_id.value();
    }

    WalletFfiError::Success
}

/// Create a new private account.
///
/// Private accounts use privacy-preserving transactions with nullifiers
/// and commitments.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `out_account_id`: Output pointer for the new account ID (32 bytes)
///
/// # Returns
/// - `Success` on successful creation
/// - Error code on failure
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `out_account_id` must be a valid pointer to a `FfiBytes32` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_create_account_private(
    handle: *mut WalletHandle,
    out_account_id: *mut FfiBytes32,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if out_account_id.is_null() {
        print_error("Null output pointer for account_id");
        return WalletFfiError::NullPointer;
    }

    let mut wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    let (account_id, _chain_index) = wallet.create_new_account_private(None);

    unsafe {
        (*out_account_id).data = *account_id.value();
    }

    WalletFfiError::Success
}

/// List all accounts in the wallet.
///
/// Returns both public and private accounts managed by this wallet.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `out_list`: Output pointer for the account list
///
/// # Returns
/// - `Success` on successful listing
/// - Error code on failure
///
/// # Memory
/// The returned list must be freed with `wallet_ffi_free_account_list()`.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `out_list` must be a valid pointer to a `FfiAccountList` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_list_accounts(
    handle: *mut WalletHandle,
    out_list: *mut FfiAccountList,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if out_list.is_null() {
        print_error("Null output pointer for account list");
        return WalletFfiError::NullPointer;
    }

    let wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    let user_data = &wallet.storage().user_data;
    let mut entries = Vec::new();

    // Public accounts from default signing keys (preconfigured)
    for account_id in user_data.default_pub_account_signing_keys.keys() {
        entries.push(FfiAccountListEntry {
            account_id: FfiBytes32::from_account_id(account_id),
            is_public: true,
        });
    }

    // Public accounts from key tree (generated)
    for account_id in user_data.public_key_tree.account_id_map.keys() {
        entries.push(FfiAccountListEntry {
            account_id: FfiBytes32::from_account_id(account_id),
            is_public: true,
        });
    }

    // Private accounts from default accounts (preconfigured)
    for account_id in user_data.default_user_private_accounts.keys() {
        entries.push(FfiAccountListEntry {
            account_id: FfiBytes32::from_account_id(account_id),
            is_public: false,
        });
    }

    // Private accounts from key tree (generated)
    for account_id in user_data.private_key_tree.account_id_map.keys() {
        entries.push(FfiAccountListEntry {
            account_id: FfiBytes32::from_account_id(account_id),
            is_public: false,
        });
    }

    let count = entries.len();

    if count == 0 {
        unsafe {
            (*out_list).entries = ptr::null_mut();
            (*out_list).count = 0;
        }
    } else {
        let entries_boxed = entries.into_boxed_slice();
        let entries_ptr = Box::into_raw(entries_boxed).cast::<FfiAccountListEntry>();

        unsafe {
            (*out_list).entries = entries_ptr;
            (*out_list).count = count;
        }
    }

    WalletFfiError::Success
}

/// Free an account list returned by `wallet_ffi_list_accounts`.
///
/// # Safety
/// The list must be either null or a valid list returned by `wallet_ffi_list_accounts`.
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_free_account_list(list: *mut FfiAccountList) {
    if list.is_null() {
        return;
    }

    unsafe {
        let list = &*list;
        if !list.entries.is_null() && list.count > 0 {
            let slice = std::slice::from_raw_parts_mut(list.entries, list.count);
            drop(Box::from_raw(std::ptr::from_mut::<[FfiAccountListEntry]>(
                slice,
            )));
        }
    }
}

/// Get account balance.
///
/// For public accounts, this fetches the balance from the network.
/// For private accounts, this returns the locally cached balance.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `account_id`: The account ID (32 bytes)
/// - `is_public`: Whether this is a public account
/// - `out_balance`: Output for balance as little-endian [u8; 16]
///
/// # Returns
/// - `Success` on successful query
/// - Error code on failure
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `account_id` must be a valid pointer to a `FfiBytes32` struct
/// - `out_balance` must be a valid pointer to a `[u8; 16]` array
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_get_balance(
    handle: *mut WalletHandle,
    account_id: *const FfiBytes32,
    is_public: bool,
    out_balance: *mut [u8; 16],
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if account_id.is_null() || out_balance.is_null() {
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

    let balance = if is_public {
        match block_on(wallet.get_account_balance(account_id)) {
            Ok(b) => b,
            Err(e) => {
                print_error(format!("Failed to get balance: {e}"));
                return WalletFfiError::NetworkError;
            }
        }
    } else if let Some(account) = wallet.get_account_private(account_id) {
        account.balance
    } else {
        print_error("Private account not found");
        return WalletFfiError::AccountNotFound;
    };

    unsafe {
        *out_balance = balance.to_le_bytes();
    }

    WalletFfiError::Success
}

/// Get full public account data from the network.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `account_id`: The account ID (32 bytes)
/// - `out_account`: Output pointer for account data
///
/// # Returns
/// - `Success` on successful query
/// - Error code on failure
///
/// # Memory
/// The account data must be freed with `wallet_ffi_free_account_data()`.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `account_id` must be a valid pointer to a `FfiBytes32` struct
/// - `out_account` must be a valid pointer to a `FfiAccount` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_get_account_public(
    handle: *mut WalletHandle,
    account_id: *const FfiBytes32,
    out_account: *mut FfiAccount,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if account_id.is_null() || out_account.is_null() {
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

    let account = match block_on(wallet.get_account_public(account_id)) {
        Ok(a) => a,
        Err(e) => {
            print_error(format!("Failed to get account: {e}"));
            return WalletFfiError::NetworkError;
        }
    };

    unsafe {
        *out_account = account.into();
    }

    WalletFfiError::Success
}

/// Get full private account data from the local storage.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `account_id`: The account ID (32 bytes)
/// - `out_account`: Output pointer for account data
///
/// # Returns
/// - `Success` on successful query
/// - Error code on failure
///
/// # Memory
/// The account data must be freed with `wallet_ffi_free_account_data()`.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `account_id` must be a valid pointer to a `FfiBytes32` struct
/// - `out_account` must be a valid pointer to a `FfiAccount` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_get_account_private(
    handle: *mut WalletHandle,
    account_id: *const FfiBytes32,
    out_account: *mut FfiAccount,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if account_id.is_null() || out_account.is_null() {
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

    let Some(account) = wallet.get_account_private(account_id) else {
        return WalletFfiError::AccountNotFound;
    };

    unsafe {
        *out_account = account.into();
    }

    WalletFfiError::Success
}

/// Free account data returned by `wallet_ffi_get_account_public`.
///
/// # Safety
/// The account must be either null or a valid account returned by
/// `wallet_ffi_get_account_public`.
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_free_account_data(account: *mut FfiAccount) {
    if account.is_null() {
        return;
    }

    unsafe {
        let account = &*account;
        if !account.data.is_null() && account.data_len > 0 {
            let slice = std::slice::from_raw_parts_mut(account.data.cast_mut(), account.data_len);
            drop(Box::from_raw(std::ptr::from_mut::<[u8]>(slice)));
        }
    }
}
