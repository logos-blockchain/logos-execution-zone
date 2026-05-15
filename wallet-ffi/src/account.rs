//! Account management functions.

use std::{ffi::c_char, ptr, str::FromStr as _};

use key_protocol::key_management::{key_tree::chain_index::ChainIndex, KeyChain};
use nssa::AccountId;
use wallet::account::{AccountIdWithPrivacy, HumanReadableAccount};

use crate::{
    block_on, c_str_to_string,
    error::{print_error, WalletFfiError},
    types::{
        FfiAccount, FfiAccountList, FfiAccountListEntry, FfiBytes32, FfiPrivateAccountKeys,
        WalletHandle,
    },
    wallet::get_wallet,
    FfiU128,
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

/// Create a new private account, storing a default account entry in local storage.
///
/// This is the private-account equivalent of `wallet_ffi_create_account_public`.
/// It generates a key node, assigns a random identifier, and inserts a default
/// account record so the account can immediately be used with
/// `wallet_ffi_register_private_account`.
///
/// The identifier is chosen at random and is not encoded in the mnemonic seed.
/// Once the account is initialized, the identifier is embedded in the encrypted
/// transaction payload and can be recovered by running `sync-private` from the
/// same mnemonic. An account that was created locally but has never been initialized
/// cannot be recovered from the seed alone.
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

/// Create a new private key node.
///
/// Returns the nullifier public key (npk) and viewing public key (vpk) to share with
/// senders. Account IDs are discovered later via sync when senders initialize accounts
/// under this key.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `out_keys`: Output pointer for the key data (npk + vpk)
///
/// # Returns
/// - `Success` on successful creation
/// - Error code on failure
///
/// # Memory
/// The keys structure must be freed with `wallet_ffi_free_private_account_keys()`.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `out_keys` must be a valid pointer to a `FfiPrivateAccountKeys` struct
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_create_private_accounts_key(
    handle: *mut WalletHandle,
    out_keys: *mut FfiPrivateAccountKeys,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if out_keys.is_null() {
        print_error("Null output pointer for keys");
        return WalletFfiError::NullPointer;
    }

    let mut wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    let chain_index = wallet.create_private_accounts_key(None);
    let key_chain = wallet
        .storage()
        .key_chain()
        .private_account_key_chain_by_index(&chain_index)
        .expect("Node was just inserted");

    let npk_bytes = key_chain.nullifier_public_key.0;
    let vpk_bytes = key_chain.viewing_public_key.to_bytes();
    let vpk_len = vpk_bytes.len();
    #[expect(
        clippy::as_conversions,
        reason = "We need to convert the boxed slice into a raw pointer for FFI"
    )]
    let vpk_ptr = Box::into_raw(vpk_bytes.to_vec().into_boxed_slice()) as *const u8;

    unsafe {
        (*out_keys).nullifier_public_key.data = npk_bytes;
        (*out_keys).viewing_public_key = vpk_ptr;
        (*out_keys).viewing_public_key_len = vpk_len;
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

    let entries = wallet
        .storage()
        .key_chain()
        .account_ids()
        .map(|(account_id, _idx)| match account_id {
            AccountIdWithPrivacy::Public(account_id) => FfiAccountListEntry {
                account_id: FfiBytes32::from_account_id(account_id),
                is_public: true,
            },
            AccountIdWithPrivacy::Private(account_id) => FfiAccountListEntry {
                account_id: FfiBytes32::from_account_id(account_id),
                is_public: false,
            },
        })
        .collect::<Vec<_>>();

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

/// Import a public account private key into wallet storage.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `private_key_hex`: Hex-encoded private key string
///
/// # Returns
/// - `Success` on successful import
/// - Error code on failure
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `private_key_hex` must be a valid pointer to a null-terminated C string
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_import_public_account(
    handle: *mut WalletHandle,
    private_key_hex: *const c_char,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    let private_key_hex = match c_str_to_string(private_key_hex, "private_key_hex") {
        Ok(value) => value,
        Err(e) => return e,
    };

    let private_key = match nssa::PrivateKey::from_str(&private_key_hex) {
        Ok(value) => value,
        Err(e) => {
            print_error(format!("Invalid public account private key: {e}"));
            return WalletFfiError::InvalidKeyValue;
        }
    };

    let mut wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    wallet
        .storage_mut()
        .key_chain_mut()
        .add_imported_public_account(private_key);

    match wallet.store_persistent_data() {
        Ok(()) => WalletFfiError::Success,
        Err(e) => {
            print_error(format!("Failed to save wallet after public import: {e}"));
            WalletFfiError::StorageError
        }
    }
}

/// Import a private account keychain and account state into wallet storage.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `key_chain_json`: JSON-encoded `key_protocol::key_management::KeyChain`
/// - `chain_index`: Optional chain index string (for example `/0/1`, `NULL` if unknown)
/// - `identifier`: Identifier for this private account as little-endian u128 bytes
/// - `account_state_json`: JSON-encoded `wallet::account::HumanReadableAccount`
///
/// # Returns
/// - `Success` on successful import
/// - Error code on failure
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `key_chain_json` must be a valid pointer to a null-terminated C string
/// - `identifier` must be a valid pointer to a `FfiU128` struct
/// - `account_state_json` must be a valid pointer to a null-terminated C string
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_import_private_account(
    handle: *mut WalletHandle,
    key_chain_json: *const c_char,
    chain_index: *const c_char,
    identifier: *const FfiU128,
    account_state_json: *const c_char,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    if identifier.is_null() {
        print_error("Null pointer for identifier");
        return WalletFfiError::NullPointer;
    }

    let key_chain_json = match c_str_to_string(key_chain_json, "key_chain_json") {
        Ok(value) => value,
        Err(e) => return e,
    };

    let account_state_json = match c_str_to_string(account_state_json, "account_state_json") {
        Ok(value) => value,
        Err(e) => return e,
    };

    let key_chain: KeyChain = match serde_json::from_str(&key_chain_json) {
        Ok(value) => value,
        Err(e) => {
            print_error(format!("Invalid key chain JSON: {e}"));
            return WalletFfiError::SerializationError;
        }
    };

    let account_state: HumanReadableAccount = match serde_json::from_str(&account_state_json) {
        Ok(value) => value,
        Err(e) => {
            print_error(format!("Invalid account state JSON: {e}"));
            return WalletFfiError::SerializationError;
        }
    };

    let account = nssa::Account::from(account_state);

    let mut wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    let chain_index = if chain_index.is_null() {
        None
    } else {
        let chain_index_path = match c_str_to_string(chain_index, "chain_index") {
            Ok(value) => value,
            Err(e) => return e,
        };

        let parsed_chain_index = match ChainIndex::from_str(&chain_index_path) {
            Ok(value) => value,
            Err(e) => {
                print_error(format!("Invalid chain index string: {e}"));
                return WalletFfiError::InvalidTypeConversion;
            }
        };

        Some(parsed_chain_index)
    };

    let identifier = u128::from_le_bytes(unsafe { (*identifier).data });

    wallet
        .storage_mut()
        .key_chain_mut()
        .add_imported_private_account(key_chain, chain_index, identifier, account);

    match wallet.store_persistent_data() {
        Ok(()) => WalletFfiError::Success,
        Err(e) => {
            print_error(format!("Failed to save wallet after private import: {e}"));
            WalletFfiError::StorageError
        }
    }
}
