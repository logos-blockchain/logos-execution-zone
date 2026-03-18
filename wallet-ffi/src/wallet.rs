//! Wallet lifecycle management functions.

use std::{
    ffi::{c_char, CStr},
    path::PathBuf,
    ptr,
    sync::Mutex,
};

use wallet::WalletCore;

use crate::{
    block_on,
    error::{print_error, WalletFfiError},
    types::WalletHandle,
};

/// Internal wrapper around `WalletCore` with mutex for thread safety.
pub(crate) struct WalletWrapper {
    pub core: Mutex<WalletCore>,
}

/// Helper to get the wallet wrapper from an opaque handle.
pub(crate) fn get_wallet(
    handle: *mut WalletHandle,
) -> Result<&'static WalletWrapper, WalletFfiError> {
    if handle.is_null() {
        print_error("Null wallet handle");
        return Err(WalletFfiError::NullPointer);
    }
    Ok(unsafe { &*handle.cast::<WalletWrapper>() })
}

/// Helper to get a mutable reference to the wallet wrapper.
#[expect(dead_code, reason = "Maybe used later")]
pub(crate) fn get_wallet_mut(
    handle: *mut WalletHandle,
) -> Result<&'static mut WalletWrapper, WalletFfiError> {
    if handle.is_null() {
        print_error("Null wallet handle");
        return Err(WalletFfiError::NullPointer);
    }
    Ok(unsafe { &mut *handle.cast::<WalletWrapper>() })
}

/// Helper to convert a C string to a Rust `PathBuf`.
fn c_str_to_path(ptr: *const c_char, name: &str) -> Result<PathBuf, WalletFfiError> {
    if ptr.is_null() {
        print_error(format!("Null pointer for {name}"));
        return Err(WalletFfiError::NullPointer);
    }

    let c_str = unsafe { CStr::from_ptr(ptr) };
    match c_str.to_str() {
        Ok(s) => Ok(PathBuf::from(s)),
        Err(e) => {
            print_error(format!("Invalid UTF-8 in {name}: {e}"));
            Err(WalletFfiError::InvalidUtf8)
        }
    }
}

/// Helper to convert a C string to a Rust String.
fn c_str_to_string(ptr: *const c_char, name: &str) -> Result<String, WalletFfiError> {
    if ptr.is_null() {
        print_error(format!("Null pointer for {name}"));
        return Err(WalletFfiError::NullPointer);
    }

    let c_str = unsafe { CStr::from_ptr(ptr) };
    match c_str.to_str() {
        Ok(s) => Ok(s.to_owned()),
        Err(e) => {
            print_error(format!("Invalid UTF-8 in {name}: {e}"));
            Err(WalletFfiError::InvalidUtf8)
        }
    }
}

/// Create a new wallet with fresh storage.
///
/// This initializes a new wallet with a new seed derived from the password.
/// Use this for first-time wallet creation.
///
/// # Parameters
/// - `config_path`: Path to the wallet configuration file (JSON)
/// - `storage_path`: Path where wallet data will be stored
/// - `password`: Password for encrypting the wallet seed
///
/// # Returns
/// - Opaque wallet handle on success
/// - Null pointer on error (call `wallet_ffi_get_last_error()` for details)
///
/// # Safety
/// All string parameters must be valid null-terminated UTF-8 strings.
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_create_new(
    config_path: *const c_char,
    storage_path: *const c_char,
    password: *const c_char,
) -> *mut WalletHandle {
    let Ok(config_path) = c_str_to_path(config_path, "config_path") else {
        return ptr::null_mut();
    };

    let Ok(storage_path) = c_str_to_path(storage_path, "storage_path") else {
        return ptr::null_mut();
    };

    let Ok(password) = c_str_to_string(password, "password") else {
        return ptr::null_mut();
    };

    match WalletCore::new_init_storage(config_path, storage_path, None, password) {
        Ok(core) => {
            let wrapper = Box::new(WalletWrapper {
                core: Mutex::new(core),
            });
            Box::into_raw(wrapper).cast::<WalletHandle>()
        }
        Err(e) => {
            print_error(format!("Failed to create wallet: {e}"));
            ptr::null_mut()
        }
    }
}

/// Open an existing wallet from storage.
///
/// This loads a wallet that was previously created with `wallet_ffi_create_new()`.
///
/// # Parameters
/// - `config_path`: Path to the wallet configuration file (JSON)
/// - `storage_path`: Path where wallet data is stored
///
/// # Returns
/// - Opaque wallet handle on success
/// - Null pointer on error (call `wallet_ffi_get_last_error()` for details)
///
/// # Safety
/// All string parameters must be valid null-terminated UTF-8 strings.
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_open(
    config_path: *const c_char,
    storage_path: *const c_char,
) -> *mut WalletHandle {
    let Ok(config_path) = c_str_to_path(config_path, "config_path") else {
        return ptr::null_mut();
    };

    let Ok(storage_path) = c_str_to_path(storage_path, "storage_path") else {
        return ptr::null_mut();
    };

    match WalletCore::new_update_chain(config_path, storage_path, None) {
        Ok(core) => {
            let wrapper = Box::new(WalletWrapper {
                core: Mutex::new(core),
            });
            Box::into_raw(wrapper).cast::<WalletHandle>()
        }
        Err(e) => {
            print_error(format!("Failed to open wallet: {e}"));
            ptr::null_mut()
        }
    }
}

/// Destroy a wallet handle and free its resources.
///
/// After calling this function, the handle is invalid and must not be used.
///
/// # Safety
/// - The handle must be either null or a valid handle from `wallet_ffi_create_new()` or
///   `wallet_ffi_open()`.
/// - The handle must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_destroy(handle: *mut WalletHandle) {
    if !handle.is_null() {
        unsafe {
            drop(Box::from_raw(handle.cast::<WalletWrapper>()));
        }
    }
}

/// Save wallet state to persistent storage.
///
/// This should be called periodically or after important operations to ensure
/// wallet data is persisted to disk.
///
/// # Parameters
/// - `handle`: Valid wallet handle
///
/// # Returns
/// - `Success` on successful save
/// - Error code on failure
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_save(handle: *mut WalletHandle) -> WalletFfiError {
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

    match block_on(wallet.store_persistent_data()) {
        Ok(()) => WalletFfiError::Success,
        Err(e) => {
            print_error(format!("Failed to save wallet: {e}"));
            WalletFfiError::StorageError
        }
    }
}

/// Get the sequencer address from the wallet configuration.
///
/// # Parameters
/// - `handle`: Valid wallet handle
///
/// # Returns
/// - Pointer to null-terminated string on success (caller must free with
///   `wallet_ffi_free_string()`)
/// - Null pointer on error
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_get_sequencer_addr(handle: *mut WalletHandle) -> *mut c_char {
    let Ok(wrapper) = get_wallet(handle) else {
        return ptr::null_mut();
    };

    let wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return ptr::null_mut();
        }
    };

    let addr = wallet.config().sequencer_addr.clone().to_string();

    match std::ffi::CString::new(addr) {
        Ok(s) => s.into_raw(),
        Err(e) => {
            print_error(format!("Invalid sequencer address: {e}"));
            ptr::null_mut()
        }
    }
}

/// Free a string returned by wallet FFI functions.
///
/// # Safety
/// The pointer must be either null or a valid string returned by an FFI function.
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            drop(std::ffi::CString::from_raw(ptr));
        }
    }
}
