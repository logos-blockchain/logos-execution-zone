//! Wallet lifecycle management functions.

use std::{
    ffi::{c_char, CStr, CString},
    path::PathBuf,
    ptr,
    str::FromStr as _,
    sync::Mutex,
};

use bip39::Mnemonic;
use wallet::{cli::execute_keys_restoration, WalletCore};

use crate::{
    block_on, c_str_to_string,
    error::{print_error, WalletFfiError},
    types::WalletHandle,
};

/// Internal wrapper around `WalletCore` with mutex for thread safety.
pub(crate) struct WalletWrapper {
    pub core: Mutex<WalletCore>,
}

#[repr(C)]
pub struct FfiCreateWalletOutput {
    pub wallet: *mut WalletHandle,
    /// C compatible(null terminated) string.
    pub mnemonic: *mut c_char,
}

impl Default for FfiCreateWalletOutput {
    fn default() -> Self {
        Self {
            wallet: std::ptr::null_mut(),
            mnemonic: std::ptr::null_mut(),
        }
    }
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
/// - Result, which contains opaque wallet handle and mnemonic words on success
/// - Result with null pointers on error (call `wallet_ffi_get_last_error()` for details)
///
/// # Safety
/// All string parameters must be valid null-terminated UTF-8 strings.
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_create_new(
    config_path: *const c_char,
    storage_path: *const c_char,
    password: *const c_char,
) -> FfiCreateWalletOutput {
    let Ok(config_path) = c_str_to_path(config_path, "config_path") else {
        return FfiCreateWalletOutput::default();
    };

    let Ok(storage_path) = c_str_to_path(storage_path, "storage_path") else {
        return FfiCreateWalletOutput::default();
    };

    let Ok(password) = c_str_to_string(password, "password") else {
        return FfiCreateWalletOutput::default();
    };

    match WalletCore::new_init_storage(config_path, storage_path, None, &password) {
        Ok((core, mnemonic)) => {
            let wrapper = Box::new(WalletWrapper {
                core: Mutex::new(core),
            });
            let handle = Box::into_raw(wrapper).cast::<WalletHandle>();

            let Ok(c_mnemonic_string) = CString::new(mnemonic.to_string()) else {
                return FfiCreateWalletOutput::default();
            };

            let raw_pointer = CString::into_raw(c_mnemonic_string);

            FfiCreateWalletOutput {
                wallet: handle,
                mnemonic: raw_pointer,
            }
        }
        Err(e) => {
            print_error(format!("Failed to create wallet: {e}"));
            FfiCreateWalletOutput::default()
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

/// Resolve LEZ's canonical wallet paths (`LEE_WALLET_HOME_DIR` or `~/.lee/wallet`)
/// and ensure the home directory exists. Centralizes the path layout so callers
/// don't have to reconstruct it.
fn default_wallet_paths() -> Result<(PathBuf, PathBuf), WalletFfiError> {
    let home = wallet::helperfunctions::get_home().map_err(|e| {
        print_error(format!("Failed to resolve wallet home: {e}"));
        WalletFfiError::InternalError
    })?;

    if let Err(e) = std::fs::create_dir_all(&home) {
        print_error(format!(
            "Failed to create wallet home {}: {e}",
            home.display()
        ));
        return Err(WalletFfiError::StorageError);
    }

    let config_path = wallet::helperfunctions::fetch_config_path().map_err(|e| {
        print_error(format!("Failed to resolve config path: {e}"));
        WalletFfiError::InternalError
    })?;
    let storage_path = wallet::helperfunctions::fetch_persistent_storage_path().map_err(|e| {
        print_error(format!("Failed to resolve storage path: {e}"));
        WalletFfiError::InternalError
    })?;

    Ok((config_path, storage_path))
}

/// Create a new wallet at LEZ's canonical home, deriving the paths from the
/// environment (`LEE_WALLET_HOME_DIR` or `~/.lee/wallet`) and creating the
/// directory if needed.
///
/// This is the path-free equivalent of [`wallet_ffi_create_new`]: callers that
/// just want the default location don't have to reconstruct LEZ's path layout.
///
/// # Parameters
/// - `password`: Password for encrypting the wallet seed
///
/// # Returns
/// - Result, which contains opaque wallet handle and mnemonic words on success
/// - Result with null pointers on error (call `wallet_ffi_get_last_error()` for details)
///
/// # Safety
/// `password` must be a valid null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_create_new_default(
    password: *const c_char,
) -> FfiCreateWalletOutput {
    let Ok(password) = c_str_to_string(password, "password") else {
        return FfiCreateWalletOutput::default();
    };

    let Ok((config_path, storage_path)) = default_wallet_paths() else {
        return FfiCreateWalletOutput::default();
    };

    match WalletCore::new_init_storage(config_path, storage_path, None, &password) {
        Ok((core, mnemonic)) => {
            let wrapper = Box::new(WalletWrapper {
                core: Mutex::new(core),
            });
            let handle = Box::into_raw(wrapper).cast::<WalletHandle>();

            let Ok(c_mnemonic_string) = CString::new(mnemonic.to_string()) else {
                return FfiCreateWalletOutput::default();
            };

            let raw_pointer = CString::into_raw(c_mnemonic_string);

            FfiCreateWalletOutput {
                wallet: handle,
                mnemonic: raw_pointer,
            }
        }
        Err(e) => {
            print_error(format!("Failed to create wallet: {e}"));
            FfiCreateWalletOutput::default()
        }
    }
}

/// Open the existing wallet at LEZ's canonical home, deriving the paths from the
/// environment (`LEE_WALLET_HOME_DIR` or `~/.lee/wallet`).
///
/// This is the path-free equivalent of [`wallet_ffi_open`].
///
/// # Returns
/// - Opaque wallet handle on success
/// - Null pointer on error (call `wallet_ffi_get_last_error()` for details)
///
/// # Safety
/// This function takes no pointer arguments and is always safe to call.
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_open_default() -> *mut WalletHandle {
    match WalletCore::from_env() {
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

/// Convert a resolved path into an owned C string for return across the FFI.
fn path_to_c_string(path: PathBuf) -> *mut c_char {
    match CString::new(path.to_string_lossy().into_owned()) {
        Ok(s) => s.into_raw(),
        Err(e) => {
            print_error(format!("Invalid path string: {e}"));
            ptr::null_mut()
        }
    }
}

/// Return LEZ's canonical wallet config path (`LEE_WALLET_HOME_DIR` or
/// `~/.lee/wallet`, plus `wallet_config.json`).
///
/// Lets callers display or inspect the default location without reconstructing
/// LEZ's path layout themselves.
///
/// # Returns
/// - Pointer to null-terminated string on success (caller must free with
///   `wallet_ffi_free_string()`)
/// - Null pointer on error
///
/// # Safety
/// This function takes no pointer arguments and is always safe to call.
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_default_config_path() -> *mut c_char {
    match wallet::helperfunctions::fetch_config_path() {
        Ok(path) => path_to_c_string(path),
        Err(e) => {
            print_error(format!("Failed to resolve config path: {e}"));
            ptr::null_mut()
        }
    }
}

/// Return LEZ's canonical wallet storage path (`LEE_WALLET_HOME_DIR` or
/// `~/.lee/wallet`, plus `storage.json`).
///
/// # Returns
/// - Pointer to null-terminated string on success (caller must free with
///   `wallet_ffi_free_string()`)
/// - Null pointer on error
///
/// # Safety
/// This function takes no pointer arguments and is always safe to call.
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_default_storage_path() -> *mut c_char {
    match wallet::helperfunctions::fetch_persistent_storage_path() {
        Ok(path) => path_to_c_string(path),
        Err(e) => {
            print_error(format!("Failed to resolve storage path: {e}"));
            ptr::null_mut()
        }
    }
}

/// Whether a wallet already exists at LEZ's canonical home (i.e. its
/// `storage.json` is present). Lets callers decide between an open and a
/// create flow without touching the filesystem or knowing the path.
///
/// # Returns
/// - `true` if the default storage file exists, `false` otherwise (including
///   when the path can't be resolved)
///
/// # Safety
/// This function takes no pointer arguments and is always safe to call.
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_wallet_exists_default() -> bool {
    match wallet::helperfunctions::fetch_persistent_storage_path() {
        Ok(path) => path.exists(),
        Err(e) => {
            print_error(format!("Failed to resolve storage path: {e}"));
            false
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

    match wallet.store_persistent_data() {
        Ok(()) => WalletFfiError::Success,
        Err(e) => {
            print_error(format!("Failed to save wallet: {e}"));
            WalletFfiError::StorageError
        }
    }
}

/// Restore wallet data from mnemonic and password.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `mnemonic`: Valid pointer to instance of `* char`, provided by `wallet_ffi_create_new`
/// - `password`: Valid pointer to C string.
/// - `depth`: Depth of a reconstructed tree
///
/// # Returns
/// - `Success` on successful restoration
/// - Error code on failure
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `mnemonic` must be a valid pointer to instance of `* char`, provided by
///   `wallet_ffi_create_new`
/// - `password` must be a valid pointer to C string.
/// - `depth` parameter induces exponential growth in execution time, be aware of it.
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_restore_data(
    handle: *mut WalletHandle,
    mnemonic: *const c_char,
    password: *const c_char,
    depth: u32,
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

    let Ok(password) = c_str_to_string(password, "password") else {
        return WalletFfiError::NullPointer;
    };

    let Ok(mnemonic) = c_str_to_string(mnemonic, "mnemonic") else {
        return WalletFfiError::NullPointer;
    };

    let mnemonic = match Mnemonic::from_str(&mnemonic) {
        Ok(mn) => mn,
        Err(e) => {
            print_error(format!("Failed to parse mnemonic: {e}"));
            return WalletFfiError::SerializationError;
        }
    };

    let res = match wallet.restore_storage(&mnemonic, &password) {
        Ok(()) => WalletFfiError::Success,
        Err(e) => {
            print_error(format!("Failed to restore wallet data: {e}"));
            WalletFfiError::StorageError
        }
    };

    if res == WalletFfiError::Success {
        match block_on(execute_keys_restoration(&mut wallet, depth)) {
            Ok(()) => WalletFfiError::Success,
            Err(err) => {
                print_error(format!("Failed to restore wallet data: {err}"));
                WalletFfiError::StorageError
            }
        }
    } else {
        res
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
