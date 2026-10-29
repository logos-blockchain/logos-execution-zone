//! Wallet lifecycle management functions.

use std::{
    ffi::{CStr, CString, c_char},
    path::PathBuf,
    ptr,
    str::FromStr as _,
    sync::Mutex,
};

use bip39::Mnemonic;
use wallet::{
    WalletCore,
    storage::{Storage, WrongPassword},
};
use zeroize::Zeroizing;

use crate::{
    error::{FfiOperationError, print_error},
    sequencer::SequencerServiceFFI,
    sequencer_ffi_client::SequencerServiceFFIWrapper,
    wallet::{block_on, c_str_to_string, types::WalletHandle},
};

/// Internal wrapper around `WalletCore` with mutex for thread safety.
pub(crate) struct WalletWrapper {
    pub core: Mutex<WalletCore<SequencerServiceFFIWrapper>>,
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
) -> Result<&'static WalletWrapper, FfiOperationError> {
    if handle.is_null() {
        print_error("Null wallet handle");
        return Err(FfiOperationError::NullPointer);
    }
    Ok(unsafe { &*handle.cast::<WalletWrapper>() })
}

/// Helper to get a mutable reference to the wallet wrapper.
#[expect(dead_code, reason = "Maybe used later")]
pub(crate) fn get_wallet_mut(
    handle: *mut WalletHandle,
) -> Result<&'static mut WalletWrapper, FfiOperationError> {
    if handle.is_null() {
        print_error("Null wallet handle");
        return Err(FfiOperationError::NullPointer);
    }
    Ok(unsafe { &mut *handle.cast::<WalletWrapper>() })
}

/// Helper to convert a C string to a Rust `PathBuf`.
fn c_str_to_path(ptr: *const c_char, name: &str) -> Result<PathBuf, FfiOperationError> {
    if ptr.is_null() {
        print_error(format!("Null pointer for {name}"));
        return Err(FfiOperationError::NullPointer);
    }

    let c_str = unsafe { CStr::from_ptr(ptr) };
    match c_str.to_str() {
        Ok(s) => Ok(PathBuf::from(s)),
        Err(e) => {
            print_error(format!("Invalid UTF-8 in {name}: {e}"));
            Err(FfiOperationError::InvalidUtf8)
        }
    }
}

/// Create a new wallet with fresh storage.
///
/// This initializes a new wallet with a fresh mnemonic, its sync cursor at the chain tip.
/// An unreachable node leaves the cursor at genesis.
/// Use this for first-time wallet creation.
///
/// # Parameters
/// - `config_path`: Path to the wallet configuration file (JSON)
/// - `storage_path`: Path where wallet data will be stored
/// - `password`: Password the wallet storage is encrypted under, or empty to leave it unencrypted
/// - `sequencer`: Valid pointer into `SequencerServiceFFI`
///
/// # Returns
/// - Result, which contains opaque wallet handle and mnemonic words on success
/// - Result with null pointers on error, whose details are printed to stderr
///
/// # Safety
/// All string parameters must be valid null-terminated UTF-8 strings. Sequencer pointer must be
/// valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_ffi_create_new(
    config_path: *const c_char,
    storage_path: *const c_char,
    password: *const c_char,
    sequencer: *const SequencerServiceFFI,
) -> FfiCreateWalletOutput {
    let Ok(config_path) = c_str_to_path(config_path, "config_path") else {
        return FfiCreateWalletOutput::default();
    };

    let Ok(storage_path) = c_str_to_path(storage_path, "storage_path") else {
        return FfiCreateWalletOutput::default();
    };

    let Ok(password) = c_str_to_string(password, "password").map(Zeroizing::new) else {
        return FfiCreateWalletOutput::default();
    };

    if sequencer.is_null() {
        return FfiCreateWalletOutput::default();
    }

    let sequencer = unsafe { &*sequencer };

    match WalletCore::new_init_storage_with_client(
        config_path,
        storage_path,
        None,
        &password,
        SequencerServiceFFIWrapper::wrap(sequencer),
    ) {
        Ok((mut core, mnemonic)) => {
            if let Err(e) = block_on(core.start_at_chain_tip()) {
                print_error(format!(
                    "Could not read the chain tip, the new wallet syncs from block 0: {e}"
                ));
            }

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
/// - `storage_path`: Path to the wallet storage (JSON)
/// - `password`: Password the wallet storage is encrypted under, or empty for an unencrypted
///   storage (see `wallet_ffi_storage_is_encrypted`)
/// - `out_handle`: Output pointer for the opaque wallet handle
/// - `sequencer`: Valid pointer into `SequencerServiceFFI`
///
/// # Returns
/// - `Success` with the handle written to `out_handle`
/// - `WrongPassword` if the password does not open the storage, including a non-empty one for an
///   unencrypted storage
/// - Another error code on any other failure, whose details are printed to stderr
///
/// # Safety
/// - All string parameters must be valid null-terminated UTF-8 strings. Sequencer pointer must be
///   valid.
/// - `out_handle` must be a valid pointer to a `WalletHandle *`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_ffi_open(
    config_path: *const c_char,
    storage_path: *const c_char,
    sequencer: *const SequencerServiceFFI,
    password: *const c_char,
    out_handle: *mut *mut WalletHandle,
) -> FfiOperationError {
    if out_handle.is_null() {
        print_error("Null output pointer for handle");
        return FfiOperationError::NullPointer;
    }

    let config_path = match c_str_to_path(config_path, "config_path") {
        Ok(path) => path,
        Err(e) => return e,
    };

    let storage_path = match c_str_to_path(storage_path, "storage_path") {
        Ok(path) => path,
        Err(e) => return e,
    };

    let password = match c_str_to_string(password, "password") {
        Ok(password) => Zeroizing::new(password),
        Err(e) => return e,
    };

    if sequencer.is_null() {
        print_error("Null input pointer for sequencer");
        return FfiOperationError::NullPointer;
    }

    let sequencer = unsafe { &*sequencer };

    match WalletCore::new_update_chain_with_client(
        config_path,
        storage_path,
        None,
        &password,
        SequencerServiceFFIWrapper::wrap(sequencer),
    ) {
        Ok(core) => {
            let wrapper = Box::new(WalletWrapper {
                core: Mutex::new(core),
            });
            unsafe {
                *out_handle = Box::into_raw(wrapper).cast::<WalletHandle>();
            }
            FfiOperationError::Success
        }
        Err(e) => {
            print_error(format!("Failed to open wallet: {e:#}"));
            if e.is::<WrongPassword>() {
                FfiOperationError::WrongPassword
            } else {
                FfiOperationError::StorageError
            }
        }
    }
}

/// Report whether the wallet storage at `storage_path` is encrypted, and so needs a password to
/// open.
///
/// # Parameters
/// - `storage_path`: Path to the wallet storage (JSON)
/// - `out_encrypted`: Output pointer for whether the storage is encrypted
///
/// # Returns
/// - `Success` with the answer written to `out_encrypted`
/// - Error code on failure, including a missing storage file, whose details are printed to stderr
///
/// # Safety
/// - `storage_path` must be a valid null-terminated UTF-8 string.
/// - `out_encrypted` must be a valid pointer to a `bool`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_ffi_storage_is_encrypted(
    storage_path: *const c_char,
    out_encrypted: *mut bool,
) -> FfiOperationError {
    if out_encrypted.is_null() {
        print_error("Null output pointer for encrypted");
        return FfiOperationError::NullPointer;
    }

    let storage_path = match c_str_to_path(storage_path, "storage_path") {
        Ok(path) => path,
        Err(e) => return e,
    };

    match Storage::is_encrypted(&storage_path) {
        Ok(encrypted) => {
            unsafe {
                *out_encrypted = encrypted;
            }
            FfiOperationError::Success
        }
        Err(e) => {
            print_error(format!("Failed to read the wallet storage: {e:#}"));
            FfiOperationError::StorageError
        }
    }
}

/// Save the wallet storage encrypted under `password`, or unencrypted for an empty one, and keep
/// saving it so.
///
/// Ask for the new password twice: nothing recovers the storage from a mistyped one.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `password`: Password to encrypt the storage under, or empty for none
///
/// # Returns
/// - `Success` once the storage is saved
/// - Error code on failure, whose details are printed to stderr
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `password` must be a valid null-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_ffi_set_password(
    handle: *mut WalletHandle,
    password: *const c_char,
) -> FfiOperationError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    let password = match c_str_to_string(password, "password") {
        Ok(password) => Zeroizing::new(password),
        Err(e) => return e,
    };

    let mut wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return FfiOperationError::InternalError;
        }
    };

    match wallet.set_password(&password) {
        Ok(()) => FfiOperationError::Success,
        Err(e) => {
            print_error(format!("Failed to set the wallet password: {e:#}"));
            FfiOperationError::StorageError
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_ffi_save(handle: *mut WalletHandle) -> FfiOperationError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    let wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return FfiOperationError::InternalError;
        }
    };

    match wallet.store_persistent_data() {
        Ok(()) => FfiOperationError::Success,
        Err(e) => {
            print_error(format!("Failed to save wallet: {e}"));
            FfiOperationError::StorageError
        }
    }
}

/// Restore wallet data from a mnemonic.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `mnemonic`: Valid pointer to instance of `* char`, provided by `wallet_ffi_create_new`
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
/// - `depth` parameter induces exponential growth in execution time, be aware of it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_ffi_restore_data(
    handle: *mut WalletHandle,
    mnemonic: *const c_char,
    depth: u32,
) -> FfiOperationError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    let mut wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return FfiOperationError::InternalError;
        }
    };

    let Ok(mnemonic) = c_str_to_string(mnemonic, "mnemonic") else {
        return FfiOperationError::NullPointer;
    };

    let mnemonic = match Mnemonic::from_str(&mnemonic) {
        Ok(mn) => mn,
        Err(e) => {
            print_error(format!("Failed to parse mnemonic: {e}"));
            return FfiOperationError::SerializationError;
        }
    };

    wallet.restore_storage(&mnemonic);

    match block_on(wallet.restore_keys(depth)) {
        Ok(()) => FfiOperationError::Success,
        Err(err) => {
            print_error(format!("Failed to restore wallet data: {err}"));
            FfiOperationError::StorageError
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
#[unsafe(no_mangle)]
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

    let addr = wallet.client_url().to_string();

    match std::ffi::CString::new(addr) {
        Ok(s) => s.into_raw(),
        Err(e) => {
            print_error(format!("Invalid sequencer address: {e}"));
            ptr::null_mut()
        }
    }
}
