use std::ffi::c_char;

use common::config::BasicAuth;
use wallet::config::SequencerConnectionData;

use crate::{
    block_on, c_str_to_string,
    error::{print_error, WalletFfiError},
    wallet::get_wallet,
    WalletHandle,
};

/// Execute client rotation.
///
/// Actualizes clients with statistics present, callibrates clients without statistics.
/// Re-chooses leaders according to a `distribution_limit` config variable.
///
/// # Parameters
/// - `handle`: Valid wallet handle
///
/// # Returns
/// - `Success` rotation passed
/// - Error code on other failures
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_client_rotation(handle: *mut WalletHandle) -> WalletFfiError {
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

    match block_on(wallet.client_rotation()) {
        Ok(()) => WalletFfiError::Success,
        Err(e) => {
            print_error(format!("Rotation failed: {e:?}"));
            WalletFfiError::NetworkError
        }
    }
}

/// Get `callibration_limit` config var.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `callibration_limit`: Valid pointer into `usize`
///
/// # Returns
/// - `Success` if config fetched successfully
/// - Error code on other failures
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `callibration_limit` must be a non-null pointer into `usize`
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_get_callibration_limit(
    handle: *mut WalletHandle,
    callibration_limit: *mut usize,
) -> WalletFfiError {
    if callibration_limit.is_null() {
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

    *callibration_limit = wallet
        .config()
        .multi_sequencer_client_config
        .calibration_limit;

    WalletFfiError::Success
}

/// Get `distribution_limit` config var.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `distribution_limit`: Valid pointer into `usize`
///
/// # Returns
/// - `Success` if config fetched successfully
/// - Error code on other failures
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `distribution_limit` must be a non-null pointer into `usize`
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_get_distribution_limit(
    handle: *mut WalletHandle,
    distribution_limit: *mut usize,
) -> WalletFfiError {
    if distribution_limit.is_null() {
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

    *distribution_limit = wallet
        .config()
        .multi_sequencer_client_config
        .distribution_limit;

    WalletFfiError::Success
}

/// Set `callibration_limit` config var.
///
/// For changes to be applied, execute `wallet_ffi_client_rotation`.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `callibration_limit`: `usize`
///
/// # Returns
/// - `Success` if config updated successfully
/// - Error code on other failures
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_set_callibration_limit(
    handle: *mut WalletHandle,
    callibration_limit: usize,
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

    wallet
        .config_mut()
        .multi_sequencer_client_config
        .calibration_limit = callibration_limit;

    WalletFfiError::Success
}

/// Get `distribution_limit` config var.
///  
/// For changes to be applied, execute `wallet_ffi_client_rotation`.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `distribution_limit`: `usize`
///
/// # Returns
/// - `Success` if config updated successfully
/// - Error code on other failures
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_set_distribution_limit(
    handle: *mut WalletHandle,
    distribution_limit: usize,
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

    wallet
        .config_mut()
        .multi_sequencer_client_config
        .distribution_limit = distribution_limit;

    WalletFfiError::Success
}

/// Remove sequencer from the list.
///  
/// For changes to be applied, execute `wallet_ffi_client_rotation`.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `addr`: C-compatible string, representing an URL address of the sequencer.
///
/// # Returns
/// - `Success` if removal passed
/// - Error code on other failures
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `addr` must be a non-null C-compatible string.
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_remove_sequencer(
    handle: *mut WalletHandle,
    addr: *const c_char,
) -> WalletFfiError {
    if addr.is_null() {
        return WalletFfiError::NullPointer;
    }

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

    let addr_string = match c_str_to_string(addr, "sequencer address") {
        Ok(a) => a,
        Err(e) => {
            print_error(format!("Failed to parse sequencer address: {e:?}"));
            return WalletFfiError::InternalError;
        }
    };

    let url_addr = match addr_string.parse() {
        Ok(u) => u,
        Err(e) => {
            print_error(format!("Failed to parse sequencer address into URL: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    match wallet.remove_sequencer(&url_addr) {
        Ok(()) => {}
        Err(e) => {
            print_error(format!("Failed to remove sequencer: {e}"));
            return WalletFfiError::InternalError;
        }
    }

    WalletFfiError::Success
}

/// Add sequencer to the list.
///  
/// For changes to be applied, execute `wallet_ffi_client_rotation`.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `addr`: C-compatible string, representing an URL address of the sequencer.
/// - `user`: C-compatible string, representing a name of a user, can be `nullptr`.
/// - `password`: C-compatible string, representing a password, can be `nullptr`.
///
/// # Returns
/// - `Success` if addition passed
/// - Error code on other failures
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `addr` must be a non-null C-compatible string.
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_add_sequencer(
    handle: *mut WalletHandle,
    addr: *const c_char,
    user: *const c_char,
    password: *const c_char,
) -> WalletFfiError {
    if addr.is_null() {
        return WalletFfiError::NullPointer;
    }

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

    let addr_string = match c_str_to_string(addr, "sequencer address") {
        Ok(a) => a,
        Err(e) => {
            print_error(format!("Failed to parse sequencer address: {e:?}"));
            return WalletFfiError::InternalError;
        }
    };

    let url_addr = match addr_string.parse() {
        Ok(u) => u,
        Err(e) => {
            print_error(format!("Failed to parse sequencer address into URL: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    let basic_auth = if user.is_null() {
        None
    } else {
        let user_str = match c_str_to_string(user, "sequencer username") {
            Ok(a) => a,
            Err(e) => {
                print_error(format!("Failed to parse username: {e:?}"));
                return WalletFfiError::InternalError;
            }
        };

        if password.is_null() {
            Some(BasicAuth {
                username: user_str,
                password: None,
            })
        } else {
            let pass_str = match c_str_to_string(password, "sequencer password") {
                Ok(a) => a,
                Err(e) => {
                    print_error(format!("Failed to parse username: {e:?}"));
                    return WalletFfiError::InternalError;
                }
            };

            Some(BasicAuth {
                username: user_str,
                password: Some(pass_str),
            })
        }
    };

    let conn_data = SequencerConnectionData {
        sequencer_addr: url_addr,
        basic_auth,
    };

    wallet.add_sequencer(conn_data);

    WalletFfiError::Success
}
