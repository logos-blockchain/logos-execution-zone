use crate::{
    block_on,
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
/// - `Success` if deployment was submitted successfully
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
/// - `Success` if deployment was submitted successfully
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
/// - `Success` if deployment was submitted successfully
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
/// - `Success` if deployment was submitted successfully
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
/// - `Success` if deployment was submitted successfully
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
