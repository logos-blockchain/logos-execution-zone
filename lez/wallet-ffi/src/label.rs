use std::{
    ffi::{c_char, CString},
    str::FromStr as _,
};

use crate::{
    c_str_to_string,
    error::{print_error, WalletFfiError},
    wallet::get_wallet,
    FfiAccountIdWithPrivacy, WalletHandle,
};

#[repr(C)]
pub struct LabelAvailability {
    pub is_available: bool,
    pub error: WalletFfiError,
}

impl LabelAvailability {
    #[must_use]
    pub const fn availability(is_available: bool) -> Self {
        Self {
            is_available,
            error: WalletFfiError::Success,
        }
    }

    #[must_use]
    pub const fn error(error: WalletFfiError) -> Self {
        Self {
            is_available: false,
            error,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AccountIdResolvedFromLabel {
    pub account_id: FfiAccountIdWithPrivacy,
    pub error: WalletFfiError,
}

impl AccountIdResolvedFromLabel {
    #[must_use]
    pub const fn account_id(account_id: FfiAccountIdWithPrivacy) -> Self {
        Self {
            account_id,
            error: WalletFfiError::Success,
        }
    }

    #[must_use]
    pub fn error(error: WalletFfiError) -> Self {
        Self {
            account_id: FfiAccountIdWithPrivacy::default(),
            error,
        }
    }
}

#[repr(C)]
pub struct LabelList {
    pub labels_data: *mut *const c_char,
    pub labels_size: usize,
    pub error: WalletFfiError,
}

impl LabelList {
    #[must_use]
    pub fn from_labels(labels: Vec<*const c_char>) -> Self {
        let labels_size = labels.len();
        let boxed_slice = labels.into_boxed_slice();
        let labels_data = Box::into_raw(boxed_slice).cast::<*const c_char>();

        Self {
            labels_data,
            labels_size,
            error: WalletFfiError::Success,
        }
    }

    #[must_use]
    pub const fn error(error: WalletFfiError) -> Self {
        Self {
            labels_data: std::ptr::null_mut(),
            labels_size: 0,
            error,
        }
    }
}

/// Check if label is available.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `label`: Input null terminated C string for a label
///
/// # Returns
/// - `LabelAvailability` struct
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `label` must be a valid pointer to a null-terminated C string
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_check_label_available(
    handle: *mut WalletHandle,
    label: *const c_char,
) -> LabelAvailability {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return LabelAvailability::error(e),
    };

    let label = match c_str_to_string(label, "label") {
        Ok(value) => value,
        Err(e) => return LabelAvailability::error(e),
    };

    let wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return LabelAvailability::error(WalletFfiError::InternalError);
        }
    };

    let is_available = wallet
        .storage()
        .check_label_availability(&label.into())
        .is_ok();

    LabelAvailability::availability(is_available)
}

/// Add new label.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `label`: Input null terminated C string for a label
/// - `account_id_with_privacy`: The account ID (32 bytes) and its privacy.
///
/// # Returns
/// - `Success` on successful query
/// - Error code on failure
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `label` must be a valid pointer to a null-terminated C string
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_add_label(
    handle: *mut WalletHandle,
    label: *const c_char,
    account_id_with_privacy: FfiAccountIdWithPrivacy,
) -> WalletFfiError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    let label = match c_str_to_string(label, "label") {
        Ok(value) => value,
        Err(e) => return e,
    };

    let mut wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return WalletFfiError::InternalError;
        }
    };

    match wallet
        .storage_mut()
        .add_label(label.into(), account_id_with_privacy.into())
    {
        Ok(()) => WalletFfiError::Success,
        Err(err) => {
            print_error(format!("Failed to add label : {err}"));
            WalletFfiError::InternalError
        }
    }
}

/// Resolve a label.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `label`: Input null terminated C string for a label
///
/// # Returns
/// - `AccountIdResolvedFromLabel` struct
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `label` must be a valid pointer to a null-terminated C string
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_resolve_label(
    handle: *mut WalletHandle,
    label: *const c_char,
) -> AccountIdResolvedFromLabel {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return AccountIdResolvedFromLabel::error(e),
    };

    let label = match c_str_to_string(label, "label") {
        Ok(value) => value,
        Err(e) => return AccountIdResolvedFromLabel::error(e),
    };

    let mut wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return AccountIdResolvedFromLabel::error(WalletFfiError::InternalError);
        }
    };

    wallet
        .storage_mut()
        .resolve_label(&label.into())
        .map_or_else(
            || {
                print_error("Failed to resolve label");
                AccountIdResolvedFromLabel::error(WalletFfiError::InternalError)
            },
            |acc_id| AccountIdResolvedFromLabel::account_id(acc_id.into()),
        )
}

/// Get all labels for account.
///
/// # Parameters
/// - `handle`: Valid wallet handle
/// - `account_id_with_privacy`: The account ID (32 bytes) and its privacy.
///
/// # Returns
/// - `LabelList` struct
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_get_all_labels_for_account(
    handle: *mut WalletHandle,
    account_id_with_privacy: FfiAccountIdWithPrivacy,
) -> LabelList {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return LabelList::error(e),
    };

    let wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return LabelList::error(WalletFfiError::InternalError);
        }
    };

    let mut labels = vec![];

    for label in wallet
        .storage()
        .labels_for_account(account_id_with_privacy.into())
    {
        let Ok(label_c) = CString::from_str(label.as_ref()) else {
            print_error(format!("Failed to cast label into C string: {label}"));
            return LabelList::error(WalletFfiError::InternalError);
        };

        let label_raw = label_c.into_raw().cast_const();

        labels.push(label_raw);
    }

    LabelList::from_labels(labels)
}

/// Free label list.
///
/// # Parameters
/// - `label_list`: Input list of labels
///
/// # Returns
/// - `Success` on successful query
/// - Error code on failure
///
/// # Safety
/// - `label_list` must be a valid pointer to `LabelList`, received from
///   `wallet_ffi_get_all_labels_for_account`
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_free_label_list(label_list: *mut LabelList) -> WalletFfiError {
    if label_list.is_null() {
        return WalletFfiError::NullPointer;
    }

    let labels_raw = unsafe { &*label_list };

    if !labels_raw.labels_data.is_null() && labels_raw.labels_size > 0 {
        let labels_slice =
            std::slice::from_raw_parts_mut(labels_raw.labels_data, labels_raw.labels_size);

        for label_ptr in labels_slice.iter() {
            if !(*label_ptr).is_null() {
                drop(CString::from_raw((*label_ptr).cast_mut()));
            }
        }

        let boxed_slice = Box::from_raw(std::ptr::from_mut::<[*const c_char]>(labels_slice));
        drop(boxed_slice);
    }

    WalletFfiError::Success
}
