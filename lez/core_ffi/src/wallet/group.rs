//! Shared accounts management functions.

use std::{
    ffi::{CString, c_char},
    str::FromStr as _,
};

use key_protocol::key_management::{
    group_key_holder::{GroupKeyHolder, SealingPublicKey},
    secret_holders::ViewingSecretKey,
};
use wallet::account::Label;

use crate::{
    error::{FfiOperationError, print_error},
    wallet::{WalletHandle, c_str_to_string, lifecycle::get_wallet},
};

/// Create new shared account at given label.
///
/// # Parameters
/// - `handle`: Valid wallet handle,
/// - `label_c`: null terminated C string.
///
/// # Returns
/// - `Success` on successful creation, error otherwise.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`
/// - `label` must be a valid C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_ffi_create_new_shared_account(
    handle: *mut WalletHandle,
    label_c: *const c_char,
) -> FfiOperationError {
    let wrapper = match get_wallet(handle) {
        Ok(w) => w,
        Err(e) => return e,
    };

    let label_raw = match c_str_to_string(label_c, "label") {
        Ok(value) => value,
        Err(e) => return e,
    };

    let label = Label::new(label_raw);

    if label.validate_for_account().is_err() {
        print_error("Label can not contain `@`, `:` and `/` characters");
        return FfiOperationError::InvalidArgument;
    }

    let mut wallet = match wrapper.core.lock() {
        Ok(w) => w,
        Err(e) => {
            print_error(format!("Failed to lock wallet: {e}"));
            return FfiOperationError::InternalError;
        }
    };

    if wallet
        .storage()
        .key_chain()
        .group_key_holder(&label)
        .is_some()
    {
        print_error("Label already in use");
        return FfiOperationError::InvalidArgument;
    }

    let holder = GroupKeyHolder::new();
    wallet.insert_group_key_holder(label, holder, true);
    match wallet.store_persistent_data() {
        Ok(()) => FfiOperationError::Success,
        Err(e) => {
            print_error(format!("Failed to save wallet: {e}"));
            FfiOperationError::StorageError
        }
    }
}

/// Create unique wallet sealing key for shared accounts. Mandatory operation for shared accounts
/// usage.
///
/// # Parameters
/// - `handle`: Valid wallet handle.
/// - `out_sealing_public_key`: valid pointer into C-compatible string.
///
/// # Returns
/// - `Success` on successful creation, error otherwise.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_ffi_create_sealing_key(
    handle: *mut WalletHandle,
    out_sealing_public_key: *mut *mut c_char,
) -> FfiOperationError {
    if out_sealing_public_key.is_null() {
        print_error("Null pointer for out_sealing_public_key, reverting");
        return FfiOperationError::NullPointer;
    }

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

    if wallet.storage().key_chain().sealing_secret_key().is_some() {
        print_error("Can be only one sealing key");
        return FfiOperationError::Unapplicable;
    }

    let mut d = [0_u8; 32];
    let mut r = [0_u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut d);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut r);
    let secret = ViewingSecretKey::new(d, r);

    let ek_bytes = lee_core::encryption::ViewingPublicKey::from_seed(&d, &r)
        .to_bytes()
        .to_vec();
    let public_key = SealingPublicKey::from_bytes(ek_bytes);

    let public_key_hex = hex::encode(public_key.to_bytes());

    let Ok(public_key_hex_c) = CString::from_str(public_key_hex.as_ref()) else {
        print_error(format!(
            "Failed to cast public_key_hex into C string: {public_key_hex}"
        ));
        return FfiOperationError::InternalError;
    };

    let public_key_hex_c_raw = public_key_hex_c.into_raw();

    wallet.set_sealing_secret_key(secret);

    unsafe {
        *out_sealing_public_key = public_key_hex_c_raw;
    }

    match wallet.store_persistent_data() {
        Ok(()) => FfiOperationError::Success,
        Err(e) => {
            print_error(format!("Failed to save wallet: {e}"));
            FfiOperationError::StorageError
        }
    }
}

/// Invite user into shared account by its sealing public key.
///
/// # Parameters
/// - `handle`: Valid wallet handle.
/// - `key`: recipient's sealing public key as C-compatible hex string.
/// - `label_c`: label of a shared account as C-compatible string.
/// - `out_sealed_message`: output pointer into C-compatible hex encoded sealed message.
///
/// # Returns
/// - `Success` on successful creation of a `sealed_message`, error otherwise.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`.
/// - `out_sealed_message` must be non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_ffi_invite_shared_account(
    handle: *mut WalletHandle,
    key: *const c_char,
    label_c: *const c_char,
    out_sealed_message: *mut *mut c_char,
) -> FfiOperationError {
    if out_sealed_message.is_null() {
        print_error("Null pointer for out_sealed_message, reverting");
        return FfiOperationError::NullPointer;
    }

    let key_enc = match c_str_to_string(key, "sealing_public_key") {
        Ok(value) => value,
        Err(e) => return e,
    };

    let Ok(key_dec) = hex::decode(key_enc) else {
        print_error("Failed to decode key");
        return FfiOperationError::InvalidHex;
    };

    let label_raw = match c_str_to_string(label_c, "label") {
        Ok(value) => value,
        Err(e) => return e,
    };

    let label = Label::new(label_raw);

    let recipient_key =
        key_protocol::key_management::group_key_holder::SealingPublicKey::from_bytes(key_dec);

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

    let Some(holder) = wallet.storage().key_chain().group_key_holder(&label) else {
        print_error(format!("Label {label} not found"));
        return FfiOperationError::InvalidArgument;
    };

    let sealed = holder.seal_for(&recipient_key);

    let sealed_hex = hex::encode(sealed);

    let Ok(sealed_hex_c) = CString::from_str(sealed_hex.as_ref()) else {
        print_error(format!(
            "Failed to cast sealed_hex into C string: {sealed_hex}"
        ));
        return FfiOperationError::InternalError;
    };

    let sealed_hex_c_raw = sealed_hex_c.into_raw();

    unsafe {
        *out_sealed_message = sealed_hex_c_raw;
    }

    match wallet.store_persistent_data() {
        Ok(()) => FfiOperationError::Success,
        Err(e) => {
            print_error(format!("Failed to save wallet: {e}"));
            FfiOperationError::StorageError
        }
    }
}

/// Join into shared account using sealing message.
///
/// # Parameters
/// - `handle`: Valid wallet handle.
/// - `sealed_message`: senders' sealing message as C-compatible hex string.
/// - `label_c`: label of a shared account as C-compatible string.
///
/// # Returns
/// - `Success` on successful joining, error otherwise.
///
/// # Safety
/// - `handle` must be a valid wallet handle from `wallet_ffi_create_new` or `wallet_ffi_open`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wallet_ffi_join_shared_account(
    handle: *mut WalletHandle,
    sealed_message: *const c_char,
    label_c: *const c_char,
) -> FfiOperationError {
    let sealed_message_enc = match c_str_to_string(sealed_message, "sealed_message") {
        Ok(value) => value,
        Err(e) => return e,
    };

    let Ok(sealed_message_dec) = hex::decode(sealed_message_enc) else {
        print_error("Failed to decode sealed_message");
        return FfiOperationError::InvalidHex;
    };

    let label_raw = match c_str_to_string(label_c, "label") {
        Ok(value) => value,
        Err(e) => return e,
    };

    let label = Label::new(label_raw);

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

    if wallet
        .storage()
        .key_chain()
        .group_key_holder(&label)
        .is_some()
    {
        print_error("Group key holder for this label already exists");
        return FfiOperationError::InvalidArgument;
    }

    let Some(sealing_key) = wallet.storage().key_chain().sealing_secret_key() else {
        print_error("Sealing key must exist before joining");
        return FfiOperationError::InternalError;
    };

    let holder = match GroupKeyHolder::unseal(&sealed_message_dec, sealing_key) {
        Ok(gkh) => gkh,
        Err(e) => {
            print_error(format!("Failed to unseal the message: {e:?}"));
            return FfiOperationError::InternalError;
        }
    };

    wallet.insert_group_key_holder(label, holder, false);

    match wallet.store_persistent_data() {
        Ok(()) => FfiOperationError::Success,
        Err(e) => {
            print_error(format!("Failed to save wallet: {e}"));
            FfiOperationError::StorageError
        }
    }
}
