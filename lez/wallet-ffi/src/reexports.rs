use std::ffi::c_char;

use primitives_ffi::types::{FfiPrivateAccountKeys, account::FfiAccount};

/// # Safety
/// It's up to the caller to pass a proper pointer, if somehow from c/c++ side
/// this is called with a type which doesn't come from a returned `CString` it
/// will cause a segfault.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn primitives_ffi_free_cstring(block: *mut c_char) {
    unsafe{
        primitives_ffi::memory::primitives_ffi_free_cstring(block)
    }
}

/// Free private account keys returned by `wallet_ffi_get_private_account_keys`.
///
/// # Safety
/// The keys must be either null or valid keys returned by
/// `wallet_ffi_get_private_account_keys`.
#[no_mangle]
pub unsafe extern "C" fn wallet_ffi_free_private_account_keys(keys: *mut FfiPrivateAccountKeys) {
    unsafe{ primitives_ffi::types::primitives_ffi_free_private_account_keys(keys); }
}

/// Frees the resources associated with the given ffi account.
///
/// Takes ownership of the whole allocation: the
/// outer `Box<FfiAccount>` (the `PointerResult.value` pointer) *and* its inner
/// data buffer. Passing the struct by value previously freed only the inner
/// buffer and leaked the outer box.
///
/// # Arguments
///
/// - `val`: The `*mut FfiAccount` returned in `PointerResult.value`.
///
/// # Returns
///
/// void.
///
/// # Safety
///
/// The caller must ensure that:
/// - `val` is a pointer to an `FfiAccount` produced by this library and not yet freed.
pub unsafe fn primitives_ffi_free_ffi_account(val: *mut FfiAccount) {
    unsafe{ primitives_ffi::types::account::primitives_ffi_free_ffi_account(val) };
}