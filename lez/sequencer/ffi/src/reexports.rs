///! Re-exports to include our free functions in the final header.

use std::ffi::{c_char};

use primitives_ffi::types::{FfiOption, FfiVec, account::FfiAccount, block::{FfiBlock, FfiBlockOpt}, event::FfiEventRecord, transaction::FfiTransaction};

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

/// Frees the resources associated with the given ffi account.
///
/// Takes ownership of the whole allocation produced by a `query_*` call: the
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn primitives_ffi_free_ffi_account(val: *mut FfiAccount) {
    unsafe{
        primitives_ffi::types::account::primitives_ffi_free_ffi_account(val)
    }
}

/// Frees the resources owned by an `FfiBlock` value.
///
/// This frees the block's transaction bodies (the only heap-owning field); the
/// header/status fields are `Copy`. It operates on the struct by value because
/// it is an element-level helper, used both for the vector path
/// ([`free_ffi_block_vec`]) and the optional path ([`free_ffi_block_opt`]) — in
/// neither case is an `FfiBlock` itself wrapped in its own outer box.
///
/// # Arguments
///
/// - `val`: An instance of `FfiBlock`.
///
/// # Returns
///
/// void.
///
/// # Safety
///
/// The caller must ensure that:
/// - `val` is a valid instance of `FfiBlock` produced by this library and not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn primitives_ffi_free_ffi_block(val: FfiBlock) {
    unsafe{
        primitives_ffi::types::block::primitives_ffi_free_ffi_block(val)
    }
}

/// Frees the resources associated with the given ffi block option.
///
/// Takes ownership of the whole allocation produced by a `query_*` call: the
/// outer `Box<FfiBlockOpt>` (the `PointerResult.value` pointer), the inner
/// `Box<FfiBlock>` (when present), and that block's transaction bodies.
///
/// # Arguments
///
/// - `val`: The `*mut FfiBlockOpt` returned in `PointerResult.value`.
///
/// # Returns
///
/// void.
///
/// # Safety
///
/// The caller must ensure that:
/// - `val` is a pointer to an `FfiBlockOpt` produced by this library and not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn primitives_ffi_free_ffi_block_opt(val: *mut FfiBlockOpt) {
    unsafe{
        primitives_ffi::types::block::primitives_ffi_free_ffi_block_opt(val)
    }
}

/// Frees the resources associated with the given ffi block vector.
///
/// Takes ownership of the whole allocation produced by a `query_*` call: the
/// outer `Box<FfiVec<FfiBlock>>` (the `PointerResult.value` pointer), the
/// vector's backing buffer, and every block within it.
///
/// # Arguments
///
/// - `val`: The `*mut FfiVec<FfiBlock>` returned in `PointerResult.value`.
///
/// # Returns
///
/// void.
///
/// # Safety
///
/// The caller must ensure that:
/// - `val` is a pointer to an `FfiVec<FfiBlock>` produced by this library and not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn primitives_ffi_free_ffi_block_vec(val: *mut FfiVec<FfiBlock>) {
    unsafe{
        primitives_ffi::types::block::primitives_ffi_free_ffi_block_vec(val)
    }
}

/// Frees the resources associated with the given vector of ffi event records.
///
/// Takes ownership of the whole allocation produced by `query_events`: the outer
/// `Box<FfiVec<FfiEventRecord>>` (the `PointerResult.value` pointer), the vector's
/// backing buffer, and every record's payload within it.
///
/// # Arguments
///
/// - `val`: The `*mut FfiVec<FfiEventRecord>` returned in `PointerResult.value`.
///
/// # Returns
///
/// void.
///
/// # Safety
///
/// The caller must ensure that:
/// - `val` is a pointer to an `FfiVec<FfiEventRecord>` produced by this library and not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn primitives_ffi_free_ffi_event_record_vec(val: *mut FfiVec<FfiEventRecord>) {
    unsafe{
        primitives_ffi::types::event::primitives_ffi_free_ffi_event_record_vec(val)
    }
}

/// Frees the resources associated with the given ffi transaction.
///
/// # Arguments
///
/// - `val`: An instance of `FfiTransaction`.
///
/// # Returns
///
/// void.
///
/// # Safety
///
/// The caller must ensure that:
/// - `val` is a valid instance of `FfiTransaction`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn primitives_ffi_free_ffi_transaction(val: FfiTransaction) {
    unsafe {
        primitives_ffi::types::transaction::primitives_ffi_free_ffi_transaction(val)
    }
}

/// Frees the resources associated with the given ffi transaction option.
///
/// Takes ownership of the whole allocation produced by a `query_*` call: the
/// outer `Box<FfiOption<FfiTransaction>>` (the `PointerResult.value` pointer),
/// the inner `Box<FfiTransaction>` (when present), and its body.
///
/// # Arguments
///
/// - `val`: The `*mut FfiOption<FfiTransaction>` returned in `PointerResult.value`.
///
/// # Returns
///
/// void.
///
/// # Safety
///
/// The caller must ensure that:
/// - `val` is a pointer to an `FfiOption<FfiTransaction>` produced by this library and not yet
///   freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn primitives_ffi_free_ffi_transaction_opt(
    val: *mut FfiOption<FfiTransaction>,
) {
    unsafe {
        primitives_ffi::types::transaction::primitives_ffi_free_ffi_transaction_opt(val)
    }
}

/// Frees the resources associated with the given vector of ffi transactions.
///
/// Takes ownership of the whole allocation produced by a `query_*` call: the
/// outer `Box<FfiVec<FfiTransaction>>` (the `PointerResult.value` pointer), the
/// vector's backing buffer, and every transaction within it.
///
/// # Arguments
///
/// - `val`: The `*mut FfiVec<FfiTransaction>` returned in `PointerResult.value`.
///
/// # Returns
///
/// void.
///
/// # Safety
///
/// The caller must ensure that:
/// - `val` is a pointer to an `FfiVec<FfiTransaction>` produced by this library and not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn primitives_ffi_free_ffi_transaction_vec(val: *mut FfiVec<FfiTransaction>) {
    unsafe {
        primitives_ffi::types::transaction::primitives_ffi_free_ffi_transaction_vec(val)
    }
}