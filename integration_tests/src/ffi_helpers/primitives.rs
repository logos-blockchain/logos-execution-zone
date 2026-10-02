use std::ffi::c_char;

use primitives_ffi::types::{
    FfiOption, FfiPrivateAccountKeys, FfiVec,
    account::FfiAccount,
    block::{FfiBlock, FfiBlockOpt},
    event::FfiEventRecord,
    transaction::FfiTransaction,
};

unsafe extern "C" {
    pub unsafe fn primitives_ffi_free_private_account_keys(keys: *mut FfiPrivateAccountKeys);
    pub unsafe fn primitives_ffi_free_cstring(block: *mut c_char);
    pub unsafe fn primitives_ffi_free_ffi_account(val: *mut FfiAccount);
    pub unsafe fn primitives_ffi_free_ffi_block(val: FfiBlock);
    pub unsafe fn primitives_ffi_free_ffi_block_opt(val: *mut FfiBlockOpt);
    pub unsafe fn primitives_ffi_free_ffi_block_vec(val: *mut FfiVec<FfiBlock>);
    pub unsafe fn primitives_ffi_free_ffi_event_record_vec(val: *mut FfiVec<FfiEventRecord>);
    pub unsafe fn primitives_ffi_free_ffi_transaction(val: FfiTransaction);
    pub unsafe fn primitives_ffi_free_ffi_transaction_opt(val: *mut FfiOption<FfiTransaction>);
    pub unsafe fn primitives_ffi_free_ffi_transaction_vec(val: *mut FfiVec<FfiTransaction>);
}
