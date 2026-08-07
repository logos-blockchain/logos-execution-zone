use ffi_core::api::types::{FfiVec, transaction::FfiTransaction};

pub type FfiBlockBody = FfiVec<FfiTransaction>;
