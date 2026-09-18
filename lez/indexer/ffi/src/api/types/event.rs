use indexer_service_protocol::EventRecord;

use crate::api::types::{
    FfiBlockId, FfiHashType, FfiProgramId, FfiSelector, FfiVec, vectors::FfiVecU8,
};

#[repr(C)]
pub struct FfiEventRecord {
    pub block_id: FfiBlockId,
    pub tx_index: u32,
    pub tx_hash: FfiHashType,
    pub program_id: FfiProgramId,
    pub selector: FfiSelector,
    pub data: FfiVecU8,
}

impl From<EventRecord> for FfiEventRecord {
    fn from(value: EventRecord) -> Self {
        let EventRecord {
            block_id,
            tx_index,
            tx_hash,
            program_id,
            selector,
            data,
        } = value;

        Self {
            block_id,
            tx_index,
            tx_hash: tx_hash.into(),
            program_id: program_id.into(),
            selector: selector.into(),
            data: data.into(),
        }
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
pub unsafe extern "C" fn free_ffi_event_record_vec(val: *mut FfiVec<FfiEventRecord>) {
    if val.is_null() {
        log::error!("Trying to free a null pointer. Exiting");
        return;
    }
    let ffi_vec = unsafe { Box::from_raw(val) };
    let records: Vec<FfiEventRecord> = (*ffi_vec).into();
    for record in records {
        drop(Vec::from(record.data));
    }
}
