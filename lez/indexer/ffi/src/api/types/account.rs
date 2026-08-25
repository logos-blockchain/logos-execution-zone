use crate::api::types::{FfiBytes32, FfiProgramId, FfiU128, vectors::FfiSlotList};

/// A single program's slot inside an account.
///
/// Note: `balance` is a u128 value represented as a little-endian byte array
/// since C doesn't have native u128 support.
#[repr(C)]
pub struct FfiAccountSlot {
    pub program_id: FfiProgramId,
    /// Balance as little-endian [u8; 16].
    pub balance: FfiU128,
    /// Pointer to slot data bytes.
    pub data: *mut u8,
    /// Length of slot data.
    pub data_len: usize,
    /// Capacity of slot data.
    pub data_cap: usize,
}

/// Account data structure - C-compatible version of lee Account.
///
/// Note: `nonce` is a u128 value represented as a little-endian byte array
/// since C doesn't have native u128 support.
#[repr(C)]
pub struct FfiAccount {
    /// The account's occupied slots, one entry per program.
    pub slots: FfiSlotList,
    /// Nonce as little-endian [u8; 16].
    pub nonce: FfiU128,
}

// Helper functions to convert between Rust and FFI types

impl From<&lee::AccountId> for FfiBytes32 {
    fn from(id: &lee::AccountId) -> Self {
        Self::from_account_id(id)
    }
}

impl From<lee::Account> for FfiAccount {
    fn from(value: lee::Account) -> Self {
        let lee::Account { nonce, slots } = value;

        Self {
            slots: slots
                .into_iter()
                .map(|(program_id, slot)| {
                    let (data, data_len, data_cap) = slot.data.into_inner().into_raw_parts();

                    FfiAccountSlot {
                        program_id: FfiProgramId {
                            data: lee::ProgramId::from(program_id),
                        },
                        balance: slot.balance.into(),
                        data,
                        data_len,
                        data_cap,
                    }
                })
                .collect::<Vec<_>>()
                .into(),
            nonce: nonce.0.into(),
        }
    }
}

impl From<FfiAccount> for indexer_service_protocol::Account {
    fn from(value: FfiAccount) -> Self {
        let FfiAccount { slots, nonce } = value;

        Self {
            nonce: nonce.into(),
            slots: Vec::from(slots)
                .into_iter()
                .map(|slot| {
                    (
                        indexer_service_protocol::ProgramId(slot.program_id.data),
                        indexer_service_protocol::Slot {
                            balance: slot.balance.into(),
                            data: indexer_service_protocol::Data(unsafe {
                                Vec::from_raw_parts(slot.data, slot.data_len, slot.data_cap)
                            }),
                        },
                    )
                })
                .collect(),
        }
    }
}

impl From<&FfiAccount> for indexer_service_protocol::Account {
    fn from(value: &FfiAccount) -> Self {
        Self {
            nonce: value.nonce.into(),
            slots: (0..value.slots.len)
                .map(|index| {
                    let slot = unsafe { value.slots.get(index) };
                    (
                        indexer_service_protocol::ProgramId(slot.program_id.data),
                        indexer_service_protocol::Slot {
                            balance: slot.balance.into(),
                            data: indexer_service_protocol::Data(
                                unsafe { std::slice::from_raw_parts(slot.data, slot.data_len) }
                                    .to_vec(),
                            ),
                        },
                    )
                })
                .collect(),
        }
    }
}

/// Frees the resources associated with the given ffi account.
///
/// Takes ownership of the whole allocation produced by a `query_*` call: the
/// outer `Box<FfiAccount>` (the `PointerResult.value` pointer), its slot array
/// *and* every slot's data buffer. Passing the struct by value previously freed
/// only the inner buffer and leaked the outer box.
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
pub unsafe extern "C" fn free_ffi_account(val: *mut FfiAccount) {
    if val.is_null() {
        log::error!("Trying to free a null pointer. Exiting");
        return;
    }
    // Reclaim the outer box, then convert to drop the slot array and each slot's buffer.
    let boxed = unsafe { Box::from_raw(val) };
    let orig_val: indexer_service_protocol::Account = (*boxed).into();
    drop(orig_val);
}
