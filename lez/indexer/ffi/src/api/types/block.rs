use ffi_core::api::types::{FfiBlockId, FfiHashType, FfiOption, FfiSignature, FfiTimestamp, FfiVec};
use indexer_service_protocol::{BedrockStatus, Block, BlockHeader, HashType, Signature};

use crate::api::types::{
    transaction::free_transaction_vec_value, vectors::FfiBlockBody,
};

#[repr(C)]
pub struct FfiBlock {
    pub header: FfiBlockHeader,
    pub body: FfiBlockBody,
    pub bedrock_status: FfiBedrockStatus,
}

impl From<Block> for FfiBlock {
    fn from(value: Block) -> Self {
        let Block {
            header,
            body,
            bedrock_status,
        } = value;

        Self {
            header: header.into(),
            body: body
                .transactions
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            bedrock_status: bedrock_status.into(),
        }
    }
}

pub type FfiBlockOpt = FfiOption<FfiBlock>;

#[repr(C)]
pub struct FfiBlockHeader {
    pub block_id: FfiBlockId,
    pub prev_block_hash: FfiHashType,
    pub hash: FfiHashType,
    pub timestamp: FfiTimestamp,
    pub signature: FfiSignature,
}

impl From<BlockHeader> for FfiBlockHeader {
    fn from(value: BlockHeader) -> Self {
        let BlockHeader {
            block_id,
            prev_block_hash,
            hash,
            timestamp,
            signature,
        } = value;

        Self {
            block_id,
            prev_block_hash: prev_block_hash.into(),
            hash: hash.into(),
            timestamp,
            signature: signature.into(),
        }
    }
}

#[repr(C)]
pub enum FfiBedrockStatus {
    Pending = 0x0,
    Safe,
    Finalized,
}

impl From<BedrockStatus> for FfiBedrockStatus {
    fn from(value: BedrockStatus) -> Self {
        match value {
            BedrockStatus::Finalized => Self::Finalized,
            BedrockStatus::Pending => Self::Pending,
            BedrockStatus::Safe => Self::Safe,
        }
    }
}

impl From<FfiBedrockStatus> for BedrockStatus {
    fn from(value: FfiBedrockStatus) -> Self {
        match value {
            FfiBedrockStatus::Finalized => Self::Finalized,
            FfiBedrockStatus::Pending => Self::Pending,
            FfiBedrockStatus::Safe => Self::Safe,
        }
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
pub unsafe extern "C" fn free_ffi_block(val: FfiBlock) {
    // We don't really need all the casts, but just in case
    // All except `ffi_tx_ffi_vec` is Copy types, so no need for Drop
    let _ = BlockHeader {
        block_id: val.header.block_id,
        prev_block_hash: HashType(val.header.prev_block_hash.data),
        hash: HashType(val.header.hash.data),
        timestamp: val.header.timestamp,
        signature: Signature(val.header.signature.data),
    };
    let ffi_tx_ffi_vec = val.body;

    #[expect(clippy::let_underscore_must_use, reason = "No use for this Copy type")]
    let _: BedrockStatus = val.bedrock_status.into();

    free_transaction_vec_value(ffi_tx_ffi_vec);
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
pub unsafe extern "C" fn free_ffi_block_opt(val: *mut FfiBlockOpt) {
    if val.is_null() {
        log::error!("Trying to free a null pointer. Exiting");
        return;
    }
    // Reclaim the outer box, then the inner block box (if any).
    let opt = unsafe { Box::from_raw(val) };
    if opt.is_some {
        let block = unsafe { Box::from_raw(opt.value) };
        unsafe {
            free_ffi_block(*block);
        }
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
pub unsafe extern "C" fn free_ffi_block_vec(val: *mut FfiVec<FfiBlock>) {
    if val.is_null() {
        log::error!("Trying to free a null pointer. Exiting");
        return;
    }
    // Reclaim the outer box, then the backing buffer and each block.
    let boxed = unsafe { Box::from_raw(val) };
    let ffi_block_std_vec: Vec<_> = (*boxed).into();
    for block in ffi_block_std_vec {
        unsafe {
            free_ffi_block(block);
        }
    }
}
