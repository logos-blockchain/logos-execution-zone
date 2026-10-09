use common::block::{BedrockStatus, Block, BlockHeader};

use crate::primitives::{
    errors::PrimitiveOperationStatus,
    types::{
        FfiBlockId, FfiHashType, FfiOption, FfiTimestamp, FfiVec,
        transaction::primitives_ffi_free_transaction_vec_value, vectors::FfiBlockBody,
    },
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

impl TryFrom<FfiBlock> for Block {
    type Error = PrimitiveOperationStatus;

    fn try_from(value: FfiBlock) -> Result<Self, Self::Error> {
        let FfiBlock {
            header,
            body,
            bedrock_status,
        } = value;

        let mut std_vec = Vec::with_capacity(body.capacity);
        let std_vec_ffi_body: Vec<_> = body.into();

        for ffi_tx in std_vec_ffi_body {
            std_vec.push(ffi_tx.try_into()?)
        }

        Ok(Self {
            header: header.into(),
            bedrock_status: bedrock_status.into(),
            body: common::block::BlockBody {
                transactions: std_vec,
            },
        })
    }
}

pub type FfiBlockOpt = FfiOption<FfiBlock>;

#[repr(C)]
pub struct FfiBlockHeader {
    pub block_id: FfiBlockId,
    pub prev_block_hash: FfiHashType,
    pub hash: FfiHashType,
    pub timestamp: FfiTimestamp,
}

impl From<BlockHeader> for FfiBlockHeader {
    fn from(value: BlockHeader) -> Self {
        let BlockHeader {
            block_id,
            prev_block_hash,
            hash,
            timestamp,
        } = value;

        Self {
            block_id,
            prev_block_hash: prev_block_hash.into(),
            hash: hash.into(),
            timestamp,
        }
    }
}

impl From<FfiBlockHeader> for BlockHeader {
    fn from(value: FfiBlockHeader) -> Self {
        let FfiBlockHeader {
            block_id,
            prev_block_hash,
            hash,
            timestamp,
        } = value;

        Self {
            block_id,
            prev_block_hash: prev_block_hash.into(),
            hash: hash.into(),
            timestamp,
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
pub unsafe extern "C" fn primitives_ffi_free_ffi_block(val: FfiBlock) {
    let ffi_tx_ffi_vec = val.body;

    primitives_ffi_free_transaction_vec_value(ffi_tx_ffi_vec);
}

/// Frees the resources associated with the given ffi block option.
///
/// Takes ownership of the whole allocation: the
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
    if val.is_null() {
        log::error!("Trying to free a null pointer. Exiting");
        return;
    }
    // Reclaim the outer box, then the inner block box (if any).
    let opt = unsafe { Box::from_raw(val) };
    if opt.is_some {
        let block = unsafe { Box::from_raw(opt.value) };
        unsafe {
            primitives_ffi_free_ffi_block(*block);
        }
    }
}

/// Frees the resources associated with the given ffi block vector.
///
/// Takes ownership of the whole allocation: the
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
    if val.is_null() {
        log::error!("Trying to free a null pointer. Exiting");
        return;
    }
    // Reclaim the outer box, then the backing buffer and each block.
    let boxed = unsafe { Box::from_raw(val) };
    let ffi_block_std_vec: Vec<_> = (*boxed).into();
    for block in ffi_block_std_vec {
        unsafe {
            primitives_ffi_free_ffi_block(block);
        }
    }
}
