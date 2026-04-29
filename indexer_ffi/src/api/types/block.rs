use indexer_service_protocol::{
    BedrockStatus, Block, BlockHeader, HashType, MantleMsgId, Signature,
};

use crate::api::types::{
    FfiBlockId, FfiHashType, FfiMsgId, FfiOption, FfiSignature, FfiTimestamp, FfiVec,
    transaction::free_ffi_transaction_vec, vectors::FfiBlockBody,
};

#[repr(C)]
pub struct FfiBlock {
    pub header: FfiBlockHeader,
    pub body: FfiBlockBody,
    pub bedrock_status: FfiBedrockStatus,
    pub bedrock_parent_id: FfiMsgId,
}

impl From<Block> for FfiBlock {
    fn from(value: Block) -> Self {
        Self {
            header: value.header.into(),
            body: value
                .body
                .transactions
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            bedrock_status: value.bedrock_status.into(),
            bedrock_parent_id: value.bedrock_parent_id.into(),
        }
    }
}

// impl From<Box<FfiBlock>> for Block {
//     fn from(value: Box<FfiBlock>) -> Self {
//         Self {
//             header: BlockHeader {
//                 block_id: value.header.block_id,
//                 prev_block_hash: HashType(value.header.prev_block_hash.data),
//                 hash: HashType(value.header.hash.data),
//                 timestamp: value.header.timestamp,
//                 signature: Signature(value.header.signature.data),
//             },
//             body: (),
//             bedrock_status: value.bedrock_status.into(),
//             bedrock_parent_id: MantleMsgId(value.bedrock_parent_id.data),
//         }
//     }
// }

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
        Self {
            block_id: value.block_id,
            prev_block_hash: value.prev_block_hash.into(),
            hash: value.hash.into(),
            timestamp: value.timestamp,
            signature: value.signature.into(),
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

/// Frees the resources associated with the given ffi block.
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
/// - `val` is a valid instance of `FfiBlock`.
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

    let _ = MantleMsgId(val.bedrock_parent_id.data);

    unsafe {
        free_ffi_transaction_vec(ffi_tx_ffi_vec);
    };
}

/// Frees the resources associated with the given ffi block option.
///
/// # Arguments
///
/// - `val`: An instance of `FfiBlockOpt`.
///
/// # Returns
///
/// void.
///
/// # Safety
///
/// The caller must ensure that:
/// - `val` is a valid instance of `FfiBlockOpt`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_ffi_block_opt(val: FfiBlockOpt) {
    if val.is_some {
        let value = unsafe { Box::from_raw(val.value) };

        // We don't really need all the casts, but just in case
        // All except `ffi_tx_ffi_vec` is Copy types, so no need for Drop
        let _ = BlockHeader {
            block_id: value.header.block_id,
            prev_block_hash: HashType(value.header.prev_block_hash.data),
            hash: HashType(value.header.hash.data),
            timestamp: value.header.timestamp,
            signature: Signature(value.header.signature.data),
        };
        let ffi_tx_ffi_vec = value.body;

        #[expect(clippy::let_underscore_must_use, reason = "No use for this Copy type")]
        let _: BedrockStatus = value.bedrock_status.into();

        let _ = MantleMsgId(value.bedrock_parent_id.data);

        unsafe {
            free_ffi_transaction_vec(ffi_tx_ffi_vec);
        };
    }
}

/// Frees the resources associated with the given ffi block vector.
///
/// # Arguments
///
/// - `val`: An instance of `FfiVec<FfiBlock>`.
///
/// # Returns
///
/// void.
///
/// # Safety
///
/// The caller must ensure that:
/// - `val` is a valid instance of `FfiVec<FfiBlock>`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_ffi_block_vec(val: FfiVec<FfiBlock>) {
    let ffi_block_std_vec: Vec<_> = val.into();
    for block in ffi_block_std_vec {
        unsafe {
            free_ffi_block(block);
        }
    }
}
