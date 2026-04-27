use crate::api::types::{
    FfiBlockId, FfiHashType, FfiMsgId, FfiSignature, FfiTimestamp, FfiVec,
    transaction::FfiTransaction,
};

#[repr(C)]
pub struct FfiBlock {
    pub header: FfiBlockHeader,
    pub body: FfiBlockBody,
    pub bedrock_status: FfiBedrockStatus,
    pub bedrock_parent_id: FfiMsgId,
}

#[repr(C)]
pub struct FfiBlockOpt {
    pub block: *const FfiBlock,
    pub is_some: bool,
}

pub type FfiBlockBody = FfiVec<FfiTransaction>;

#[repr(C)]
pub struct FfiBlockHeader {
    pub block_id: FfiBlockId,
    pub prev_block_hash: FfiHashType,
    pub hash: FfiHashType,
    pub timestamp: FfiTimestamp,
    pub signature: FfiSignature,
}

#[repr(C)]
pub enum FfiBedrockStatus {
    Pending = 0x0,
    Safe,
    Finalized,
}
