use indexer_service_protocol::{BedrockStatus, Block, BlockHeader};

use crate::api::types::{
    FfiBlockId, FfiHashType, FfiMsgId, FfiOption, FfiSignature, FfiTimestamp, vectors::FfiBlockBody,
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
