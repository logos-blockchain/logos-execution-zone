use crate::api::types::{
    FfiAccountId, FfiBytes32, FfiHashType, FfiProgramId, FfiPublicKey, FfiSignature, account::FfiAccount, vectors::{
        FfiAccountIdList, FfiInstructionDataList, FfiNonceList, FfiPrivateActionList, FfiProgramDeploymentMessage, FfiProof, FfiPublicActionList, FfiSignaturePubKeyList, FfiVecU8,
    },
};

#[repr(C)]
pub struct FfiPublicTransactionBody {
    pub hash: FfiHashType,
    pub message: FfiPublicMessage,
    pub witness_set: FfiSignaturePubKeyList,
}

#[repr(C)]
pub struct FfiPublicMessage {
    pub program_id: FfiProgramId,
    pub account_ids: FfiAccountIdList,
    pub nonces: FfiNonceList,
    pub instruction_data: FfiInstructionDataList,
}

#[repr(C)]
pub struct FfiPrivateTransactionBody {
    pub hash: FfiHashType,
    pub message: FfiPrivacyPreservingMessage,
    pub witness_set: FfiSignaturePubKeyList,
    pub proof: FfiProof,
}

#[repr(C)]
pub struct FfiPublicAction {
    pub account_id: FfiAccountId,
    pub post_state: FfiAccount,
}

#[repr(C)]
pub struct FfiPrivateAction {
    pub nullifier: FfiBytes32,
    pub root: FfiBytes32,
    pub commitment: FfiBytes32,
    pub encrypted_post_state: FfiEncryptedAccountData,
}

#[repr(C)]
pub struct FfiPrivacyPreservingMessage {
    pub public_actions: FfiPublicActionList,
    pub nonces: FfiNonceList,
    pub private_actions: FfiPrivateActionList,
    pub block_validity_window: [u64; 2],
    pub timestamp_validity_window: [u64; 2],
}

#[repr(C)]
pub struct FfiEncryptedAccountData {
    pub ciphertext: FfiVecU8,
    pub epk: FfiVecU8,
    pub view_tag: u8,
}

#[repr(C)]
pub struct FfiSignaturePubKeyEntry {
    pub signature: FfiSignature,
    pub public_key: FfiPublicKey,
}

#[repr(C)]
pub struct FfiProgramDeploymentTransactionBody {
    pub hash: FfiHashType,
    pub message: FfiProgramDeploymentMessage,
}

#[repr(C)]
pub struct FfiTransactionBody {
    pub public_body: *mut FfiPublicTransactionBody,
    pub private_body: *mut FfiPrivateTransactionBody,
    pub program_deployment_body: *mut FfiProgramDeploymentTransactionBody,
}

#[repr(C)]
pub struct FfiTransaction {
    pub body: FfiTransactionBody,
    pub kind: FfiTransactionKind,
}

#[repr(C)]
pub enum FfiTransactionKind {
    Public = 0x0,
    Private,
    ProgramDeploy,
}
