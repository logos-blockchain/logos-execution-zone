use crate::api::types::{
    FfiHashType, FfiNonce, FfiPublicKey, FfiSignature, FfiVec,
    account::{FfiAccountIdList, FfiAccountList, FfiBytes32, FfiProgramId, FfiVecBytes32},
};

#[repr(C)]
pub struct FfiPublicTransactionBody {
    pub hash: FfiHashType,
    pub message: FfiPublicMessage,
    pub witness_set: FfiSignaturePubKeyList,
}

pub type FfiNonceList = FfiVec<FfiNonce>;

pub type FfiInstructionDataList = FfiVec<u32>;

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
    pub proof: FfiProofOpt,
}

#[repr(C)]
pub struct FfiPrivacyPreservingMessage {
    pub public_account_ids: FfiAccountIdList,
    pub nonces: FfiNonceList,
    pub public_post_states: FfiAccountList,
    pub encrypted_private_post_states: FfiVec<FfiEncryptedAccountData>,
    pub new_commitments: FfiVecBytes32,
    pub new_nullifiers: FfiVec<NullifierCommitmentSet>,
    pub block_validity_window: [u64; 2],
    pub timestamp_validity_window: [u64; 2],
}

#[repr(C)]
pub struct NullifierCommitmentSet {
    pub nullifier: FfiBytes32,
    pub commitment_set_digest: FfiBytes32,
}

#[repr(C)]
pub struct FfiEncryptedAccountData {
    pub ciphertext: FfiVec<u8>,
    pub epk: FfiVec<u8>,
    pub view_tag: u8,
}

#[repr(C)]
pub struct FfiSignaturePubKeyEntry {
    pub signature: FfiSignature,
    pub public_key: FfiPublicKey,
}

pub struct FfiSignaturePubKeyList {
    pub entries: *const FfiSignaturePubKeyEntry,
    pub len: usize,
}

#[repr(C)]
pub struct FfiProofOpt {
    pub proof: FfiVec<u8>,
    pub is_some: bool,
}

#[repr(C)]
pub struct FfiProgramDeploymentTransactionBody {
    pub hash: FfiHashType,
    pub message: FfiProgramDeploymentMessage,
}

pub type FfiProgramDeploymentMessage = FfiVec<u8>;

#[repr(C)]
pub struct FfiTransactionBody {
    pub public_body: *const FfiPublicTransactionBody,
    pub private_body: *const FfiPrivateTransactionBody,
    pub program_deployment_body: *const FfiProgramDeploymentTransactionBody,
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
