use crate::api::types::{
    FfiAccountId, FfiNonce, FfiVec,
    transaction::{
        FfiPrivateAction, FfiProgramImageClaim, FfiPublicAction, FfiSignaturePubKeyEntry,
        FfiTransaction,
    },
};

pub type FfiVecU8 = FfiVec<u8>;

pub type FfiAccountIdList = FfiVec<FfiAccountId>;

pub type FfiBlockBody = FfiVec<FfiTransaction>;

pub type FfiNonceList = FfiVec<FfiNonce>;

pub type FfiInstructionDataList = FfiVec<u8>;

pub type FfiSignaturePubKeyList = FfiVec<FfiSignaturePubKeyEntry>;

pub type FfiProof = FfiVecU8;

pub type FfiProgramDeploymentMessage = FfiVecU8;

pub type FfiPublicActionList = FfiVec<FfiPublicAction>;

pub type FfiPrivateActionList = FfiVec<FfiPrivateAction>;

pub type FfiProgramImageClaimList = FfiVec<FfiProgramImageClaim>;
