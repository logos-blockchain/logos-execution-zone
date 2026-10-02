use crate::api::types::{
    FfiAccountId, FfiBytes32, FfiNonce, FfiVec,
    transaction::{
        FfiActor, FfiBoundaryStep, FfiMessageBody, FfiPrivateAction, FfiPublicIdentity,
        FfiSignaturePubKeyEntry, FfiTransaction,
    },
};

pub type FfiVecU8 = FfiVec<u8>;

pub type FfiActorList = FfiVec<FfiActor>;

pub type FfiAccountIdList = FfiVec<FfiAccountId>;

pub type FfiBlockBody = FfiVec<FfiTransaction>;

pub type FfiNonceList = FfiVec<FfiNonce>;

pub type FfiMessageDataList = FfiVec<u8>;

pub type FfiSignaturePubKeyList = FfiVec<FfiSignaturePubKeyEntry>;

pub type FfiProof = FfiVecU8;

pub type FfiProgramDeploymentMessage = FfiVecU8;

pub type FfiBoundaryStepList = FfiVec<FfiBoundaryStep>;

pub type FfiMessageBodyList = FfiVec<FfiMessageBody>;

pub type FfiPublicIdentityList = FfiVec<FfiPublicIdentity>;

pub type FfiPrivateActionList = FfiVec<FfiPrivateAction>;

pub type FfiPdaSeedList = FfiVec<FfiBytes32>;
