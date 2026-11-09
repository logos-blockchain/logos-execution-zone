use crate::primitives::types::{
    FfiAccountId, FfiBytes32, FfiVec,
    actor::{
        FfiActor, FfiBoundaryStep, FfiNonceEntry, FfiPrivateAction, FfiPublicAccountEvidence,
        FfiRecoveryBinding, FfiSealedMessage, FfiSignaturePubKeyEntry,
    },
    transaction::FfiTransaction,
};

pub type FfiVecU8 = FfiVec<u8>;

pub type FfiBlockBody = FfiVec<FfiTransaction>;

pub type FfiProof = FfiVecU8;

pub type FfiProgramDeploymentMessage = FfiVecU8;

pub type FfiActorList = FfiVec<FfiActor>;

pub type FfiAccountIdList = FfiVec<FfiAccountId>;

pub type FfiNonceList = FfiVec<FfiNonceEntry>;

pub type FfiMessageDataList = FfiVec<u8>;

pub type FfiSignaturePubKeyList = FfiVec<FfiSignaturePubKeyEntry>;

pub type FfiBoundaryStepList = FfiVec<FfiBoundaryStep>;

pub type FfiSealedMessageList = FfiVec<FfiSealedMessage>;

pub type FfiPublicAccountEvidenceList = FfiVec<FfiPublicAccountEvidence>;

pub type FfiPrivateActionList = FfiVec<FfiPrivateAction>;

pub type FfiRecoveryBindingList = FfiVec<FfiRecoveryBinding>;

pub type FfiPdaSeedList = FfiVec<FfiBytes32>;

pub type FfiPromotionList = FfiVec<u64>;
