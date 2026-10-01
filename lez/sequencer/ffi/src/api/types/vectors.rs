use crate::api::types::{
    FfiAccountId, FfiBytes32, FfiNonce, FfiVec,
    transaction::{
        FfiActor, FfiAssumption, FfiMessageBody, FfiPrivateAction, FfiPublicDelivery,
        FfiPublicIdentity, FfiScheduleOp, FfiSignaturePubKeyEntry, FfiTransaction,
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

pub type FfiPublicDeliveryList = FfiVec<FfiPublicDelivery>;

pub type FfiAssumptionList = FfiVec<FfiAssumption>;

pub type FfiScheduleOpList = FfiVec<FfiScheduleOp>;

pub type FfiMessageBodyList = FfiVec<FfiMessageBody>;

pub type FfiPublicIdentityList = FfiVec<FfiPublicIdentity>;

pub type FfiPrivateActionList = FfiVec<FfiPrivateAction>;

pub type FfiPdaSeedList = FfiVec<FfiBytes32>;
