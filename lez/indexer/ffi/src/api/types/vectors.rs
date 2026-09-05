use crate::api::types::{
    FfiNonce, FfiVec,
    transaction::{
        FfiPosition, FfiPrivateAction, FfiPublicAction, FfiSignaturePubKeyEntry, FfiTransaction,
    },
};

pub type FfiVecU8 = FfiVec<u8>;

pub type FfiPositionList = FfiVec<FfiPosition>;

pub type FfiBlockBody = FfiVec<FfiTransaction>;

pub type FfiNonceList = FfiVec<FfiNonce>;

pub type FfiInstructionDataList = FfiVec<u8>;

pub type FfiSignaturePubKeyList = FfiVec<FfiSignaturePubKeyEntry>;

pub type FfiProof = FfiVecU8;

pub type FfiPublicActionList = FfiVec<FfiPublicAction>;

pub type FfiPrivateActionList = FfiVec<FfiPrivateAction>;
