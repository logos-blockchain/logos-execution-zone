pub use ffi_types::{
    FfiAccountIdList, FfiActorList, FfiBoundaryStepList, FfiMessageDataList, FfiNonceList,
    FfiPdaSeedList, FfiPrivateActionList, FfiPromotionList, FfiPublicAccountEvidenceList,
    FfiPublicationList, FfiRecoveryBindingList, FfiSignaturePubKeyList, FfiVecU8,
};

use crate::api::types::{FfiVec, transaction::FfiTransaction};

pub type FfiBlockBody = FfiVec<FfiTransaction>;

pub type FfiProof = FfiVecU8;
