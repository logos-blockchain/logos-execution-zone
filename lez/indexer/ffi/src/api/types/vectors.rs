pub use ffi_types::{
    FfiAccountIdList, FfiActorList, FfiBoundaryStepList, FfiCastPromotionList, FfiMessageDataList,
    FfiNonceList, FfiPdaSeedList, FfiPrivateActionList, FfiPublicAccountEvidenceList,
    FfiRecoveryBindingList, FfiSealedCastList, FfiSignaturePubKeyList, FfiVecU8,
};

use crate::api::types::{FfiVec, transaction::FfiTransaction};

pub type FfiBlockBody = FfiVec<FfiTransaction>;

pub type FfiProof = FfiVecU8;
