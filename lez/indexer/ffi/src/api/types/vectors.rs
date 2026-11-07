pub use ffi_types::{
    FfiAccountIdList, FfiActorList, FfiBoundaryStepList, FfiMessageDataList, FfiNonceList,
    FfiPdaSeedList, FfiPrivateActionList, FfiPromotionList, FfiPublicAccountEvidenceList,
    FfiRecoveryBindingList, FfiSealedMessageList, FfiVecU8, FfiWitnessEntryList,
};

use crate::api::types::{FfiVec, transaction::FfiTransaction};

pub type FfiBlockBody = FfiVec<FfiTransaction>;

pub type FfiProof = FfiVecU8;
