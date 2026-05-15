use crate::api::types::{
    FfiAccountId, FfiBytes32, FfiNonce, FfiVec,
    account::FfiAccount,
    transaction::{
        FfiEncryptedAccountData, FfiNullifierCommitmentSet, FfiSignaturePubKeyEntry, FfiTransaction,
    },
};

pub type FfiVecU8 = FfiVec<u8>;

pub type FfiAccountList = FfiVec<FfiAccount>;

pub type FfiAccountIdList = FfiVec<FfiAccountId>;

pub type FfiVecBytes32 = FfiVec<FfiBytes32>;

pub type FfiBlockBody = FfiVec<FfiTransaction>;

pub type FfiNonceList = FfiVec<FfiNonce>;

pub type FfiInstructionDataList = FfiVec<u32>;

pub type FfiSignaturePubKeyList = FfiVec<FfiSignaturePubKeyEntry>;

pub type FfiProof = FfiVecU8;

pub type FfiProgramDeploymentMessage = FfiVecU8;

pub type FfiEncryptedAccountDataList = FfiVec<FfiEncryptedAccountData>;

pub type FfiNullifierCommitmentSetList = FfiVec<FfiNullifierCommitmentSet>;
