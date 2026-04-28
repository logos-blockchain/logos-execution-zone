use indexer_service_protocol::{
    CommitmentSetDigest, EncryptedAccountData, Nullifier, PrivacyPreservingMessage,
    PrivacyPreservingTransaction, ProgramDeploymentTransaction, PublicKey, PublicMessage,
    PublicTransaction, Signature, Transaction, ValidityWindow,
};

use crate::api::types::{
    FfiHashType, FfiPublicKey, FfiSignature,
    account::{FfiBytes32, FfiProgramId},
    vectors::{
        FfiAccountIdList, FfiAccountList, FfiEncryptedAccountDataList, FfiInstructionDataList,
        FfiNonceList, FfiNullifierCommitmentSetList, FfiProgramDeploymentMessage, FfiProof,
        FfiSignaturePubKeyList, FfiVecBytes32, FfiVecU8,
    },
};

#[repr(C)]
pub struct FfiPublicTransactionBody {
    pub hash: FfiHashType,
    pub message: FfiPublicMessage,
    pub witness_set: FfiSignaturePubKeyList,
}

impl From<PublicTransaction> for FfiPublicTransactionBody {
    fn from(value: PublicTransaction) -> Self {
        Self {
            hash: value.hash.into(),
            message: value.message.into(),
            witness_set: value
                .witness_set
                .signatures_and_public_keys
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
        }
    }
}

#[repr(C)]
pub struct FfiPublicMessage {
    pub program_id: FfiProgramId,
    pub account_ids: FfiAccountIdList,
    pub nonces: FfiNonceList,
    pub instruction_data: FfiInstructionDataList,
}

impl From<PublicMessage> for FfiPublicMessage {
    fn from(value: PublicMessage) -> Self {
        Self {
            program_id: value.program_id.into(),
            account_ids: value
                .account_ids
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            nonces: value
                .nonces
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            instruction_data: value.instruction_data.into(),
        }
    }
}

#[repr(C)]
pub struct FfiPrivateTransactionBody {
    pub hash: FfiHashType,
    pub message: FfiPrivacyPreservingMessage,
    pub witness_set: FfiSignaturePubKeyList,
    pub proof: FfiProof,
}

impl From<PrivacyPreservingTransaction> for FfiPrivateTransactionBody {
    fn from(value: PrivacyPreservingTransaction) -> Self {
        Self {
            hash: value.hash.into(),
            message: value.message.into(),
            witness_set: value
                .witness_set
                .signatures_and_public_keys
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            proof: value
                .witness_set
                .proof
                .expect("Private execution: proof must be present")
                .0
                .into(),
        }
    }
}

#[repr(C)]
pub struct FfiPrivacyPreservingMessage {
    pub public_account_ids: FfiAccountIdList,
    pub nonces: FfiNonceList,
    pub public_post_states: FfiAccountList,
    pub encrypted_private_post_states: FfiEncryptedAccountDataList,
    pub new_commitments: FfiVecBytes32,
    pub new_nullifiers: FfiNullifierCommitmentSetList,
    pub block_validity_window: [u64; 2],
    pub timestamp_validity_window: [u64; 2],
}

impl From<PrivacyPreservingMessage> for FfiPrivacyPreservingMessage {
    fn from(value: PrivacyPreservingMessage) -> Self {
        Self {
            public_account_ids: value
                .public_account_ids
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            nonces: value
                .nonces
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            public_post_states: value
                .public_post_states
                .into_iter()
                .map(|acc_ind| -> nssa::Account {
                    acc_ind.try_into().expect("Source is in blocks, must fit")
                })
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            encrypted_private_post_states: value
                .encrypted_private_post_states
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            new_commitments: value
                .new_commitments
                .into_iter()
                .map(|comm| FfiBytes32 { data: comm.0 })
                .collect::<Vec<_>>()
                .into(),
            new_nullifiers: value
                .new_nullifiers
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            block_validity_window: cast_validity_window(value.block_validity_window),
            timestamp_validity_window: cast_validity_window(value.timestamp_validity_window),
        }
    }
}

#[repr(C)]
pub struct FfiNullifierCommitmentSet {
    pub nullifier: FfiBytes32,
    pub commitment_set_digest: FfiBytes32,
}

impl From<(Nullifier, CommitmentSetDigest)> for FfiNullifierCommitmentSet {
    fn from(value: (Nullifier, CommitmentSetDigest)) -> Self {
        Self {
            nullifier: FfiBytes32 { data: value.0.0 },
            commitment_set_digest: FfiBytes32 { data: value.1.0 },
        }
    }
}

#[repr(C)]
pub struct FfiEncryptedAccountData {
    pub ciphertext: FfiVecU8,
    pub epk: FfiVecU8,
    pub view_tag: u8,
}

impl From<EncryptedAccountData> for FfiEncryptedAccountData {
    fn from(value: EncryptedAccountData) -> Self {
        Self {
            ciphertext: value.ciphertext.0.into(),
            epk: value.epk.0.into(),
            view_tag: value.view_tag,
        }
    }
}

#[repr(C)]
pub struct FfiSignaturePubKeyEntry {
    pub signature: FfiSignature,
    pub public_key: FfiPublicKey,
}

impl From<(Signature, PublicKey)> for FfiSignaturePubKeyEntry {
    fn from(value: (Signature, PublicKey)) -> Self {
        Self {
            signature: value.0.into(),
            public_key: value.1.into(),
        }
    }
}

#[repr(C)]
pub struct FfiProgramDeploymentTransactionBody {
    pub hash: FfiHashType,
    pub message: FfiProgramDeploymentMessage,
}

impl From<ProgramDeploymentTransaction> for FfiProgramDeploymentTransactionBody {
    fn from(value: ProgramDeploymentTransaction) -> Self {
        Self {
            hash: value.hash.into(),
            message: value.message.bytecode.into(),
        }
    }
}

#[repr(C)]
pub struct FfiTransactionBody {
    pub public_body: *mut FfiPublicTransactionBody,
    pub private_body: *mut FfiPrivateTransactionBody,
    pub program_deployment_body: *mut FfiProgramDeploymentTransactionBody,
}

#[repr(C)]
pub struct FfiTransaction {
    pub body: FfiTransactionBody,
    pub kind: FfiTransactionKind,
}

impl From<Transaction> for FfiTransaction {
    fn from(value: Transaction) -> Self {
        match value {
            Transaction::Public(pub_tx) => Self {
                body: FfiTransactionBody {
                    public_body: Box::into_raw(Box::new(pub_tx.into())),
                    private_body: std::ptr::null_mut(),
                    program_deployment_body: std::ptr::null_mut(),
                },
                kind: FfiTransactionKind::Public,
            },
            Transaction::PrivacyPreserving(priv_tx) => Self {
                body: FfiTransactionBody {
                    public_body: std::ptr::null_mut(),
                    private_body: Box::into_raw(Box::new(priv_tx.into())),
                    program_deployment_body: std::ptr::null_mut(),
                },
                kind: FfiTransactionKind::Public,
            },
            Transaction::ProgramDeployment(pr_dep_tx) => Self {
                body: FfiTransactionBody {
                    public_body: std::ptr::null_mut(),
                    private_body: std::ptr::null_mut(),
                    program_deployment_body: Box::into_raw(Box::new(pr_dep_tx.into())),
                },
                kind: FfiTransactionKind::Public,
            },
        }
    }
}

#[repr(C)]
pub enum FfiTransactionKind {
    Public = 0x0,
    Private,
    ProgramDeploy,
}

fn cast_validity_window(window: ValidityWindow) -> [u64; 2] {
    [
        window.0.0.unwrap_or_default(),
        window.0.1.unwrap_or(u64::MAX),
    ]
}
