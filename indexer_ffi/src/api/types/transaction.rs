use indexer_service_protocol::{
    AccountId, Ciphertext, Commitment, CommitmentSetDigest, EncryptedAccountData,
    EphemeralPublicKey, HashType, Nullifier, PrivacyPreservingMessage,
    PrivacyPreservingTransaction, ProgramDeploymentMessage, ProgramDeploymentTransaction,
    ProgramId, Proof, PublicKey, PublicMessage, PublicTransaction, Signature, Transaction,
    ValidityWindow, WitnessSet,
};

use crate::api::types::{
    FfiBytes32, FfiHashType, FfiOption, FfiProgramId, FfiPublicKey, FfiSignature, FfiVec,
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

impl From<Box<FfiPublicTransactionBody>> for PublicTransaction {
    fn from(value: Box<FfiPublicTransactionBody>) -> Self {
        Self {
            hash: HashType(value.hash.data),
            message: PublicMessage {
                program_id: ProgramId(value.message.program_id.data),
                account_ids: {
                    let std_vec: Vec<_> = value.message.account_ids.into();
                    std_vec
                        .into_iter()
                        .map(|ffi_val| AccountId {
                            value: ffi_val.data,
                        })
                        .collect()
                },
                nonces: {
                    let std_vec: Vec<_> = value.message.nonces.into();
                    std_vec.into_iter().map(Into::into).collect()
                },
                instruction_data: value.message.instruction_data.into(),
            },
            witness_set: WitnessSet {
                signatures_and_public_keys: {
                    let std_vec: Vec<_> = value.witness_set.into();
                    std_vec
                        .into_iter()
                        .map(|ffi_val| {
                            (
                                Signature(ffi_val.signature.data),
                                PublicKey(ffi_val.public_key.data),
                            )
                        })
                        .collect()
                },
                proof: None,
            },
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

impl From<Box<FfiPrivateTransactionBody>> for PrivacyPreservingTransaction {
    fn from(value: Box<FfiPrivateTransactionBody>) -> Self {
        Self {
            hash: HashType(value.hash.data),
            message: PrivacyPreservingMessage {
                public_account_ids: {
                    let std_vec: Vec<_> = value.message.public_account_ids.into();
                    std_vec
                        .into_iter()
                        .map(|ffi_val| AccountId {
                            value: ffi_val.data,
                        })
                        .collect()
                },
                nonces: {
                    let std_vec: Vec<_> = value.message.nonces.into();
                    std_vec.into_iter().map(Into::into).collect()
                },
                public_post_states: {
                    let std_vec: Vec<_> = value.message.public_post_states.into();
                    std_vec.into_iter().map(Into::into).collect()
                },
                encrypted_private_post_states: {
                    let std_vec: Vec<_> = value.message.encrypted_private_post_states.into();
                    std_vec
                        .into_iter()
                        .map(|ffi_val| EncryptedAccountData {
                            ciphertext: Ciphertext(ffi_val.ciphertext.into()),
                            epk: EphemeralPublicKey(ffi_val.epk.into()),
                            view_tag: ffi_val.view_tag,
                        })
                        .collect()
                },
                new_commitments: {
                    let std_vec: Vec<_> = value.message.new_commitments.into();
                    std_vec
                        .into_iter()
                        .map(|ffi_val| Commitment(ffi_val.data))
                        .collect()
                },
                new_nullifiers: {
                    let std_vec: Vec<_> = value.message.new_nullifiers.into();
                    std_vec
                        .into_iter()
                        .map(|ffi_val| {
                            (
                                Nullifier(ffi_val.nullifier.data),
                                CommitmentSetDigest(ffi_val.commitment_set_digest.data),
                            )
                        })
                        .collect()
                },
                block_validity_window: cast_ffi_validity_window(
                    value.message.block_validity_window,
                ),
                timestamp_validity_window: cast_ffi_validity_window(
                    value.message.timestamp_validity_window,
                ),
            },
            witness_set: WitnessSet {
                signatures_and_public_keys: {
                    let std_vec: Vec<_> = value.witness_set.into();
                    std_vec
                        .into_iter()
                        .map(|ffi_val| {
                            (
                                Signature(ffi_val.signature.data),
                                PublicKey(ffi_val.public_key.data),
                            )
                        })
                        .collect()
                },
                proof: Some(Proof(value.proof.into())),
            },
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

impl From<Box<FfiProgramDeploymentTransactionBody>> for ProgramDeploymentTransaction {
    fn from(value: Box<FfiProgramDeploymentTransactionBody>) -> Self {
        Self {
            hash: HashType(value.hash.data),
            message: ProgramDeploymentMessage {
                bytecode: value.message.into(),
            },
        }
    }
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

/// Frees the resources associated with the given ffi transaction.
///
/// # Arguments
///
/// - `val`: An instance of `FfiTransaction`.
///
/// # Returns
///
/// void.
///
/// # Safety
///
/// The caller must ensure that:
/// - `val` is a valid instance of `FfiTransaction`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_ffi_transaction(val: FfiTransaction) {
    match val.kind {
        FfiTransactionKind::Public => {
            let body = unsafe { Box::from_raw(val.body.public_body) };
            let std_body: PublicTransaction = body.into();
            drop(std_body);
        }
        FfiTransactionKind::Private => {
            let body = unsafe { Box::from_raw(val.body.private_body) };
            let std_body: PrivacyPreservingTransaction = body.into();
            drop(std_body);
        }
        FfiTransactionKind::ProgramDeploy => {
            let body = unsafe { Box::from_raw(val.body.program_deployment_body) };
            let std_body: ProgramDeploymentTransaction = body.into();
            drop(std_body);
        }
    }
}

/// Frees the resources associated with the given ffi transaction option.
///
/// # Arguments
///
/// - `val`: An instance of `FfiOption<FfiTransaction>`.
///
/// # Returns
///
/// void.
///
/// # Safety
///
/// The caller must ensure that:
/// - `val` is a valid instance of `FfiOption<FfiTransaction>`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_ffi_transaction_opt(val: FfiOption<FfiTransaction>) {
    if val.is_some {
        let value = unsafe { Box::from_raw(val.value) };

        match value.kind {
            FfiTransactionKind::Public => {
                let body = unsafe { Box::from_raw(value.body.public_body) };
                let std_body: PublicTransaction = body.into();
                drop(std_body);
            }
            FfiTransactionKind::Private => {
                let body = unsafe { Box::from_raw(value.body.private_body) };
                let std_body: PrivacyPreservingTransaction = body.into();
                drop(std_body);
            }
            FfiTransactionKind::ProgramDeploy => {
                let body = unsafe { Box::from_raw(value.body.program_deployment_body) };
                let std_body: ProgramDeploymentTransaction = body.into();
                drop(std_body);
            }
        }
    }
}

/// Frees the resources associated with the given vector of ffi transactions.
///
/// # Arguments
///
/// - `val`: An instance of `FfiVec<FfiTransaction>`.
///
/// # Returns
///
/// void.
///
/// # Safety
///
/// The caller must ensure that:
/// - `val` is a valid instance of `FfiVec<FfiTransaction>`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_ffi_transaction_vec(val: FfiVec<FfiTransaction>) {
    let ffi_tx_std_vec: Vec<_> = val.into();
    for tx in ffi_tx_std_vec {
        unsafe {
            free_ffi_transaction(tx);
        }
    }
}

fn cast_validity_window(window: ValidityWindow) -> [u64; 2] {
    [
        window.0.0.unwrap_or_default(),
        window.0.1.unwrap_or(u64::MAX),
    ]
}

const fn cast_ffi_validity_window(ffi_window: [u64; 2]) -> ValidityWindow {
    let left = if ffi_window[0] == 0 {
        None
    } else {
        Some(ffi_window[0])
    };

    let right = if ffi_window[1] == u64::MAX {
        None
    } else {
        Some(ffi_window[1])
    };

    ValidityWindow((left, right))
}
