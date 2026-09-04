use common::transaction::LeeTransaction;
use lee::{
    AccountId, EphemeralPublicKey, FeeDeclaration, PrivacyPreservingTransaction,
    ProgramDeploymentTransaction, PublicKey, PublicTransaction, Signature,
    privacy_preserving_transaction::{
        circuit::Proof,
        message::{EncryptedAccountData, PublicActionWithID},
    },
};
use lee_core::{
    Commitment, Nullifier, PrivateAction, encryption::Ciphertext, program::ValidityWindow,
};
use sequencer_executor_actor::protocol::Transaction;

use crate::api::types::{
    FfiAccountId, FfiBytes32, FfiHashType, FfiOption, FfiProgramId, FfiPublicKey, FfiSignature,
    FfiU128, FfiVec,
    account::FfiAccount,
    vectors::{
        FfiAccountIdList, FfiInstructionDataList, FfiNonceList, FfiPrivateActionList,
        FfiProgramDeploymentMessage, FfiProof, FfiPublicActionList, FfiSignaturePubKeyList,
        FfiVecU8,
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
        let hash = value.hash();

        let PublicTransaction {
            message,
            witness_set,
        } = value;

        Self {
            hash: FfiBytes32::from_bytes(hash),
            message: message.into(),
            witness_set: witness_set
                .signatures_and_public_keys()
                .to_vec()
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
            message: lee::public_transaction::Message {
                program_id: value.message.program_id.data,
                account_ids: {
                    let std_vec: Vec<_> = value.message.account_ids.into();
                    std_vec
                        .into_iter()
                        .map(|ffi_val| AccountId::new(ffi_val.data))
                        .collect()
                },
                nonces: {
                    let std_vec: Vec<_> = value.message.nonces.into();
                    std_vec.into_iter().map(Into::into).collect()
                },
                instruction_data: value.message.instruction_data.into(),
                fee: value.message.has_fee.then(|| value.message.fee.into()),
            },
            witness_set: lee::public_transaction::WitnessSet::from_raw_parts({
                let std_vec: Vec<_> = value.witness_set.into();
                std_vec
                    .into_iter()
                    .map(|ffi_val| {
                        (
                            Signature {
                                value: ffi_val.signature.data,
                            },
                            PublicKey::try_new(ffi_val.public_key.data).unwrap(),
                        )
                    })
                    .collect()
            }),
        }
    }
}

/// Fee declaration of a public transaction. Held inline (not behind a
/// pointer): a fee-exempt transaction carries `has_fee == false` and a zeroed
/// declaration.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FfiFeeDeclaration {
    pub payer: FfiAccountId,
    pub gas_limit: u64,
    pub tip: u64,
    pub max_fee: FfiU128,
}

impl From<FeeDeclaration> for FfiFeeDeclaration {
    fn from(value: FeeDeclaration) -> Self {
        let FeeDeclaration {
            payer,
            gas_limit,
            tip,
            max_fee,
        } = value;

        Self {
            payer: payer.into(),
            gas_limit,
            tip,
            max_fee: max_fee.into(),
        }
    }
}

impl From<FfiFeeDeclaration> for FeeDeclaration {
    fn from(value: FfiFeeDeclaration) -> Self {
        Self {
            payer: AccountId::new(value.payer.data),
            gas_limit: value.gas_limit,
            tip: value.tip,
            max_fee: value.max_fee.into(),
        }
    }
}

#[repr(C)]
pub struct FfiPublicMessage {
    pub program_id: FfiProgramId,
    pub account_ids: FfiAccountIdList,
    pub nonces: FfiNonceList,
    pub instruction_data: FfiInstructionDataList,
    pub has_fee: bool,
    pub fee: FfiFeeDeclaration,
}

impl From<lee::public_transaction::Message> for FfiPublicMessage {
    fn from(value: lee::public_transaction::Message) -> Self {
        let lee::public_transaction::Message {
            program_id,
            account_ids,
            nonces,
            instruction_data,
            fee,
        } = value;

        Self {
            program_id: program_id.into(),
            account_ids: account_ids
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            nonces: nonces
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            instruction_data: instruction_data.into(),
            has_fee: fee.is_some(),
            fee: fee.map(Into::into).unwrap_or_default(),
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
        let hash = value.hash();

        let PrivacyPreservingTransaction {
            message,
            witness_set,
        } = value;

        let (signatures_and_public_keys, proof) = witness_set.into_raw_parts();

        Self {
            hash: FfiBytes32::from_bytes(hash),
            message: message.into(),
            witness_set: signatures_and_public_keys
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            proof: proof.into_inner().into(),
        }
    }
}

impl From<Box<FfiPrivateTransactionBody>> for PrivacyPreservingTransaction {
    fn from(value: Box<FfiPrivateTransactionBody>) -> Self {
        Self {
            message: lee::privacy_preserving_transaction::Message {
                public_actions: {
                    let std_vec: Vec<_> = value.message.public_actions.into();
                    std_vec
                        .into_iter()
                        .map(|ffi_val| PublicActionWithID {
                            account_id: AccountId::new(ffi_val.account_id.data),
                            post_state: ffi_val.post_state.into(),
                        })
                        .collect()
                },
                nonces: {
                    let std_vec: Vec<_> = value.message.nonces.into();
                    std_vec.into_iter().map(Into::into).collect()
                },
                private_actions: {
                    let std_vec: Vec<_> = value.message.private_actions.into();
                    std_vec
                        .into_iter()
                        .map(|ffi_val| PrivateAction {
                            nullifier: Nullifier::from_byte_array(ffi_val.nullifier.data),
                            root: ffi_val.root.data,
                            commitment: Commitment::from_byte_array(ffi_val.commitment.data),
                            encrypted_post_state: EncryptedAccountData {
                                ciphertext: Ciphertext::from_inner(
                                    ffi_val.encrypted_post_state.ciphertext.into(),
                                ),
                                epk: EphemeralPublicKey(ffi_val.encrypted_post_state.epk.into()),
                                view_tag: ffi_val.encrypted_post_state.view_tag,
                            },
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
            witness_set: lee::privacy_preserving_transaction::WitnessSet::from_raw_parts(
                {
                    let std_vec: Vec<_> = value.witness_set.into();
                    std_vec
                        .into_iter()
                        .map(|ffi_val| {
                            (
                                Signature {
                                    value: ffi_val.signature.data,
                                },
                                PublicKey::try_new(ffi_val.public_key.data).unwrap(),
                            )
                        })
                        .collect()
                },
                Proof::from_inner(value.proof.into()),
            ),
        }
    }
}

#[repr(C)]
pub struct FfiPublicAction {
    pub account_id: FfiAccountId,
    pub post_state: FfiAccount,
}

impl From<PublicActionWithID> for FfiPublicAction {
    fn from(value: PublicActionWithID) -> Self {
        let post_state: lee::Account = value
            .post_state
            .try_into()
            .expect("Source is in blocks, must fit");
        Self {
            account_id: value.account_id.into(),
            post_state: post_state.into(),
        }
    }
}

#[repr(C)]
pub struct FfiPrivateAction {
    pub nullifier: FfiBytes32,
    pub root: FfiBytes32,
    pub commitment: FfiBytes32,
    pub encrypted_post_state: FfiEncryptedAccountData,
}

impl From<PrivateAction> for FfiPrivateAction {
    fn from(value: PrivateAction) -> Self {
        Self {
            nullifier: FfiBytes32 {
                data: value.nullifier.to_byte_array(),
            },
            root: FfiBytes32 { data: value.root },
            commitment: FfiBytes32 {
                data: value.commitment.to_byte_array(),
            },
            encrypted_post_state: value.encrypted_post_state.into(),
        }
    }
}

#[repr(C)]
pub struct FfiPrivacyPreservingMessage {
    pub public_actions: FfiPublicActionList,
    pub nonces: FfiNonceList,
    pub private_actions: FfiPrivateActionList,
    pub block_validity_window: [u64; 2],
    pub timestamp_validity_window: [u64; 2],
}

impl From<lee::privacy_preserving_transaction::Message> for FfiPrivacyPreservingMessage {
    fn from(value: lee::privacy_preserving_transaction::Message) -> Self {
        let lee::privacy_preserving_transaction::Message {
            public_actions,
            nonces,
            private_actions,
            block_validity_window,
            timestamp_validity_window,
        } = value;

        Self {
            public_actions: public_actions
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            nonces: nonces
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            private_actions: private_actions
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            block_validity_window: cast_validity_window(block_validity_window),
            timestamp_validity_window: cast_validity_window(timestamp_validity_window),
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
        let EncryptedAccountData {
            ciphertext,
            epk,
            view_tag,
        } = value;

        Self {
            ciphertext: ciphertext.into_inner().into(),
            epk: epk.0.into(),
            view_tag,
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
            message: lee::program_deployment_transaction::Message::new(value.message.into()),
        }
    }
}

impl From<ProgramDeploymentTransaction> for FfiProgramDeploymentTransactionBody {
    fn from(value: ProgramDeploymentTransaction) -> Self {
        let hash = value.hash();

        let ProgramDeploymentTransaction { message } = value;

        Self {
            hash: FfiBytes32::from_bytes(hash),
            message: message.into_bytecode().into(),
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

impl From<LeeTransaction> for FfiTransaction {
    fn from(value: LeeTransaction) -> Self {
        match value {
            LeeTransaction::Public(pub_tx) => Self {
                body: FfiTransactionBody {
                    public_body: Box::into_raw(Box::new(pub_tx.into())),
                    private_body: std::ptr::null_mut(),
                    program_deployment_body: std::ptr::null_mut(),
                },
                kind: FfiTransactionKind::Public,
            },
            LeeTransaction::PrivacyPreserving(priv_tx) => Self {
                body: FfiTransactionBody {
                    public_body: std::ptr::null_mut(),
                    private_body: Box::into_raw(Box::new(priv_tx.into())),
                    program_deployment_body: std::ptr::null_mut(),
                },
                kind: FfiTransactionKind::Private,
            },
            LeeTransaction::ProgramDeployment(pr_dep_tx) => Self {
                body: FfiTransactionBody {
                    public_body: std::ptr::null_mut(),
                    private_body: std::ptr::null_mut(),
                    program_deployment_body: Box::into_raw(Box::new(pr_dep_tx.into())),
                },
                kind: FfiTransactionKind::ProgramDeploy,
            },
        }
    }
}

impl From<Transaction> for FfiTransaction {
    fn from(value: Transaction) -> Self {
        value.transaction.into()
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
/// Takes ownership of the whole allocation produced by a `query_*` call: the
/// outer `Box<FfiOption<FfiTransaction>>` (the `PointerResult.value` pointer),
/// the inner `Box<FfiTransaction>` (when present), and its body.
///
/// # Arguments
///
/// - `val`: The `*mut FfiOption<FfiTransaction>` returned in `PointerResult.value`.
///
/// # Returns
///
/// void.
///
/// # Safety
///
/// The caller must ensure that:
/// - `val` is a pointer to an `FfiOption<FfiTransaction>` produced by this library and not yet
///   freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_ffi_transaction_opt(val: *mut FfiOption<FfiTransaction>) {
    if val.is_null() {
        log::error!("Trying to free a null pointer. Exiting");
        return;
    }
    // Reclaim the outer box, then the inner transaction box (if any).
    let opt = unsafe { Box::from_raw(val) };
    if opt.is_some {
        let tx = unsafe { Box::from_raw(opt.value) };
        unsafe {
            free_ffi_transaction(*tx);
        }
    }
}

/// Frees the resources owned by an `FfiVec<FfiTransaction>` value (the backing
/// buffer and each transaction), without owning an outer box.
///
/// This is the element-level helper shared by the block free path
/// ([`crate::api::types::block::free_ffi_block`], whose body is a transaction
/// vector held by value) and the public [`free_ffi_transaction_vec`] entry
/// point (which first reclaims the outer box).
pub(crate) fn free_transaction_vec_value(val: FfiVec<FfiTransaction>) {
    let ffi_tx_std_vec: Vec<_> = val.into();
    for tx in ffi_tx_std_vec {
        unsafe {
            free_ffi_transaction(tx);
        }
    }
}

/// Frees the resources associated with the given vector of ffi transactions.
///
/// Takes ownership of the whole allocation produced by a `query_*` call: the
/// outer `Box<FfiVec<FfiTransaction>>` (the `PointerResult.value` pointer), the
/// vector's backing buffer, and every transaction within it.
///
/// # Arguments
///
/// - `val`: The `*mut FfiVec<FfiTransaction>` returned in `PointerResult.value`.
///
/// # Returns
///
/// void.
///
/// # Safety
///
/// The caller must ensure that:
/// - `val` is a pointer to an `FfiVec<FfiTransaction>` produced by this library and not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_ffi_transaction_vec(val: *mut FfiVec<FfiTransaction>) {
    if val.is_null() {
        log::error!("Trying to free a null pointer. Exiting");
        return;
    }
    // Reclaim the outer box, then the backing buffer and each transaction.
    let boxed = unsafe { Box::from_raw(val) };
    free_transaction_vec_value(*boxed);
}

fn cast_validity_window(window: ValidityWindow<u64>) -> [u64; 2] {
    [
        window.start().unwrap_or_default(),
        window.end().unwrap_or(u64::MAX),
    ]
}

fn cast_ffi_validity_window(ffi_window: [u64; 2]) -> ValidityWindow<u64> {
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

    ValidityWindow::try_from((left, right)).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_transaction_fee_roundtrips_over_the_ffi() {
        let tx = |fee| PublicTransaction {
            message: lee::public_transaction::Message {
                program_id: [2; 8],
                account_ids: vec![AccountId::new([3; 32])],
                nonces: vec![],
                instruction_data: vec![9, 9],
                fee,
            },
            witness_set: lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
        };

        for fee in [
            None,
            Some(FeeDeclaration {
                payer: AccountId::new([3; 32]),
                gas_limit: 5,
                tip: 1,
                max_fee: 42,
            }),
        ] {
            let original = tx(fee);
            let ffi: FfiPublicTransactionBody = original.clone().into();
            let back: PublicTransaction = Box::new(ffi).into();
            assert_eq!(back.message.fee, original.message.fee);
        }
    }
}
