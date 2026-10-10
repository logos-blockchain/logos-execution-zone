use common::transaction::LeeTransaction;
use ffi_types::empty_root_call;
pub use ffi_types::{
    FfiActor, FfiBoundaryStep, FfiBoundaryStepKind, FfiDelivery, FfiEncryptedAccountData,
    FfiFeeDeclaration, FfiPrivateAction, FfiPublicAccountEvidence, FfiPublicAccountEvidenceKind,
    FfiPublicExecutionContext, FfiRecoveryBinding, FfiRootCall, FfiSealedCast,
    FfiSignaturePubKeyEntry,
};
use lee::{
    PrivacyPreservingTransaction, PublicAccountEvidence, PublicKey, PublicTransaction, Signature,
    error::LeeError, privacy_preserving_transaction::circuit::Proof,
};
use lee_core::{
    ProgramImageClaim, ProvenExecution,
    program::{ValidityWindow, ValidityWindows},
};
use sequencer_executor_actor::protocol::Transaction;

use crate::{
    OperationStatus,
    api::types::{
        FfiAccountId, FfiBytes32, FfiHashType, FfiOption, FfiVec,
        vectors::{
            FfiBoundaryStepList, FfiNonceList, FfiPrivateActionList, FfiProof,
            FfiPublicAccountEvidenceList, FfiRecoveryBindingList, FfiSealedCastList,
            FfiSignaturePubKeyList,
        },
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

impl TryFrom<Box<FfiPublicTransactionBody>> for PublicTransaction {
    type Error = OperationStatus;

    fn try_from(value: Box<FfiPublicTransactionBody>) -> Result<Self, Self::Error> {
        Ok(Self {
            message: lee::public_transaction::Message {
                context: value.message.context.into(),
                execution: lee::public_transaction::PublicExecution {
                    root: value.message.root.into(),
                    fee: value.message.has_fee.then(|| value.message.fee.into()),
                },
                nonces: value.message.nonces.try_into().map_err(cast_error)?,
                admission_evidence: {
                    let std_vec: Vec<FfiPublicAccountEvidence> =
                        value.message.admission_evidence.into();
                    std_vec
                        .into_iter()
                        .map(|evidence| {
                            PublicAccountEvidence::try_from(evidence).map_err(cast_error)
                        })
                        .collect::<Result<Vec<_>, OperationStatus>>()?
                },
            },
            witness_set: lee::public_transaction::WitnessSet::from_raw_parts({
                let std_vec: Vec<_> = value.witness_set.into();

                let mut cast_vec = vec![];

                for ffi_val in std_vec {
                    cast_vec.push((
                        Signature {
                            value: ffi_val.signature.data,
                        },
                        PublicKey::try_new(ffi_val.public_key.data).map_err(cast_error)?,
                    ));
                }

                cast_vec
            }),
        })
    }
}

#[repr(C)]
pub struct FfiPublicMessage {
    pub context: FfiPublicExecutionContext,
    pub root: FfiRootCall,
    pub has_fee: bool,
    pub fee: FfiFeeDeclaration,
    pub nonces: FfiNonceList,
    pub admission_evidence: FfiPublicAccountEvidenceList,
}

impl From<lee::public_transaction::Message> for FfiPublicMessage {
    fn from(value: lee::public_transaction::Message) -> Self {
        let lee::TransactionMessage {
            context,
            execution: lee::public_transaction::PublicExecution { root, fee },
            nonces,
            admission_evidence,
        } = value;

        Self {
            context: context.into(),
            root: root.into(),
            nonces: nonces
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            has_fee: fee.is_some(),
            fee: fee.map(Into::into).unwrap_or_default(),
            admission_evidence: admission_evidence
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
        }
    }
}

#[repr(C)]
pub enum FfiProgramImageClaimKind {
    Disclosed = 0x0,
    Undisclosed,
}

#[repr(C)]
pub struct FfiProgramImageClaim {
    image_claim_kind: FfiProgramImageClaimKind,
    account_id: *const FfiAccountId,
    image_id: *const [u32; 8],
    root: *const [u8; 32],
}

impl From<ProgramImageClaim> for FfiProgramImageClaim {
    fn from(value: ProgramImageClaim) -> Self {
        match value {
            ProgramImageClaim::Disclosed {
                account_id,
                image_id,
            } => Self {
                image_claim_kind: FfiProgramImageClaimKind::Disclosed,
                account_id: Box::into_raw(Box::new(account_id.into())),
                image_id: Box::into_raw(Box::new(image_id)),
                root: std::ptr::null(),
            },
            ProgramImageClaim::Undisclosed { root } => Self {
                image_claim_kind: FfiProgramImageClaimKind::Undisclosed,
                account_id: std::ptr::null(),
                image_id: std::ptr::null(),
                root: Box::into_raw(Box::new(root)),
            },
        }
    }
}

impl From<FfiProgramImageClaim> for ProgramImageClaim {
    fn from(value: FfiProgramImageClaim) -> Self {
        match value.image_claim_kind {
            FfiProgramImageClaimKind::Disclosed => {
                let account_id = unsafe { Box::from_raw(value.account_id.cast_mut()) };
                let image_id = unsafe { Box::from_raw(value.image_id.cast_mut()) };

                Self::Disclosed {
                    account_id: (*account_id).into(),
                    image_id: *image_id,
                }
            }
            FfiProgramImageClaimKind::Undisclosed => {
                let root = unsafe { Box::from_raw(value.root.cast_mut()) };

                Self::Undisclosed { root: *root }
            }
        }
    }
}

type FfiProgramImageClaims = FfiVec<FfiProgramImageClaim>;

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

impl TryFrom<Box<FfiPrivateTransactionBody>> for PrivacyPreservingTransaction {
    type Error = OperationStatus;

    fn try_from(value: Box<FfiPrivateTransactionBody>) -> Result<Self, Self::Error> {
        let public_root = value.message.public_root;
        Ok(Self {
            message: lee::privacy_preserving_transaction::Message {
                context: value.message.context.into(),
                execution: ProvenExecution {
                    boundary: {
                        let std_vec: Vec<FfiBoundaryStep> = value.message.boundary.into();
                        std_vec.into_iter().map(Into::into).collect()
                    },
                    casts: {
                        let std_vec: Vec<FfiSealedCast> = value.message.casts.into();
                        std_vec.into_iter().map(Into::into).collect()
                    },
                    recovery_bindings: {
                        let std_vec: Vec<FfiRecoveryBinding> =
                            value.message.recovery_bindings.into();
                        std_vec.into_iter().map(Into::into).collect()
                    },
                    public_root: value.message.has_public_root.then(|| public_root.into()),
                    private_actions: {
                        let std_vec: Vec<FfiPrivateAction> = value.message.private_actions.into();
                        std_vec.into_iter().map(Into::into).collect()
                    },
                    validity: ValidityWindows {
                        blocks: cast_ffi_validity_window(value.message.block_validity_window)?,
                        timestamps: cast_ffi_validity_window(
                            value.message.timestamp_validity_window,
                        )?,
                    },
                    program_image_claims: {
                        let std_vec: Vec<_> = value.message.program_image_claims.into();
                        std_vec.into_iter().map(Into::into).collect()
                    },
                },
                nonces: value.message.nonces.try_into().map_err(cast_error)?,
                admission_evidence: {
                    let std_vec: Vec<FfiPublicAccountEvidence> =
                        value.message.admission_evidence.into();
                    std_vec
                        .into_iter()
                        .map(|evidence| {
                            PublicAccountEvidence::try_from(evidence).map_err(cast_error)
                        })
                        .collect::<Result<Vec<_>, OperationStatus>>()?
                },
            },
            witness_set: lee::privacy_preserving_transaction::WitnessSet::from_raw_parts(
                {
                    let std_vec: Vec<_> = value.witness_set.into();
                    let mut cast_vec = vec![];

                    for ffi_val in std_vec {
                        cast_vec.push((
                            Signature {
                                value: ffi_val.signature.data,
                            },
                            PublicKey::try_new(ffi_val.public_key.data).map_err(cast_error)?,
                        ));
                    }

                    cast_vec
                },
                Proof::from_inner(value.proof.into()),
            ),
        })
    }
}

#[repr(C)]
pub struct FfiPrivacyPreservingMessage {
    pub context: FfiPublicExecutionContext,
    pub boundary: FfiBoundaryStepList,
    pub casts: FfiSealedCastList,
    pub recovery_bindings: FfiRecoveryBindingList,
    pub has_public_root: bool,
    pub public_root: FfiRootCall,
    pub nonces: FfiNonceList,
    pub private_actions: FfiPrivateActionList,
    pub block_validity_window: [u64; 2],
    pub timestamp_validity_window: [u64; 2],
    pub program_image_claims: FfiProgramImageClaims,
    pub admission_evidence: FfiPublicAccountEvidenceList,
}

impl From<lee::privacy_preserving_transaction::Message> for FfiPrivacyPreservingMessage {
    fn from(value: lee::privacy_preserving_transaction::Message) -> Self {
        let lee::TransactionMessage {
            context,
            execution:
                ProvenExecution {
                    boundary,
                    casts,
                    recovery_bindings,
                    public_root,
                    private_actions,
                    validity,
                    program_image_claims,
                },
            nonces,
            admission_evidence,
        } = value;

        Self {
            context: context.into(),
            boundary: boundary
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            casts: casts.into_iter().map(Into::into).collect::<Vec<_>>().into(),
            recovery_bindings: recovery_bindings
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            has_public_root: public_root.is_some(),
            public_root: public_root.map_or_else(empty_root_call, Into::into),
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
            block_validity_window: cast_validity_window(validity.blocks),
            timestamp_validity_window: cast_validity_window(validity.timestamps),
            program_image_claims: program_image_claims
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            admission_evidence: admission_evidence
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
        }
    }
}

#[repr(C)]
pub struct FfiTransactionBody {
    pub public_body: *mut FfiPublicTransactionBody,
    pub private_body: *mut FfiPrivateTransactionBody,
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
                },
                kind: FfiTransactionKind::Public,
            },
            LeeTransaction::PrivacyPreserving(priv_tx) => Self {
                body: FfiTransactionBody {
                    public_body: std::ptr::null_mut(),
                    private_body: Box::into_raw(Box::new(priv_tx.into())),
                },
                kind: FfiTransactionKind::Private,
            },
        }
    }
}

impl From<Transaction> for FfiTransaction {
    fn from(value: Transaction) -> Self {
        value.transaction.into()
    }
}

impl TryFrom<FfiTransaction> for LeeTransaction {
    type Error = OperationStatus;

    fn try_from(value: FfiTransaction) -> Result<Self, Self::Error> {
        match value.kind {
            FfiTransactionKind::Public => {
                let body = unsafe { Box::from_raw(value.body.public_body) };
                let std_body: PublicTransaction = body.try_into()?;
                Ok(Self::Public(std_body))
            }
            FfiTransactionKind::Private => {
                let body = unsafe { Box::from_raw(value.body.private_body) };
                let std_body: PrivacyPreservingTransaction = body.try_into()?;
                Ok(Self::PrivacyPreserving(std_body))
            }
        }
    }
}

#[repr(C)]
pub enum FfiTransactionKind {
    Public = 0x0,
    Private,
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
pub unsafe extern "C" fn sequencer_ffi_free_ffi_transaction(val: FfiTransaction) {
    match val.kind {
        FfiTransactionKind::Public => {
            let body = unsafe { Box::from_raw(val.body.public_body) };
            let std_body_res: Result<PublicTransaction, OperationStatus> =
                body.try_into().inspect_err(|_| {
                    log::error!(
                        "Failed to cast `Box<FfiPublicTransactionBody>` into `PublicTransaction`"
                    );
                });

            if let Ok(std_body) = std_body_res {
                drop(std_body);
            }
        }
        FfiTransactionKind::Private => {
            let body = unsafe { Box::from_raw(val.body.private_body) };
            let std_body_res: Result<PrivacyPreservingTransaction, OperationStatus> = body.try_into()
            .inspect_err(|_| log::error!("Failed to cast `Box<FfiPrivateTransactionBody>` into `PrivacyPreservingTransaction`"));

            if let Ok(std_body) = std_body_res {
                drop(std_body);
            }
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
pub unsafe extern "C" fn sequencer_ffi_free_ffi_transaction_opt(
    val: *mut FfiOption<FfiTransaction>,
) {
    if val.is_null() {
        log::error!("Trying to free a null pointer. Exiting");
        return;
    }
    // Reclaim the outer box, then the inner transaction box (if any).
    let opt = unsafe { Box::from_raw(val) };
    if opt.is_some {
        let tx = unsafe { Box::from_raw(opt.value) };
        unsafe {
            sequencer_ffi_free_ffi_transaction(*tx);
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
pub(crate) fn sequencer_ffi_free_transaction_vec_value(val: FfiVec<FfiTransaction>) {
    let ffi_tx_std_vec: Vec<_> = val.into();
    for tx in ffi_tx_std_vec {
        unsafe {
            sequencer_ffi_free_ffi_transaction(tx);
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
pub unsafe extern "C" fn sequencer_ffi_free_ffi_transaction_vec(val: *mut FfiVec<FfiTransaction>) {
    if val.is_null() {
        log::error!("Trying to free a null pointer. Exiting");
        return;
    }
    // Reclaim the outer box, then the backing buffer and each transaction.
    let boxed = unsafe { Box::from_raw(val) };
    sequencer_ffi_free_transaction_vec_value(*boxed);
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "`map_err` passes the error by value"
)]
fn cast_error(error: LeeError) -> OperationStatus {
    log::error!("Failed to cast `[u8; 32]` into PublicKey, err: {error}");
    OperationStatus::CastError
}

fn cast_validity_window(window: ValidityWindow<u64>) -> [u64; 2] {
    [
        window.start().unwrap_or_default(),
        window.end().unwrap_or(u64::MAX),
    ]
}

fn cast_ffi_validity_window(ffi_window: [u64; 2]) -> Result<ValidityWindow<u64>, OperationStatus> {
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

    ValidityWindow::try_from((left, right)).map_err(|e| {
        log::error!("Failed to cast ffi validity window: {e}");
        OperationStatus::CastError
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use lee::{
        AccountId, Actor, BoundaryStep, Delivery, EphemeralPublicKey, FeeDeclaration,
        MessageEnvelope, PublicExecutionContext, RootCall,
    };
    use lee_core::{
        Commitment, EncryptedNote, SealedCast, account::Nonce, encryption::Ciphertext,
        program::PdaSeed,
    };

    use super::*;

    fn account_id(tag: u8) -> AccountId {
        AccountId::new([tag; 32])
    }

    fn actor(account_tag: u8, program_tag: u8) -> Actor {
        Actor {
            account_id: account_id(account_tag),
            program_account_id: account_id(program_tag),
        }
    }

    fn admission_evidence() -> Vec<PublicAccountEvidence> {
        let signer = lee::PrivateKey::try_new([1; 32]).expect("valid key");
        vec![
            PublicAccountEvidence::Key(PublicKey::new_from_private_key(&signer)),
            PublicAccountEvidence::Pda {
                program: account_id(2),
                seed: PdaSeed::new([3; 32]),
            },
        ]
    }

    fn delivery(from: Actor, to: Actor, message: u8) -> Delivery<Actor> {
        Delivery {
            envelope: MessageEnvelope {
                from,
                to,
                message: vec![message],
            },
            inherited_authorizations: BTreeSet::new(),
            inherits_entry_authorizations: true,
            pda_seeds: BTreeSet::new(),
        }
    }

    #[test]
    fn both_program_image_claim_kinds_roundtrip_over_the_ffi() {
        for claim in [
            ProgramImageClaim::Disclosed {
                account_id: account_id(1),
                image_id: [2; 8],
            },
            ProgramImageClaim::Undisclosed { root: [3; 32] },
        ] {
            let ffi: FfiProgramImageClaim = claim.into();
            assert_eq!(ProgramImageClaim::from(ffi), claim);
        }
    }

    #[test]
    fn public_transaction_message_fee_and_admission_evidence_roundtrip_over_the_ffi() {
        for fee in [
            None,
            Some(FeeDeclaration {
                payer: account_id(3),
                gas_limit: 5,
                tip: 1,
                max_fee: 42,
            }),
        ] {
            let original = PublicTransaction {
                message: lee::public_transaction::Message {
                    admission_evidence: admission_evidence(),
                    ..lee::public_transaction::Message::new_preserialized(
                        actor(4, 7),
                        vec![8],
                        [actor(5, 6)],
                        BTreeMap::from([(account_id(9), Nonce(10))]),
                        fee,
                    )
                },
                witness_set: lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
            };

            let ffi: FfiPublicTransactionBody = original.clone().into();
            let back: PublicTransaction = Box::new(ffi).try_into().unwrap();

            assert_eq!(back.message, original.message);
        }
    }

    #[test]
    fn private_transaction_boundary_entry_and_admission_evidence_roundtrip_over_the_ffi() {
        // A repeated send to one actor, and not a palindrome: a set would collapse the
        // sequence and a reversal would show, and execution replays them in emission order.
        let repeated = delivery(actor(3, 53), actor(4, 5), 6);
        let original = PrivacyPreservingTransaction {
            message: lee::privacy_preserving_transaction::Message {
                context: PublicExecutionContext {
                    cast_promotions: BTreeSet::from([21, 27]),
                    ..PublicExecutionContext::default()
                },
                execution: ProvenExecution {
                    boundary: vec![
                        BoundaryStep::PrivateToPublic(repeated.clone()),
                        BoundaryStep::PrivateToPublic(Delivery {
                            inherited_authorizations: BTreeSet::from([account_id(14)]),
                            pda_seeds: BTreeSet::from([PdaSeed::new([15; 32])]),
                            ..delivery(actor(11, 61), actor(8, 9), 10)
                        }),
                        BoundaryStep::PrivateToPublic(delivery(actor(40, 90), actor(41, 42), 43)),
                        BoundaryStep::PrivateToPublic(repeated),
                        BoundaryStep::PublicToPrivate(Delivery {
                            inherits_entry_authorizations: false,
                            ..delivery(actor(16, 17), actor(18, 19), 20)
                        }),
                        BoundaryStep::EndPrivateSubtree,
                        BoundaryStep::EndPublicSubtree,
                    ],
                    casts: vec![
                        SealedCast {
                            commitment: Commitment::from_byte_array([22; 32]),
                            note: EncryptedNote {
                                epk: EphemeralPublicKey(vec![23; 2]),
                                ciphertext: Ciphertext::from_inner(vec![24; 3]),
                            },
                        };
                        2
                    ],
                    recovery_bindings: Vec::new(),
                    public_root: Some(RootCall {
                        to: actor(25, 26),
                        message: vec![27; 2],
                    }),
                    private_actions: vec![],
                    validity: ValidityWindows::new_unbounded(),
                    program_image_claims: vec![],
                },
                nonces: BTreeMap::from([(account_id(28), Nonce(29))]),
                admission_evidence: admission_evidence(),
            },
            witness_set: lee::privacy_preserving_transaction::WitnessSet::from_raw_parts(
                vec![],
                Proof::from_inner(vec![]),
            ),
        };

        let ffi: FfiPrivateTransactionBody = original.clone().into();
        let back: PrivacyPreservingTransaction = Box::new(ffi).try_into().unwrap();

        assert_eq!(back.message, original.message);
    }
}
