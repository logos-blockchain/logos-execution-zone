use ffi_types::empty_root_call;
pub use ffi_types::{
    FfiActor, FfiBoundaryStep, FfiBoundaryStepKind, FfiDelivery, FfiEncryptedAccountData,
    FfiFeeDeclaration, FfiPrivateAction, FfiPublicAccountEvidence, FfiPublicAccountEvidenceKind,
    FfiPublicExecutionContext, FfiRecoveryBinding, FfiRootCall, FfiSealedCast,
    FfiSignaturePubKeyEntry,
};
use indexer_service_protocol::{
    HashType, PdaSeed, PrivacyPreservingMessage, PrivacyPreservingTransaction, Proof,
    PublicAccountEvidence, PublicKey, PublicMessage, PublicTransaction, Signature, Transaction,
    ValidityWindow, WitnessSet,
};

use crate::api::types::{
    FfiAccountId, FfiBytes32, FfiHashType, FfiOption, FfiPublicKey, FfiVec,
    vectors::{
        FfiBoundaryStepList, FfiNonceList, FfiPrivateActionList, FfiProof,
        FfiPublicAccountEvidenceList, FfiRecoveryBindingList, FfiSealedCastList,
        FfiSignaturePubKeyList,
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
        let PublicTransaction {
            hash,
            message,
            witness_set,
        } = value;

        Self {
            hash: hash.into(),
            message: message.into(),
            witness_set: witness_set
                .signatures_and_public_keys
                .into_iter()
                .map(signature_entry)
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
                context: lee::PublicExecutionContext::from(value.message.context).into(),
                root: lee::RootCall::from(value.message.root).into(),
                fee: value
                    .message
                    .has_fee
                    .then(|| lee::FeeDeclaration::from(value.message.fee).into()),
                nonces: {
                    let std_vec: Vec<_> = value.message.nonces.into();
                    std_vec.into_iter().map(Into::into).collect()
                },
                admission_evidence: {
                    let std_vec: Vec<_> = value.message.admission_evidence.into();
                    std_vec
                        .iter()
                        .map(public_account_evidence_from_ffi)
                        .collect()
                },
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
    pub context: FfiPublicExecutionContext,
    pub root: FfiRootCall,
    pub has_fee: bool,
    pub fee: FfiFeeDeclaration,
    pub nonces: FfiNonceList,
    pub admission_evidence: FfiPublicAccountEvidenceList,
}

impl From<PublicMessage> for FfiPublicMessage {
    fn from(value: PublicMessage) -> Self {
        let PublicMessage {
            context,
            root,
            fee,
            nonces,
            admission_evidence,
        } = value;

        Self {
            context: lee::PublicExecutionContext::from(context).into(),
            root: lee::RootCall::from(root).into(),
            nonces: nonces
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            has_fee: fee.is_some(),
            fee: fee
                .map(|fee| lee::FeeDeclaration::from(fee).into())
                .unwrap_or_default(),
            admission_evidence: admission_evidence
                .iter()
                .map(public_account_evidence_to_ffi)
                .collect::<Vec<_>>()
                .into(),
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
        let PrivacyPreservingTransaction {
            hash,
            message,
            witness_set,
        } = value;

        Self {
            hash: hash.into(),
            message: message.into(),
            witness_set: witness_set
                .signatures_and_public_keys
                .into_iter()
                .map(signature_entry)
                .collect::<Vec<_>>()
                .into(),
            proof: witness_set
                .proof
                .expect("Private execution: proof must be present")
                .0
                .into(),
        }
    }
}

impl From<Box<FfiPrivateTransactionBody>> for PrivacyPreservingTransaction {
    fn from(value: Box<FfiPrivateTransactionBody>) -> Self {
        let public_root = value.message.public_root;
        Self {
            hash: HashType(value.hash.data),
            message: PrivacyPreservingMessage {
                context: lee::PublicExecutionContext::from(value.message.context).into(),
                boundary: {
                    let std_vec: Vec<FfiBoundaryStep> = value.message.boundary.into();
                    std_vec
                        .into_iter()
                        .map(|step| lee::BoundaryStep::from(step).into())
                        .collect()
                },
                casts: {
                    let std_vec: Vec<FfiSealedCast> = value.message.casts.into();
                    std_vec
                        .into_iter()
                        .map(|cast| lee::SealedCast::from(cast).into())
                        .collect()
                },
                recovery_bindings: {
                    let std_vec: Vec<FfiRecoveryBinding> = value.message.recovery_bindings.into();
                    std_vec
                        .into_iter()
                        .map(|binding| lee::RecoveryBinding::from(binding).into())
                        .collect()
                },
                public_root: value
                    .message
                    .has_public_root
                    .then(|| lee::RootCall::from(public_root).into()),
                nonces: {
                    let std_vec: Vec<_> = value.message.nonces.into();
                    std_vec.into_iter().map(Into::into).collect()
                },
                private_actions: {
                    let std_vec: Vec<FfiPrivateAction> = value.message.private_actions.into();
                    std_vec
                        .into_iter()
                        .map(|action| lee_core::PrivateAction::from(action).into())
                        .collect()
                },
                block_validity_window: cast_ffi_validity_window(
                    value.message.block_validity_window,
                ),
                timestamp_validity_window: cast_ffi_validity_window(
                    value.message.timestamp_validity_window,
                ),
                admission_evidence: {
                    let std_vec: Vec<_> = value.message.admission_evidence.into();
                    std_vec
                        .iter()
                        .map(public_account_evidence_from_ffi)
                        .collect()
                },
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
    pub admission_evidence: FfiPublicAccountEvidenceList,
}

impl From<PrivacyPreservingMessage> for FfiPrivacyPreservingMessage {
    fn from(value: PrivacyPreservingMessage) -> Self {
        let PrivacyPreservingMessage {
            context,
            boundary,
            casts,
            recovery_bindings,
            public_root,
            nonces,
            private_actions,
            block_validity_window,
            timestamp_validity_window,
            admission_evidence,
        } = value;

        Self {
            context: lee::PublicExecutionContext::from(context).into(),
            boundary: boundary
                .into_iter()
                .map(|step| FfiBoundaryStep::from(lee::BoundaryStep::from(step)))
                .collect::<Vec<_>>()
                .into(),
            casts: casts
                .into_iter()
                .map(|cast| FfiSealedCast::from(lee::SealedCast::from(cast)))
                .collect::<Vec<_>>()
                .into(),
            recovery_bindings: recovery_bindings
                .into_iter()
                .map(|binding| FfiRecoveryBinding::from(lee::RecoveryBinding::from(binding)))
                .collect::<Vec<_>>()
                .into(),
            has_public_root: public_root.is_some(),
            public_root: public_root
                .map_or_else(empty_root_call, |root| lee::RootCall::from(root).into()),
            nonces: nonces
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            private_actions: private_actions
                .into_iter()
                .map(|action| FfiPrivateAction::from(lee_core::PrivateAction::from(action)))
                .collect::<Vec<_>>()
                .into(),
            block_validity_window: cast_validity_window(block_validity_window),
            timestamp_validity_window: cast_validity_window(timestamp_validity_window),
            admission_evidence: admission_evidence
                .iter()
                .map(public_account_evidence_to_ffi)
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

impl From<Transaction> for FfiTransaction {
    fn from(value: Transaction) -> Self {
        match value {
            Transaction::Public(pub_tx) => Self {
                body: FfiTransactionBody {
                    public_body: Box::into_raw(Box::new(pub_tx.into())),
                    private_body: std::ptr::null_mut(),
                },
                kind: FfiTransactionKind::Public,
            },
            Transaction::PrivacyPreserving(priv_tx) => Self {
                body: FfiTransactionBody {
                    public_body: std::ptr::null_mut(),
                    private_body: Box::into_raw(Box::new(priv_tx.into())),
                },
                kind: FfiTransactionKind::Private,
            },
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

fn public_account_evidence_to_ffi(evidence: &PublicAccountEvidence) -> FfiPublicAccountEvidence {
    match *evidence {
        PublicAccountEvidence::Key(key) => FfiPublicAccountEvidence {
            kind: FfiPublicAccountEvidenceKind::Key,
            key: key.into(),
            program: FfiAccountId::default(),
            seed: FfiBytes32::default(),
        },
        PublicAccountEvidence::Pda { program, seed } => FfiPublicAccountEvidence {
            kind: FfiPublicAccountEvidenceKind::Pda,
            key: FfiPublicKey::default(),
            program: program.into(),
            seed: FfiBytes32 { data: seed.0 },
        },
    }
}

fn public_account_evidence_from_ffi(evidence: &FfiPublicAccountEvidence) -> PublicAccountEvidence {
    match evidence.kind {
        FfiPublicAccountEvidenceKind::Key => {
            PublicAccountEvidence::Key(PublicKey(evidence.key.data))
        }
        FfiPublicAccountEvidenceKind::Pda => PublicAccountEvidence::Pda {
            program: evidence.program.into(),
            seed: PdaSeed(evidence.seed.data),
        },
    }
}

fn signature_entry((signature, public_key): (Signature, PublicKey)) -> FfiSignaturePubKeyEntry {
    FfiSignaturePubKeyEntry {
        signature: signature.into(),
        public_key: public_key.into(),
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

#[cfg(test)]
mod tests {
    use indexer_service_protocol::{
        AccountId, Actor, BoundaryStep, Ciphertext, Commitment, Delivery, EncryptedNote,
        EphemeralPublicKey, FeeDeclaration, MessageEnvelope, PublicExecutionContext, RootCall,
        SealedCast,
    };

    use super::*;

    fn account_id(tag: u8) -> AccountId {
        AccountId { value: [tag; 32] }
    }

    fn actor(account_tag: u8, program_tag: u8) -> Actor {
        Actor {
            account_id: account_id(account_tag),
            program_account_id: account_id(program_tag),
        }
    }

    fn admission_evidence() -> Vec<PublicAccountEvidence> {
        vec![
            PublicAccountEvidence::Key(PublicKey([1; 32])),
            PublicAccountEvidence::Pda {
                program: account_id(2),
                seed: PdaSeed([3; 32]),
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
            inherited_authorizations: vec![],
            inherits_entry_authorizations: true,
            pda_seeds: vec![],
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
                hash: HashType([4; 32]),
                message: PublicMessage {
                    context: PublicExecutionContext {
                        actors: vec![actor(6, 7)],
                        authorized_accounts: vec![account_id(10)],
                        cast_promotions: vec![],
                    },
                    root: RootCall {
                        to: actor(5, 8),
                        message: vec![9],
                    },
                    fee,
                    nonces: vec![(account_id(10), 11)],
                    admission_evidence: admission_evidence(),
                },
                witness_set: WitnessSet {
                    signatures_and_public_keys: vec![],
                    proof: None,
                },
            };

            let ffi: FfiPublicTransactionBody = original.clone().into();
            let back: PublicTransaction = Box::new(ffi).into();

            assert_eq!(back.message, original.message);
        }
    }

    #[test]
    fn private_transaction_boundary_entry_and_admission_evidence_roundtrip_over_the_ffi() {
        // A repeated send to one actor, and not a palindrome: a set would collapse the
        // sequence and a reversal would show, and execution replays them in emission order.
        let repeated = delivery(actor(3, 53), actor(5, 6), 7);
        let original = PrivacyPreservingTransaction {
            hash: HashType([4; 32]),
            message: PrivacyPreservingMessage {
                context: PublicExecutionContext {
                    cast_promotions: vec![22, 28],
                    ..PublicExecutionContext::default()
                },
                boundary: vec![
                    BoundaryStep::PrivateToPublic(repeated.clone()),
                    BoundaryStep::PrivateToPublic(Delivery {
                        inherited_authorizations: vec![account_id(15)],
                        pda_seeds: vec![PdaSeed([16; 32])],
                        ..delivery(actor(12, 62), actor(9, 10), 11)
                    }),
                    BoundaryStep::PrivateToPublic(delivery(actor(40, 90), actor(41, 42), 43)),
                    BoundaryStep::PrivateToPublic(repeated),
                    BoundaryStep::PublicToPrivate(Delivery {
                        inherits_entry_authorizations: false,
                        ..delivery(actor(17, 18), actor(19, 20), 21)
                    }),
                    BoundaryStep::EndPrivateSubtree,
                    BoundaryStep::EndPublicSubtree,
                ],
                casts: vec![
                    SealedCast {
                        commitment: Commitment([23; 32]),
                        note: EncryptedNote {
                            epk: EphemeralPublicKey(vec![24; 2]),
                            ciphertext: Ciphertext(vec![25; 3]),
                        },
                    };
                    2
                ],
                recovery_bindings: vec![],
                public_root: Some(RootCall {
                    to: actor(27, 28),
                    message: vec![29; 2],
                }),
                nonces: vec![],
                private_actions: vec![],
                block_validity_window: ValidityWindow((None, None)),
                timestamp_validity_window: ValidityWindow((None, None)),
                admission_evidence: admission_evidence(),
            },
            witness_set: WitnessSet {
                signatures_and_public_keys: vec![],
                proof: Some(Proof(vec![])),
            },
        };

        let ffi: FfiPrivateTransactionBody = original.clone().into();
        let back: PrivacyPreservingTransaction = Box::new(ffi).into();

        assert_eq!(back.message, original.message);
    }
}
