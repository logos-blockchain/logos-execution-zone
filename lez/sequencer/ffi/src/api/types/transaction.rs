use common::transaction::LeeTransaction;
pub use ffi_types::{
    FfiActor, FfiBoundaryStep, FfiBoundaryStepKind, FfiDelivery, FfiEncryptedAccountData,
    FfiFeeDeclaration, FfiPrivateAction, FfiPublicAccountEvidence, FfiPublicAccountEvidenceKind,
    FfiPublicExecutionContext, FfiRecoveryBinding, FfiRootCall, FfiSealedMessage,
    FfiSignaturePubKeyEntry,
};
use ffi_types::{FfiNonceEntry, empty_root_call, nonces_from_ffi};
use lee::{
    BoundaryStep, FeeDeclaration, PrivacyPreservingTransaction, PublicAccountEvidence,
    PublicExecutionContext, PublicKey, PublicTransaction, RootCall, Signature, error::LeeError,
    privacy_preserving_transaction::circuit::Proof,
};
use lee_core::{
    PrivateAction, ProgramImageClaim, ProvenExecution, RecoveryBinding, SealedMessage,
    program::{ValidityWindow, ValidityWindows},
};
use sequencer_executor_actor::protocol::Transaction;

use crate::{
    OperationStatus,
    api::types::{
        FfiAccountId, FfiBytes32, FfiHashType, FfiOption, FfiVec,
        vectors::{
            FfiBoundaryStepList, FfiNonceList, FfiPrivateActionList, FfiProof,
            FfiPublicAccountEvidenceList, FfiRecoveryBindingList, FfiSealedMessageList,
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

struct OwnedPublicBody {
    public_context: PublicExecutionContext,
    root: RootCall,
    fee: Option<FeeDeclaration>,
    nonces: Vec<FfiNonceEntry>,
    admission_evidence: Vec<FfiPublicAccountEvidence>,
    witness_set: Vec<FfiSignaturePubKeyEntry>,
}

impl From<Box<FfiPublicTransactionBody>> for OwnedPublicBody {
    fn from(value: Box<FfiPublicTransactionBody>) -> Self {
        let FfiPublicTransactionBody {
            hash: _,
            message,
            witness_set,
        } = *value;
        Self {
            public_context: message.public_context.into(),
            root: message.root.into(),
            fee: message.has_fee.then(|| message.fee.into()),
            nonces: message.nonces.into(),
            admission_evidence: message.admission_evidence.into(),
            witness_set: witness_set.into(),
        }
    }
}

impl TryFrom<Box<FfiPublicTransactionBody>> for PublicTransaction {
    type Error = OperationStatus;

    fn try_from(value: Box<FfiPublicTransactionBody>) -> Result<Self, Self::Error> {
        let OwnedPublicBody {
            public_context,
            root,
            fee,
            nonces,
            admission_evidence,
            witness_set,
        } = value.into();
        Ok(Self {
            message: lee::public_transaction::Message {
                public_context,
                execution: lee::public_transaction::PublicExecution { root, fee },
                nonces: nonces_from_ffi(nonces).map_err(cast_error)?,
                admission_evidence: public_account_evidence(admission_evidence)?,
            },
            witness_set: lee::public_transaction::WitnessSet::from_raw_parts(signatures(
                witness_set,
            )?),
        })
    }
}

#[repr(C)]
pub struct FfiPublicMessage {
    pub public_context: FfiPublicExecutionContext,
    pub root: FfiRootCall,
    pub has_fee: bool,
    pub fee: FfiFeeDeclaration,
    pub nonces: FfiNonceList,
    pub admission_evidence: FfiPublicAccountEvidenceList,
}

impl From<lee::public_transaction::Message> for FfiPublicMessage {
    fn from(value: lee::public_transaction::Message) -> Self {
        let lee::TransactionMessage {
            public_context,
            execution: lee::public_transaction::PublicExecution { root, fee },
            nonces,
            admission_evidence,
        } = value;

        Self {
            public_context: public_context.into(),
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

impl TryFrom<FfiProgramImageClaim> for ProgramImageClaim {
    type Error = OperationStatus;

    /// Frees every non-null pointer (unused ones must be null); a missing required one is an error.
    fn try_from(value: FfiProgramImageClaim) -> Result<Self, Self::Error> {
        let account_id = (!value.account_id.is_null())
            .then(|| unsafe { Box::from_raw(value.account_id.cast_mut()) });
        let image_id = (!value.image_id.is_null())
            .then(|| unsafe { Box::from_raw(value.image_id.cast_mut()) });
        let root = (!value.root.is_null()).then(|| unsafe { Box::from_raw(value.root.cast_mut()) });

        match value.image_claim_kind {
            FfiProgramImageClaimKind::Disclosed => {
                if let (Some(account_id), Some(image_id)) = (account_id, image_id) {
                    Ok(Self::Disclosed {
                        account_id: (*account_id).into(),
                        image_id: *image_id,
                    })
                } else {
                    log::error!(
                        "Disclosed `FfiProgramImageClaim` is missing its account or image id"
                    );
                    Err(OperationStatus::NullPointer)
                }
            }
            FfiProgramImageClaimKind::Undisclosed => root
                .map(|root| Self::Undisclosed { root: *root })
                .ok_or_else(|| {
                    log::error!("Undisclosed `FfiProgramImageClaim` is missing its root");
                    OperationStatus::NullPointer
                }),
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

struct OwnedPrivateBody {
    public_context: PublicExecutionContext,
    boundary: Vec<BoundaryStep>,
    async_messages: Vec<SealedMessage>,
    recovery_bindings: Vec<RecoveryBinding>,
    public_root: Option<RootCall>,
    private_actions: Vec<PrivateAction>,
    block_validity_window: [u64; 2],
    timestamp_validity_window: [u64; 2],
    program_image_claims: Vec<Result<ProgramImageClaim, OperationStatus>>,
    nonces: Vec<FfiNonceEntry>,
    admission_evidence: Vec<FfiPublicAccountEvidence>,
    witness_set: Vec<FfiSignaturePubKeyEntry>,
    proof: Vec<u8>,
}

impl From<Box<FfiPrivateTransactionBody>> for OwnedPrivateBody {
    fn from(value: Box<FfiPrivateTransactionBody>) -> Self {
        let FfiPrivateTransactionBody {
            hash: _,
            message,
            witness_set,
            proof,
        } = *value;
        let public_root = RootCall::from(message.public_root);
        Self {
            public_context: message.public_context.into(),
            boundary: owned(message.boundary),
            async_messages: owned(message.async_messages),
            recovery_bindings: owned(message.recovery_bindings),
            public_root: message.has_public_root.then_some(public_root),
            private_actions: owned(message.private_actions),
            block_validity_window: message.block_validity_window,
            timestamp_validity_window: message.timestamp_validity_window,
            program_image_claims: Vec::from(message.program_image_claims)
                .into_iter()
                .map(ProgramImageClaim::try_from)
                .collect(),
            nonces: message.nonces.into(),
            admission_evidence: message.admission_evidence.into(),
            witness_set: witness_set.into(),
            proof: proof.into(),
        }
    }
}

impl TryFrom<Box<FfiPrivateTransactionBody>> for PrivacyPreservingTransaction {
    type Error = OperationStatus;

    /// Reclaims every allocation before validating, so a failed conversion leaks nothing.
    fn try_from(value: Box<FfiPrivateTransactionBody>) -> Result<Self, Self::Error> {
        let OwnedPrivateBody {
            public_context,
            boundary,
            async_messages,
            recovery_bindings,
            public_root,
            private_actions,
            block_validity_window,
            timestamp_validity_window,
            program_image_claims,
            nonces,
            admission_evidence,
            witness_set,
            proof,
        } = value.into();
        Ok(Self {
            message: lee::privacy_preserving_transaction::Message {
                public_context,
                execution: ProvenExecution {
                    boundary,
                    async_messages,
                    recovery_bindings,
                    public_root,
                    private_actions,
                    validity: ValidityWindows {
                        blocks: cast_ffi_validity_window(block_validity_window)?,
                        timestamps: cast_ffi_validity_window(timestamp_validity_window)?,
                    },
                    program_image_claims: program_image_claims
                        .into_iter()
                        .collect::<Result<_, _>>()?,
                },
                nonces: nonces_from_ffi(nonces).map_err(cast_error)?,
                admission_evidence: public_account_evidence(admission_evidence)?,
            },
            witness_set: lee::privacy_preserving_transaction::WitnessSet::from_raw_parts(
                signatures(witness_set)?,
                Proof::from_inner(proof),
            ),
        })
    }
}

#[repr(C)]
pub struct FfiPrivacyPreservingMessage {
    pub public_context: FfiPublicExecutionContext,
    pub boundary: FfiBoundaryStepList,
    pub async_messages: FfiSealedMessageList,
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
            public_context,
            execution:
                ProvenExecution {
                    boundary,
                    async_messages,
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
            public_context: public_context.into(),
            boundary: boundary
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            async_messages: async_messages
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
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
/// - `val` is a valid instance of `FfiTransaction`, its inactive payloads initialized as
///   `sequencer_ffi_send_transaction` requires.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sequencer_ffi_free_ffi_transaction(val: FfiTransaction) {
    match val.kind {
        FfiTransactionKind::Public => {
            drop(OwnedPublicBody::from(unsafe {
                Box::from_raw(val.body.public_body)
            }));
        }
        FfiTransactionKind::Private => {
            drop(OwnedPrivateBody::from(unsafe {
                Box::from_raw(val.body.private_body)
            }));
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

fn owned<T, U: From<T>>(list: FfiVec<T>) -> Vec<U> {
    Vec::from(list).into_iter().map(U::from).collect()
}

fn public_account_evidence(
    entries: Vec<FfiPublicAccountEvidence>,
) -> Result<Vec<PublicAccountEvidence>, OperationStatus> {
    entries
        .into_iter()
        .map(|evidence| PublicAccountEvidence::try_from(evidence).map_err(cast_error))
        .collect()
}

fn signatures(
    entries: Vec<FfiSignaturePubKeyEntry>,
) -> Result<Vec<(Signature, PublicKey)>, OperationStatus> {
    entries
        .into_iter()
        .map(|entry| {
            Ok((
                Signature {
                    value: entry.signature.data,
                },
                PublicKey::try_new(entry.public_key.data).map_err(cast_error)?,
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{
        alloc::{GlobalAlloc, Layout, System},
        cell::Cell,
        collections::{BTreeMap, BTreeSet},
    };

    use ffi_types::FfiNonceEntry;
    use lee::{
        AccountId, Actor, BoundaryStep, Delivery, EphemeralPublicKey, FeeDeclaration,
        MessageEnvelope, PublicExecutionContext, RootCall,
    };
    use lee_core::{
        Commitment, EncryptedNote, SealedMessage, account::Nonce, encryption::Ciphertext,
        program::PdaSeed,
    };

    use super::*;

    thread_local! {
        static LIVE_ALLOCATIONS: Cell<isize> = const { Cell::new(0) };
    }

    #[global_allocator]
    static ALLOCATOR: CountingAllocator = CountingAllocator;

    struct CountingAllocator;

    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let ptr = unsafe { System.alloc(layout) };
            if !ptr.is_null() {
                count_allocations(1);
            }
            ptr
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe {
                System.dealloc(ptr, layout);
            }
            count_allocations(-1);
        }
    }

    fn count_allocations(delta: isize) {
        LIVE_ALLOCATIONS.with(|live| live.set(live.get().saturating_add(delta)));
    }

    fn net_allocations(scenario: impl Fn()) -> isize {
        scenario();
        let before = LIVE_ALLOCATIONS.with(Cell::get);
        scenario();
        LIVE_ALLOCATIONS.with(Cell::get).saturating_sub(before)
    }

    fn account_id(tag: u8) -> AccountId {
        AccountId::new([tag; 32])
    }

    fn actor(account_tag: u8, program_tag: u8) -> Actor {
        Actor {
            account_id: account_id(account_tag),
            program_account_id: account_id(program_tag),
        }
    }

    fn signer() -> PublicKey {
        PublicKey::new_from_private_key(&lee::PrivateKey::try_new([1; 32]).expect("valid key"))
    }

    fn admission_evidence() -> Vec<PublicAccountEvidence> {
        vec![
            PublicAccountEvidence::Key(signer()),
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

    fn public_transaction(fee: Option<FeeDeclaration>) -> PublicTransaction {
        PublicTransaction {
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
        }
    }

    fn private_transaction() -> PrivacyPreservingTransaction {
        // A repeated send to one actor, and not a palindrome: a set would collapse the
        // sequence and a reversal would show, and execution replays them in emission order.
        let repeated = delivery(actor(3, 53), actor(4, 5), 6);
        PrivacyPreservingTransaction {
            message: lee::privacy_preserving_transaction::Message {
                public_context: PublicExecutionContext {
                    promotions: BTreeSet::from([21, 27]),
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
                    async_messages: vec![
                        SealedMessage {
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
                    program_image_claims: vec![
                        ProgramImageClaim::Disclosed {
                            account_id: account_id(30),
                            image_id: [31; 8],
                        },
                        ProgramImageClaim::Undisclosed { root: [32; 32] },
                    ],
                },
                nonces: BTreeMap::from([(account_id(28), Nonce(29))]),
                admission_evidence: admission_evidence(),
            },
            witness_set: lee::privacy_preserving_transaction::WitnessSet::from_raw_parts(
                vec![],
                Proof::from_inner(vec![]),
            ),
        }
    }

    fn signed_public_body(corrupt: fn(&mut FfiPublicTransactionBody)) -> FfiPublicTransactionBody {
        let mut body = FfiPublicTransactionBody::from(PublicTransaction {
            witness_set: lee::public_transaction::WitnessSet::from_raw_parts(vec![(
                Signature { value: [5; 64] },
                signer(),
            )]),
            ..public_transaction(None)
        });
        corrupt(&mut body);
        body
    }

    fn signed_private_body(
        corrupt: fn(&mut FfiPrivateTransactionBody),
    ) -> FfiPrivateTransactionBody {
        let mut body = FfiPrivateTransactionBody::from(PrivacyPreservingTransaction {
            witness_set: lee::privacy_preserving_transaction::WitnessSet::from_raw_parts(
                vec![(Signature { value: [5; 64] }, signer())],
                Proof::from_inner(vec![6; 8]),
            ),
            ..private_transaction()
        });
        corrupt(&mut body);
        body
    }

    fn edit<T>(list: &mut FfiVec<T>, edit: impl FnOnce(&mut Vec<T>)) {
        let mut entries = Vec::from(std::mem::replace(list, Vec::new().into()));
        edit(&mut entries);
        *list = entries.into();
    }

    /// The first claim is the disclosed one.
    fn drop_a_disclosed_image_id(claims: &mut [FfiProgramImageClaim]) {
        let claim = &mut claims[0];
        drop(unsafe { Box::from_raw(claim.image_id.cast_mut()) });
        claim.image_id = std::ptr::null();
    }

    fn duplicate_first_nonce(nonces: &mut Vec<FfiNonceEntry>) {
        let duplicate = FfiNonceEntry {
            account_id: nonces[0].account_id,
            nonce: nonces[0].nonce,
        };
        nonces.push(duplicate);
    }

    fn invalidate_first_key(evidence: &mut [FfiPublicAccountEvidence]) {
        evidence[0].key.data = [0xFF; 32];
    }

    fn invalidate_first_signer(witness_set: &mut [FfiSignaturePubKeyEntry]) {
        witness_set[0].public_key.data = [0xFF; 32];
    }

    fn end_of_subtree_deliveries(
        steps: &mut [FfiBoundaryStep],
    ) -> impl Iterator<Item = &mut FfiDelivery> {
        steps
            .iter_mut()
            .filter(|step| {
                matches!(
                    step.kind,
                    FfiBoundaryStepKind::EndPrivateSubtree | FfiBoundaryStepKind::EndPublicSubtree
                )
            })
            .map(|step| &mut step.delivery)
    }

    fn zero_inactive_payloads(body: &mut FfiPrivateTransactionBody) {
        body.message.has_public_root = false;
        drop(RootCall::from(std::mem::replace(
            &mut body.message.public_root,
            unsafe { std::mem::zeroed() },
        )));
        edit(&mut body.message.boundary, |steps| {
            for slot in end_of_subtree_deliveries(steps) {
                drop(Delivery::<Actor>::from(std::mem::replace(slot, unsafe {
                    std::mem::zeroed()
                })));
            }
        });
    }

    fn fill_inactive_payloads(body: &mut FfiPrivateTransactionBody) {
        body.message.has_public_root = false;
        edit(&mut body.message.boundary, |steps| {
            for slot in end_of_subtree_deliveries(steps) {
                let filled = Delivery {
                    inherited_authorizations: BTreeSet::from([account_id(30)]),
                    pda_seeds: BTreeSet::from([PdaSeed::new([31; 32])]),
                    ..delivery(actor(32, 33), actor(34, 35), 36)
                };
                drop(Delivery::<Actor>::from(std::mem::replace(
                    slot,
                    filled.into(),
                )));
            }
        });
    }

    fn free_public(body: FfiPublicTransactionBody) {
        unsafe {
            sequencer_ffi_free_ffi_transaction(FfiTransaction {
                body: FfiTransactionBody {
                    public_body: Box::into_raw(Box::new(body)),
                    private_body: std::ptr::null_mut(),
                },
                kind: FfiTransactionKind::Public,
            });
        }
    }

    fn free_private(body: FfiPrivateTransactionBody) {
        unsafe {
            sequencer_ffi_free_ffi_transaction(FfiTransaction {
                body: FfiTransactionBody {
                    public_body: std::ptr::null_mut(),
                    private_body: Box::into_raw(Box::new(body)),
                },
                kind: FfiTransactionKind::Private,
            });
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
            assert_eq!(ProgramImageClaim::try_from(ffi), Ok(claim));
        }
    }

    #[test]
    fn a_claim_missing_a_pointer_its_tag_needs_is_a_null_pointer_error() {
        let disclosed_without_ids = FfiProgramImageClaim {
            image_claim_kind: FfiProgramImageClaimKind::Disclosed,
            account_id: std::ptr::null(),
            image_id: std::ptr::null(),
            root: Box::into_raw(Box::new([9; 32])),
        };
        assert_eq!(
            ProgramImageClaim::try_from(disclosed_without_ids),
            Err(OperationStatus::NullPointer)
        );

        let undisclosed_without_root = FfiProgramImageClaim {
            image_claim_kind: FfiProgramImageClaimKind::Undisclosed,
            account_id: std::ptr::null(),
            image_id: std::ptr::null(),
            root: std::ptr::null(),
        };
        assert_eq!(
            ProgramImageClaim::try_from(undisclosed_without_root),
            Err(OperationStatus::NullPointer)
        );
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
            let original = public_transaction(fee);

            let ffi: FfiPublicTransactionBody = original.clone().into();
            let back: PublicTransaction = Box::new(ffi).try_into().unwrap();

            assert_eq!(back.message, original.message);
        }
    }

    #[test]
    fn private_transaction_boundary_entry_and_admission_evidence_roundtrip_over_the_ffi() {
        let original = private_transaction();

        let ffi: FfiPrivateTransactionBody = original.clone().into();
        let back: PrivacyPreservingTransaction = Box::new(ffi).try_into().unwrap();

        assert_eq!(back.message, original.message);
    }

    #[test]
    fn a_rejected_public_body_releases_every_buffer_whether_converted_or_freed() {
        assert!(PublicTransaction::try_from(Box::new(signed_public_body(|_| {}))).is_ok());
        let corruptions: [fn(&mut FfiPublicTransactionBody); 3] = [
            |body| edit(&mut body.message.nonces, duplicate_first_nonce),
            |body| {
                edit(&mut body.message.admission_evidence, |e| {
                    invalidate_first_key(e);
                });
            },
            |body| edit(&mut body.witness_set, |w| invalidate_first_signer(w)),
        ];
        for corrupt in corruptions {
            let converted = || {
                assert!(
                    PublicTransaction::try_from(Box::new(signed_public_body(corrupt))).is_err()
                );
            };
            let freed = || free_public(signed_public_body(corrupt));
            assert_eq!(net_allocations(converted), 0);
            assert_eq!(net_allocations(freed), 0);
        }
    }

    #[test]
    fn a_rejected_private_body_releases_every_buffer_whether_converted_or_freed() {
        assert!(
            PrivacyPreservingTransaction::try_from(Box::new(signed_private_body(|_| {}))).is_ok()
        );
        let corruptions: [fn(&mut FfiPrivateTransactionBody); 5] = [
            |body| body.message.block_validity_window = [5, 3],
            |body| {
                edit(&mut body.message.program_image_claims, |claims| {
                    drop_a_disclosed_image_id(claims);
                });
            },
            |body| edit(&mut body.message.nonces, duplicate_first_nonce),
            |body| {
                edit(&mut body.message.admission_evidence, |e| {
                    invalidate_first_key(e);
                });
            },
            |body| edit(&mut body.witness_set, |w| invalidate_first_signer(w)),
        ];
        for corrupt in corruptions {
            let converted = || {
                assert!(
                    PrivacyPreservingTransaction::try_from(Box::new(signed_private_body(corrupt)))
                        .is_err()
                );
            };
            let freed = || free_private(signed_private_body(corrupt));
            assert_eq!(net_allocations(converted), 0);
            assert_eq!(net_allocations(freed), 0);
        }
    }

    #[test]
    fn inactive_payloads_are_reclaimed_whether_zero_initialized_or_allocated() {
        let shapes: [fn(&mut FfiPrivateTransactionBody); 2] =
            [zero_inactive_payloads, fill_inactive_payloads];
        for shape in shapes {
            let converted = || {
                let transaction =
                    PrivacyPreservingTransaction::try_from(Box::new(signed_private_body(shape)))
                        .unwrap();
                assert_eq!(transaction.message.execution.public_root, None);
            };
            let freed = || free_private(signed_private_body(shape));
            assert_eq!(net_allocations(converted), 0);
            assert_eq!(net_allocations(freed), 0);
        }
    }
}
