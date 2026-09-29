use common::transaction::LeeTransaction;
use lee::{
    AccountId, Actor, Assumption, Boundary, Declared, EphemeralPublicKey, FeeDeclaration, Origin,
    Output, PrivacyPreservingTransaction, PublicKey, PublicTransaction, ScheduleOp, Signature,
    privacy_preserving_transaction::{circuit::Proof, message::EncryptedAccountData},
};
use lee_core::{
    Commitment, Nullifier, PrivateAction, ProgramImageClaim,
    encryption::Ciphertext,
    program::{PdaSeed, ValidityWindow},
};
use sequencer_executor_actor::protocol::Transaction;

use crate::{
    OperationStatus,
    api::types::{
        FfiAccountId, FfiBytes32, FfiHashType, FfiOption, FfiPublicKey, FfiSignature, FfiU128,
        FfiVec,
        vectors::{
            FfiAccountIdList, FfiActorList, FfiAssumptionList, FfiMessageDataList, FfiNonceList,
            FfiOutputList, FfiPdaSeedList, FfiPrivateActionList, FfiProof, FfiScheduleOpList,
            FfiSignaturePubKeyList, FfiVecU8,
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
                to: value.message.to.into(),
                message: value.message.message.into(),
                public_actors: {
                    let std_vec: Vec<FfiActor> = value.message.public_actors.into();
                    std_vec.into_iter().map(Into::into).collect()
                },
                nonces: {
                    let std_vec: Vec<_> = value.message.nonces.into();
                    std_vec.into_iter().map(Into::into).collect()
                },
                fee: value.message.has_fee.then(|| value.message.fee.into()),
            },
            witness_set: lee::public_transaction::WitnessSet::from_raw_parts({
                let std_vec: Vec<_> = value.witness_set.into();

                let mut cast_vec = vec![];

                for ffi_val in std_vec {
                    cast_vec.push((
                        Signature {
                            value: ffi_val.signature.data,
                        },
                        PublicKey::try_new(ffi_val.public_key.data).map_err(|e| {
                            log::error!("Failed to cast `[u8; 32]` into PublicKey, err: {e}");
                            OperationStatus::CastError
                        })?,
                    ));
                }

                cast_vec
            }),
        })
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

/// Identifies one of an account's program shards.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FfiActor {
    pub account_id: FfiAccountId,
    pub program_account_id: FfiAccountId,
}

impl From<Actor> for FfiActor {
    fn from(value: Actor) -> Self {
        let Actor {
            account_id,
            program_account_id,
        } = value;

        Self {
            account_id: account_id.into(),
            program_account_id: program_account_id.into(),
        }
    }
}

impl From<FfiActor> for Actor {
    fn from(value: FfiActor) -> Self {
        Self {
            account_id: value.account_id.into(),
            program_account_id: value.program_account_id.into(),
        }
    }
}

#[repr(C)]
pub struct FfiPublicMessage {
    pub to: FfiActor,
    pub message: FfiMessageDataList,
    pub public_actors: FfiActorList,
    pub nonces: FfiNonceList,
    pub has_fee: bool,
    pub fee: FfiFeeDeclaration,
}

impl From<lee::public_transaction::Message> for FfiPublicMessage {
    fn from(value: lee::public_transaction::Message) -> Self {
        let lee::public_transaction::Message {
            to,
            message,
            public_actors,
            nonces,
            fee,
        } = value;

        Self {
            to: to.into(),
            message: message.into(),
            public_actors: public_actors
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            nonces: nonces
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            has_fee: fee.is_some(),
            fee: fee.map(Into::into).unwrap_or_default(),
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
                image_claim_kind: FfiProgramImageClaimKind::Disclosed,
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
        Ok(Self {
            message: lee::privacy_preserving_transaction::Message {
                declared: value.message.declared.into(),
                boundary: value.message.boundary.into(),
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
                )?,
                timestamp_validity_window: cast_ffi_validity_window(
                    value.message.timestamp_validity_window,
                )?,
                program_image_claims: {
                    let std_vec: Vec<_> = value.message.program_image_claims.into();
                    std_vec.into_iter().map(Into::into).collect()
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
                            PublicKey::try_new(ffi_val.public_key.data).map_err(|e| {
                                log::error!("Failed to cast `[u8; 32]` into PublicKey, err: {e}");
                                OperationStatus::CastError
                            })?,
                        ));
                    }

                    cast_vec
                },
                Proof::from_inner(value.proof.into()),
            ),
        })
    }
}

/// Where a delivery came from: the root, or the program that sent it
/// (`program_account_id`, meaningful when `is_root` is false).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiOrigin {
    pub is_root: bool,
    pub program_account_id: FfiAccountId,
}

impl From<Origin> for FfiOrigin {
    fn from(value: Origin) -> Self {
        match value {
            Origin::Root => Self {
                is_root: true,
                program_account_id: FfiAccountId::default(),
            },
            Origin::Program(program) => Self {
                is_root: false,
                program_account_id: program.into(),
            },
        }
    }
}

impl From<FfiOrigin> for Origin {
    fn from(value: FfiOrigin) -> Self {
        if value.is_root {
            Self::Root
        } else {
            Self::Program(value.program_account_id.into())
        }
    }
}

#[repr(C)]
pub struct FfiOutput {
    pub to: FfiActor,
    pub message: FfiMessageDataList,
    pub origin: FfiOrigin,
    pub grants: FfiAccountIdList,
    pub pda_seeds: FfiPdaSeedList,
}

impl From<Output> for FfiOutput {
    fn from(value: Output) -> Self {
        let Output {
            to,
            message,
            origin,
            grants,
            pda_seeds,
        } = value;

        Self {
            to: to.into(),
            message: message.into(),
            origin: origin.into(),
            grants: grants_to_ffi(grants),
            pda_seeds: pda_seeds
                .into_iter()
                .map(pda_seed_to_ffi)
                .collect::<Vec<_>>()
                .into(),
        }
    }
}

impl From<FfiOutput> for Output {
    fn from(value: FfiOutput) -> Self {
        Self {
            to: value.to.into(),
            message: value.message.into(),
            origin: value.origin.into(),
            grants: grants_from_ffi(value.grants),
            pda_seeds: {
                let std_vec: Vec<_> = value.pda_seeds.into();
                std_vec.into_iter().map(ffi_to_pda_seed).collect()
            },
        }
    }
}

#[repr(C)]
pub struct FfiAssumption {
    pub from: FfiActor,
    pub to: FfiActor,
    pub message: FfiMessageDataList,
    pub grants: FfiAccountIdList,
    pub pda_seeds: FfiPdaSeedList,
}

impl From<Assumption> for FfiAssumption {
    fn from(value: Assumption) -> Self {
        let Assumption {
            from,
            to,
            message,
            grants,
            pda_seeds,
        } = value;

        Self {
            from: from.into(),
            to: to.into(),
            message: message.into(),
            grants: grants_to_ffi(grants),
            pda_seeds: pda_seeds
                .into_iter()
                .map(pda_seed_to_ffi)
                .collect::<Vec<_>>()
                .into(),
        }
    }
}

impl From<FfiAssumption> for Assumption {
    fn from(value: FfiAssumption) -> Self {
        Self {
            from: value.from.into(),
            to: value.to.into(),
            message: value.message.into(),
            grants: grants_from_ffi(value.grants),
            pda_seeds: {
                let std_vec: Vec<_> = value.pda_seeds.into();
                std_vec.into_iter().map(ffi_to_pda_seed).collect()
            },
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub enum FfiScheduleOp {
    CallPublic = 0,
    EnterPrivate,
    LeavePrivate,
    ReturnPublic,
}

impl From<ScheduleOp> for FfiScheduleOp {
    fn from(value: ScheduleOp) -> Self {
        match value {
            ScheduleOp::CallPublic => Self::CallPublic,
            ScheduleOp::EnterPrivate => Self::EnterPrivate,
            ScheduleOp::LeavePrivate => Self::LeavePrivate,
            ScheduleOp::ReturnPublic => Self::ReturnPublic,
        }
    }
}

impl From<FfiScheduleOp> for ScheduleOp {
    fn from(value: FfiScheduleOp) -> Self {
        match value {
            FfiScheduleOp::CallPublic => Self::CallPublic,
            FfiScheduleOp::EnterPrivate => Self::EnterPrivate,
            FfiScheduleOp::LeavePrivate => Self::LeavePrivate,
            FfiScheduleOp::ReturnPublic => Self::ReturnPublic,
        }
    }
}

#[repr(C)]
pub struct FfiBoundary {
    pub outputs: FfiOutputList,
    pub assumptions: FfiAssumptionList,
    pub schedule: FfiScheduleOpList,
}

impl From<Boundary> for FfiBoundary {
    fn from(value: Boundary) -> Self {
        let Boundary {
            outputs,
            assumptions,
            schedule,
        } = value;

        Self {
            outputs: outputs
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            assumptions: assumptions
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            schedule: schedule
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
        }
    }
}

impl From<FfiBoundary> for Boundary {
    fn from(value: FfiBoundary) -> Self {
        let outputs: Vec<FfiOutput> = value.outputs.into();
        let assumptions: Vec<FfiAssumption> = value.assumptions.into();
        let schedule: Vec<FfiScheduleOp> = value.schedule.into();

        Self {
            outputs: outputs.into_iter().map(Into::into).collect(),
            assumptions: assumptions.into_iter().map(Into::into).collect(),
            schedule: schedule.into_iter().map(Into::into).collect(),
        }
    }
}

#[repr(C)]
pub struct FfiDeclared {
    pub public_actors: FfiActorList,
    pub authorized_accounts: FfiAccountIdList,
}

impl From<Declared> for FfiDeclared {
    fn from(value: Declared) -> Self {
        let Declared {
            public_actors,
            authorized_accounts,
        } = value;

        Self {
            public_actors: public_actors
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            authorized_accounts: authorized_accounts
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
        }
    }
}

impl From<FfiDeclared> for Declared {
    fn from(value: FfiDeclared) -> Self {
        let public_actors: Vec<FfiActor> = value.public_actors.into();
        let authorized_accounts: Vec<FfiAccountId> = value.authorized_accounts.into();

        Self {
            public_actors: public_actors.into_iter().map(Into::into).collect(),
            authorized_accounts: authorized_accounts.into_iter().map(Into::into).collect(),
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
    pub declared: FfiDeclared,
    pub boundary: FfiBoundary,
    pub nonces: FfiNonceList,
    pub private_actions: FfiPrivateActionList,
    pub block_validity_window: [u64; 2],
    pub timestamp_validity_window: [u64; 2],
    pub program_image_claims: FfiProgramImageClaims,
}

impl From<lee::privacy_preserving_transaction::Message> for FfiPrivacyPreservingMessage {
    fn from(value: lee::privacy_preserving_transaction::Message) -> Self {
        let lee::privacy_preserving_transaction::Message {
            declared,
            boundary,
            nonces,
            private_actions,
            block_validity_window,
            timestamp_validity_window,
            program_image_claims,
        } = value;

        Self {
            declared: declared.into(),
            boundary: boundary.into(),
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
            program_image_claims: program_image_claims
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
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

fn grants_to_ffi(grants: Vec<AccountId>) -> FfiAccountIdList {
    grants
        .into_iter()
        .map(Into::into)
        .collect::<Vec<_>>()
        .into()
}

fn grants_from_ffi(grants: FfiAccountIdList) -> Vec<AccountId> {
    let std_vec: Vec<FfiAccountId> = grants.into();
    std_vec.into_iter().map(Into::into).collect()
}

const fn pda_seed_to_ffi(seed: PdaSeed) -> FfiBytes32 {
    FfiBytes32::from_bytes(*seed.as_bytes())
}

const fn ffi_to_pda_seed(seed: FfiBytes32) -> PdaSeed {
    PdaSeed::new(seed.data)
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
    use super::*;

    #[test]
    fn public_transaction_fee_roundtrips_over_the_ffi() {
        let to = Actor {
            account_id: AccountId::new([3; 32]),
            program_account_id: AccountId::new([42; 32]),
        };
        let tx = |fee| PublicTransaction {
            message: lee::public_transaction::Message {
                to,
                message: vec![9, 9],
                public_actors: vec![to],
                nonces: vec![],
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
            let back: PublicTransaction = Box::new(ffi).try_into().unwrap();
            assert_eq!(back.message.fee, original.message.fee);
        }
    }
}
