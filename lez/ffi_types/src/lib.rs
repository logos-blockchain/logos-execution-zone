#![allow(clippy::undocumented_unsafe_blocks, reason = "It is an FFI")]

use std::collections::{BTreeMap, BTreeSet};

use common::HashType;
use indexer_service_protocol as protocol;
use lee::{
    AccountId, Actor, BoundaryStep, Delivery, EphemeralPublicKey, FeeDeclaration, MessageEnvelope,
    PublicAccountEvidence, PublicExecutionContext, PublicKey, RootCall, Signature, error::LeeError,
};
use lee_core::{
    Commitment, EncryptedNote, Nullifier, PrivateAction, RecoveryBinding, SealedCast,
    account::Nonce, encryption::Ciphertext, program::PdaSeed,
};

/// 32-byte array type for `AccountId`, keys, hashes, etc.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct FfiBytes32 {
    pub data: [u8; 32],
}

/// 64-byte array type for signatures, etc.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiBytes64 {
    pub data: [u8; 64],
}

/// U128 - 16 bytes little endian.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FfiU128 {
    pub data: [u8; 16],
}

impl FfiBytes32 {
    /// Create from a 32-byte array.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { data: bytes }
    }

    /// Create from an `AccountId`.
    #[must_use]
    pub const fn from_account_id(id: &lee::AccountId) -> Self {
        Self { data: *id.value() }
    }
}

impl From<u128> for FfiU128 {
    fn from(value: u128) -> Self {
        Self {
            data: value.to_le_bytes(),
        }
    }
}

impl From<FfiU128> for u128 {
    fn from(value: FfiU128) -> Self {
        Self::from_le_bytes(value.data)
    }
}

impl From<Nonce> for FfiU128 {
    fn from(value: Nonce) -> Self {
        value.0.into()
    }
}

impl From<FfiU128> for Nonce {
    fn from(value: FfiU128) -> Self {
        Self(value.into())
    }
}

pub type FfiSignature = FfiBytes64;
pub type FfiAccountId = FfiBytes32;
pub type FfiNonce = FfiU128;
pub type FfiPublicKey = FfiBytes32;

impl From<AccountId> for FfiBytes32 {
    fn from(value: AccountId) -> Self {
        Self {
            data: value.to_bytes(),
        }
    }
}

impl From<&lee::AccountId> for FfiBytes32 {
    fn from(id: &lee::AccountId) -> Self {
        Self::from_account_id(id)
    }
}

impl From<HashType> for FfiBytes32 {
    fn from(value: HashType) -> Self {
        Self { data: value.0 }
    }
}

impl From<FfiBytes32> for HashType {
    fn from(value: FfiBytes32) -> Self {
        Self(value.data)
    }
}

impl From<FfiBytes32> for AccountId {
    fn from(value: FfiBytes32) -> Self {
        Self::new(value.data)
    }
}

impl From<Signature> for FfiSignature {
    fn from(value: Signature) -> Self {
        Self { data: value.value }
    }
}

impl From<PublicKey> for FfiPublicKey {
    fn from(value: PublicKey) -> Self {
        Self {
            data: *value.value(),
        }
    }
}

impl From<protocol::HashType> for FfiBytes32 {
    fn from(value: protocol::HashType) -> Self {
        Self { data: value.0 }
    }
}

impl From<protocol::Signature> for FfiSignature {
    fn from(value: protocol::Signature) -> Self {
        Self { data: value.0 }
    }
}

impl From<protocol::AccountId> for FfiBytes32 {
    fn from(value: protocol::AccountId) -> Self {
        Self { data: value.value }
    }
}

impl From<FfiBytes32> for protocol::AccountId {
    fn from(value: FfiBytes32) -> Self {
        Self { value: value.data }
    }
}

impl From<protocol::PublicKey> for FfiBytes32 {
    fn from(value: protocol::PublicKey) -> Self {
        Self { data: value.0 }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct FfiVec<T> {
    pub entries: *mut T,
    pub len: usize,
    pub capacity: usize,
}

impl<T> From<Vec<T>> for FfiVec<T> {
    fn from(value: Vec<T>) -> Self {
        let (entries, len, capacity) = value.into_raw_parts();
        Self {
            entries,
            len,
            capacity,
        }
    }
}

impl<T> From<FfiVec<T>> for Vec<T> {
    fn from(value: FfiVec<T>) -> Self {
        unsafe { Self::from_raw_parts(value.entries, value.len, value.capacity) }
    }
}

impl<T> FfiVec<T> {
    /// # Safety
    ///
    /// `index` must be lesser than `self.len`.
    #[must_use]
    pub unsafe fn get(&self, index: usize) -> &T {
        let ptr = unsafe { self.entries.add(index) };
        unsafe { &*ptr }
    }
}

pub type FfiVecU8 = FfiVec<u8>;

pub type FfiActorList = FfiVec<FfiActor>;

pub type FfiAccountIdList = FfiVec<FfiAccountId>;

pub type FfiNonceList = FfiVec<FfiNonceEntry>;

pub type FfiMessageDataList = FfiVec<u8>;

pub type FfiSignaturePubKeyList = FfiVec<FfiSignaturePubKeyEntry>;

pub type FfiBoundaryStepList = FfiVec<FfiBoundaryStep>;

pub type FfiSealedCastList = FfiVec<FfiSealedCast>;

pub type FfiPublicAccountEvidenceList = FfiVec<FfiPublicAccountEvidence>;

pub type FfiPrivateActionList = FfiVec<FfiPrivateAction>;

pub type FfiRecoveryBindingList = FfiVec<FfiRecoveryBinding>;

pub type FfiPdaSeedList = FfiVec<FfiBytes32>;

pub type FfiCastPromotionList = FfiVec<u64>;

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

/// Identifies one of an account's program actor states.
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

/// One signer's replay nonce.
#[repr(C)]
pub struct FfiNonceEntry {
    pub account_id: FfiAccountId,
    pub nonce: FfiNonce,
}

impl From<(AccountId, Nonce)> for FfiNonceEntry {
    fn from((account_id, nonce): (AccountId, Nonce)) -> Self {
        Self {
            account_id: account_id.into(),
            nonce: nonce.into(),
        }
    }
}

impl From<(protocol::AccountId, u128)> for FfiNonceEntry {
    fn from((account_id, nonce): (protocol::AccountId, u128)) -> Self {
        Self {
            account_id: account_id.into(),
            nonce: nonce.into(),
        }
    }
}

impl From<FfiNonceEntry> for (protocol::AccountId, u128) {
    fn from(value: FfiNonceEntry) -> Self {
        (value.account_id.into(), value.nonce.into())
    }
}

impl TryFrom<FfiNonceList> for BTreeMap<AccountId, Nonce> {
    type Error = LeeError;

    fn try_from(value: FfiNonceList) -> Result<Self, Self::Error> {
        let entries: Vec<FfiNonceEntry> = value.into();
        Ok(lee::nonce_map(entries.into_iter().map(|entry| {
            (entry.account_id.into(), entry.nonce.into())
        }))?)
    }
}

/// How a proven transaction starts, as far as its proof discloses: a Call to a public actor.
#[repr(C)]
pub struct FfiRootCall {
    pub to: FfiActor,
    pub message: FfiMessageDataList,
}

impl From<RootCall> for FfiRootCall {
    fn from(value: RootCall) -> Self {
        Self {
            to: value.to.into(),
            message: value.message.into(),
        }
    }
}

impl From<FfiRootCall> for RootCall {
    fn from(value: FfiRootCall) -> Self {
        Self {
            to: value.to.into(),
            message: value.message.into(),
        }
    }
}

#[repr(C)]
pub enum FfiPublicAccountEvidenceKind {
    Key = 0x0,
    Pda,
}

#[repr(C)]
pub struct FfiPublicAccountEvidence {
    pub kind: FfiPublicAccountEvidenceKind,
    pub key: FfiPublicKey,
    pub program: FfiAccountId,
    pub seed: FfiBytes32,
}

impl From<PublicAccountEvidence> for FfiPublicAccountEvidence {
    fn from(value: PublicAccountEvidence) -> Self {
        match value {
            PublicAccountEvidence::Key(key) => Self {
                kind: FfiPublicAccountEvidenceKind::Key,
                key: key.into(),
                program: FfiAccountId::default(),
                seed: FfiBytes32::default(),
            },
            PublicAccountEvidence::Pda { program, seed } => Self {
                kind: FfiPublicAccountEvidenceKind::Pda,
                key: FfiPublicKey::default(),
                program: program.into(),
                seed: pda_seed_to_ffi(seed),
            },
        }
    }
}

impl TryFrom<FfiPublicAccountEvidence> for PublicAccountEvidence {
    type Error = LeeError;

    fn try_from(value: FfiPublicAccountEvidence) -> Result<Self, Self::Error> {
        match value.kind {
            FfiPublicAccountEvidenceKind::Key => PublicKey::try_new(value.key.data).map(Self::Key),
            FfiPublicAccountEvidenceKind::Pda => Ok(Self::Pda {
                program: value.program.into(),
                seed: ffi_to_pda_seed(value.seed),
            }),
        }
    }
}

#[repr(C)]
pub struct FfiDelivery {
    pub from: FfiActor,
    pub to: FfiActor,
    pub message: FfiMessageDataList,
    pub inherited_authorizations: FfiAccountIdList,
    pub inherits_entry_authorizations: bool,
    pub pda_seeds: FfiPdaSeedList,
}

impl From<Delivery<Actor>> for FfiDelivery {
    fn from(value: Delivery<Actor>) -> Self {
        let Delivery {
            envelope: MessageEnvelope { from, to, message },
            inherited_authorizations,
            inherits_entry_authorizations,
            pda_seeds,
        } = value;

        Self {
            from: from.into(),
            to: to.into(),
            message: message.into(),
            inherited_authorizations: inherited_authorizations_to_ffi(inherited_authorizations),
            inherits_entry_authorizations,
            pda_seeds: pda_seeds
                .into_iter()
                .map(pda_seed_to_ffi)
                .collect::<Vec<_>>()
                .into(),
        }
    }
}

impl From<FfiDelivery> for Delivery<Actor> {
    fn from(value: FfiDelivery) -> Self {
        Self {
            envelope: MessageEnvelope {
                from: value.from.into(),
                to: value.to.into(),
                message: value.message.into(),
            },
            inherited_authorizations: inherited_authorizations_from_ffi(
                value.inherited_authorizations,
            ),
            inherits_entry_authorizations: value.inherits_entry_authorizations,
            pda_seeds: {
                let std_vec: Vec<_> = value.pda_seeds.into();
                std_vec.into_iter().map(ffi_to_pda_seed).collect()
            },
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub enum FfiBoundaryStepKind {
    PrivateToPublic = 0,
    PublicToPrivate,
    EndPrivateSubtree,
    EndPublicSubtree,
}

/// One step of a proof's boundary trace (`delivery`, meaningful only for `PrivateToPublic` and
/// `PublicToPrivate`).
#[repr(C)]
pub struct FfiBoundaryStep {
    pub kind: FfiBoundaryStepKind,
    pub delivery: FfiDelivery,
}

impl From<BoundaryStep> for FfiBoundaryStep {
    fn from(value: BoundaryStep) -> Self {
        let (kind, delivery) = match value {
            BoundaryStep::PrivateToPublic(delivery) => {
                (FfiBoundaryStepKind::PrivateToPublic, delivery.into())
            }
            BoundaryStep::PublicToPrivate(delivery) => {
                (FfiBoundaryStepKind::PublicToPrivate, delivery.into())
            }
            BoundaryStep::EndPrivateSubtree => {
                (FfiBoundaryStepKind::EndPrivateSubtree, empty_delivery())
            }
            BoundaryStep::EndPublicSubtree => {
                (FfiBoundaryStepKind::EndPublicSubtree, empty_delivery())
            }
        };
        Self { kind, delivery }
    }
}

impl From<FfiBoundaryStep> for BoundaryStep {
    fn from(value: FfiBoundaryStep) -> Self {
        match value.kind {
            FfiBoundaryStepKind::PrivateToPublic => Self::PrivateToPublic(value.delivery.into()),
            FfiBoundaryStepKind::PublicToPrivate => Self::PublicToPrivate(value.delivery.into()),
            FfiBoundaryStepKind::EndPrivateSubtree => Self::EndPrivateSubtree,
            FfiBoundaryStepKind::EndPublicSubtree => Self::EndPublicSubtree,
        }
    }
}

/// One Cast a proof publishes.
#[repr(C)]
pub struct FfiSealedCast {
    pub commitment: FfiBytes32,
    pub epk: FfiVecU8,
    pub ciphertext: FfiVecU8,
}

impl From<SealedCast> for FfiSealedCast {
    fn from(value: SealedCast) -> Self {
        let SealedCast {
            commitment,
            note: EncryptedNote { epk, ciphertext },
        } = value;

        Self {
            commitment: FfiBytes32::from_bytes(commitment.to_byte_array()),
            epk: epk.0.into(),
            ciphertext: ciphertext.into_inner().into(),
        }
    }
}

impl From<FfiSealedCast> for SealedCast {
    fn from(value: FfiSealedCast) -> Self {
        Self {
            commitment: Commitment::from_byte_array(value.commitment.data),
            note: EncryptedNote {
                epk: EphemeralPublicKey(value.epk.into()),
                ciphertext: Ciphertext::from_inner(value.ciphertext.into()),
            },
        }
    }
}

#[repr(C)]
pub struct FfiPublicExecutionContext {
    pub actors: FfiActorList,
    pub authorized_accounts: FfiAccountIdList,
    pub cast_promotions: FfiCastPromotionList,
}

impl From<PublicExecutionContext> for FfiPublicExecutionContext {
    fn from(value: PublicExecutionContext) -> Self {
        let PublicExecutionContext {
            actors,
            authorized_accounts,
            cast_promotions,
        } = value;

        Self {
            actors: actors
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            authorized_accounts: authorized_accounts
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>()
                .into(),
            cast_promotions: cast_promotions.into_iter().collect::<Vec<_>>().into(),
        }
    }
}

impl From<FfiPublicExecutionContext> for PublicExecutionContext {
    fn from(value: FfiPublicExecutionContext) -> Self {
        let actors: Vec<FfiActor> = value.actors.into();
        let authorized_accounts: Vec<FfiAccountId> = value.authorized_accounts.into();
        let cast_promotions: Vec<u64> = value.cast_promotions.into();

        Self {
            actors: actors.into_iter().map(Into::into).collect(),
            authorized_accounts: authorized_accounts.into_iter().map(Into::into).collect(),
            cast_promotions: cast_promotions.into_iter().collect(),
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

impl From<FfiPrivateAction> for PrivateAction {
    fn from(value: FfiPrivateAction) -> Self {
        Self {
            nullifier: Nullifier::from_byte_array(value.nullifier.data),
            root: value.root.data,
            commitment: Commitment::from_byte_array(value.commitment.data),
            encrypted_post_state: EncryptedNote {
                ciphertext: Ciphertext::from_inner(value.encrypted_post_state.ciphertext.into()),
                epk: EphemeralPublicKey(value.encrypted_post_state.epk.into()),
            },
        }
    }
}

#[repr(C)]
pub struct FfiRecoveryBinding {
    pub address: FfiAccountId,
    pub epk: FfiVecU8,
    pub ciphertext: FfiVecU8,
}

impl From<RecoveryBinding> for FfiRecoveryBinding {
    fn from(value: RecoveryBinding) -> Self {
        let RecoveryBinding {
            address,
            note: EncryptedNote { epk, ciphertext },
        } = value;

        Self {
            address: address.into(),
            epk: epk.0.into(),
            ciphertext: ciphertext.into_inner().into(),
        }
    }
}

impl From<FfiRecoveryBinding> for RecoveryBinding {
    fn from(value: FfiRecoveryBinding) -> Self {
        Self {
            address: value.address.into(),
            note: EncryptedNote {
                epk: EphemeralPublicKey(value.epk.into()),
                ciphertext: Ciphertext::from_inner(value.ciphertext.into()),
            },
        }
    }
}

#[repr(C)]
pub struct FfiEncryptedAccountData {
    pub ciphertext: FfiVecU8,
    pub epk: FfiVecU8,
}

impl From<EncryptedNote> for FfiEncryptedAccountData {
    fn from(value: EncryptedNote) -> Self {
        let EncryptedNote { ciphertext, epk } = value;

        Self {
            ciphertext: ciphertext.into_inner().into(),
            epk: epk.0.into(),
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

#[must_use]
pub fn empty_root_call() -> FfiRootCall {
    FfiRootCall {
        to: FfiActor::default(),
        message: Vec::new().into(),
    }
}

fn empty_delivery() -> FfiDelivery {
    FfiDelivery {
        from: FfiActor::default(),
        to: FfiActor::default(),
        message: Vec::new().into(),
        inherited_authorizations: Vec::new().into(),
        inherits_entry_authorizations: false,
        pda_seeds: Vec::new().into(),
    }
}

fn inherited_authorizations_to_ffi(
    inherited_authorizations: BTreeSet<AccountId>,
) -> FfiAccountIdList {
    inherited_authorizations
        .into_iter()
        .map(Into::into)
        .collect::<Vec<_>>()
        .into()
}

fn inherited_authorizations_from_ffi(
    inherited_authorizations: FfiAccountIdList,
) -> BTreeSet<AccountId> {
    let std_vec: Vec<FfiAccountId> = inherited_authorizations.into();
    std_vec.into_iter().map(Into::into).collect()
}

const fn pda_seed_to_ffi(seed: PdaSeed) -> FfiBytes32 {
    FfiBytes32::from_bytes(*seed.as_bytes())
}

const fn ffi_to_pda_seed(seed: FfiBytes32) -> PdaSeed {
    PdaSeed::new(seed.data)
}
