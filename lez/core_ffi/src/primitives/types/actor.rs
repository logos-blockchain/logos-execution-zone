use std::collections::{BTreeMap, BTreeSet};

use lee::{
    AccountId, Actor, BoundaryStep, Delivery, EncryptedNote, EphemeralPublicKey, MessageEnvelope,
    PublicAccountEvidence, PublicExecutionContext, PublicKey, RecoveryBinding, RootCall,
    SealedMessage, Signature, error::LeeError,
};
use lee_core::{
    Commitment, Nullifier, PrivateAction, account::Nonce, encryption::Ciphertext, program::PdaSeed,
};

use crate::primitives::types::{
    FfiAccountId, FfiBytes32, FfiNonce, FfiPublicKey, FfiSignature,
    vectors::{
        FfiAccountIdList, FfiActorList, FfiMessageDataList, FfiPdaSeedList, FfiPromotionList,
        FfiVecU8,
    },
};

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

/// How a proven transaction starts, as far as its proof discloses: a call to a public actor.
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

/// One step of a proof's boundary trace. `delivery` is read and freed for every kind, so an
/// `EndPrivateSubtree` or `EndPublicSubtree` step must carry an initialized, empty one.
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
        let delivery = Delivery::from(value.delivery);
        match value.kind {
            FfiBoundaryStepKind::PrivateToPublic => Self::PrivateToPublic(delivery),
            FfiBoundaryStepKind::PublicToPrivate => Self::PublicToPrivate(delivery),
            FfiBoundaryStepKind::EndPrivateSubtree => Self::EndPrivateSubtree,
            FfiBoundaryStepKind::EndPublicSubtree => Self::EndPublicSubtree,
        }
    }
}

/// One async message a proof publishes.
#[repr(C)]
pub struct FfiSealedMessage {
    pub commitment: FfiBytes32,
    pub epk: FfiVecU8,
    pub ciphertext: FfiVecU8,
}

impl From<SealedMessage> for FfiSealedMessage {
    fn from(value: SealedMessage) -> Self {
        let SealedMessage {
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

impl From<FfiSealedMessage> for SealedMessage {
    fn from(value: FfiSealedMessage) -> Self {
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
    pub promotions: FfiPromotionList,
}

impl From<PublicExecutionContext> for FfiPublicExecutionContext {
    fn from(value: PublicExecutionContext) -> Self {
        let PublicExecutionContext {
            actors,
            authorized_accounts,
            promotions,
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
            promotions: promotions.into_iter().collect::<Vec<_>>().into(),
        }
    }
}

impl From<FfiPublicExecutionContext> for PublicExecutionContext {
    fn from(value: FfiPublicExecutionContext) -> Self {
        let actors: Vec<FfiActor> = value.actors.into();
        let authorized_accounts: Vec<FfiAccountId> = value.authorized_accounts.into();
        let promotions: Vec<u64> = value.promotions.into();

        Self {
            actors: actors.into_iter().map(Into::into).collect(),
            authorized_accounts: authorized_accounts.into_iter().map(Into::into).collect(),
            promotions: promotions.into_iter().collect(),
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

pub fn nonces_from_ffi(
    entries: Vec<FfiNonceEntry>,
) -> Result<BTreeMap<AccountId, Nonce>, LeeError> {
    Ok(lee::nonce_map(entries.into_iter().map(|entry| {
        (entry.account_id.into(), entry.nonce.into())
    }))?)
}

const fn pda_seed_to_ffi(seed: PdaSeed) -> FfiBytes32 {
    FfiBytes32::from_bytes(*seed.as_bytes())
}

const fn ffi_to_pda_seed(seed: FfiBytes32) -> PdaSeed {
    PdaSeed::new(seed.data)
}

#[cfg(test)]
mod tests {
    use lee::FeeDeclaration;

    use super::*;
    use crate::primitives::types::FfiFeeDeclaration;

    fn account_id(tag: u8) -> AccountId {
        AccountId::new([tag; 32])
    }

    fn actor(account_tag: u8, program_tag: u8) -> Actor {
        Actor {
            account_id: account_id(account_tag),
            program_account_id: account_id(program_tag),
        }
    }

    fn note(epk_tag: u8, ciphertext_tag: u8) -> EncryptedNote {
        EncryptedNote {
            epk: EphemeralPublicKey(vec![epk_tag; 2]),
            ciphertext: Ciphertext::from_inner(vec![ciphertext_tag; 3]),
        }
    }

    fn roundtrip<C, T>(value: T) -> T
    where
        T: Into<C>,
        C: Into<T>,
    {
        let ffi: C = value.into();
        ffi.into()
    }

    #[test]
    fn boundary_steps_decode_only_the_payload_their_kind_selects() {
        let delivery = Delivery {
            envelope: MessageEnvelope {
                from: actor(1, 51),
                to: actor(2, 3),
                message: vec![4],
            },
            inherited_authorizations: BTreeSet::from([account_id(5)]),
            inherits_entry_authorizations: true,
            pda_seeds: BTreeSet::from([PdaSeed::new([6; 32])]),
        };
        let cross_message = Delivery {
            envelope: MessageEnvelope {
                from: actor(7, 8),
                to: actor(9, 10),
                message: vec![11],
            },
            inherited_authorizations: BTreeSet::from([account_id(12)]),
            inherits_entry_authorizations: false,
            pda_seeds: BTreeSet::from([PdaSeed::new([13; 32])]),
        };

        let steps = [
            FfiBoundaryStep {
                kind: FfiBoundaryStepKind::PrivateToPublic,
                delivery: delivery.clone().into(),
            },
            FfiBoundaryStep {
                kind: FfiBoundaryStepKind::PublicToPrivate,
                delivery: cross_message.clone().into(),
            },
            FfiBoundaryStep {
                kind: FfiBoundaryStepKind::EndPrivateSubtree,
                delivery: empty_delivery(),
            },
            FfiBoundaryStep {
                kind: FfiBoundaryStepKind::EndPublicSubtree,
                delivery: empty_delivery(),
            },
        ];

        assert_eq!(
            steps.map(BoundaryStep::from),
            [
                BoundaryStep::PrivateToPublic(delivery),
                BoundaryStep::PublicToPrivate(cross_message),
                BoundaryStep::EndPrivateSubtree,
                BoundaryStep::EndPublicSubtree,
            ]
        );
    }

    #[test]
    fn each_shared_component_roundtrips_over_the_ffi() {
        let public_context = PublicExecutionContext {
            actors: BTreeSet::from([actor(1, 2), actor(3, 4)]),
            authorized_accounts: BTreeSet::from([account_id(5), account_id(6)]),
            promotions: BTreeSet::from([7, 8]),
        };
        let sealed = SealedMessage {
            commitment: Commitment::from_byte_array([9; 32]),
            note: note(10, 11),
        };
        let binding = RecoveryBinding {
            address: account_id(12),
            note: note(13, 14),
        };
        let root = RootCall {
            to: actor(15, 16),
            message: vec![17; 2],
        };
        let fee = FeeDeclaration {
            payer: account_id(18),
            gas_limit: 5,
            tip: 1,
            max_fee: 42,
        };
        let signer = lee::PrivateKey::try_new([1; 32]).expect("valid key");

        assert_eq!(
            roundtrip::<FfiPublicExecutionContext, _>(public_context.clone()),
            public_context
        );
        assert_eq!(roundtrip::<FfiSealedMessage, _>(sealed.clone()), sealed);
        assert_eq!(roundtrip::<FfiRecoveryBinding, _>(binding.clone()), binding);
        assert_eq!(roundtrip::<FfiRootCall, _>(root.clone()), root);
        assert_eq!(roundtrip::<FfiFeeDeclaration, _>(fee), fee);
        for evidence in [
            PublicAccountEvidence::Key(PublicKey::new_from_private_key(&signer)),
            PublicAccountEvidence::Pda {
                program: account_id(19),
                seed: PdaSeed::new([20; 32]),
            },
        ] {
            let ffi = FfiPublicAccountEvidence::from(evidence.clone());
            assert_eq!(PublicAccountEvidence::try_from(ffi).unwrap(), evidence);
        }
    }
}
