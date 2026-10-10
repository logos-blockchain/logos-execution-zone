//! Test-only constructors for otherwise-opaque state types.
//!
//! A [`ValidatedStateDiff`] can normally only be produced by the transaction validation
//! functions, which guarantees it has been checked before any state mutation. These
//! helpers let downstream crates unit-test *post-execution* validation logic — e.g. the
//! system-account and bridge guards in `common` — against a hand-built diff, without
//! running a program in the zkVM.

#[cfg(feature = "test-utils")]
use std::collections::HashMap;
use std::collections::{BTreeMap, BTreeSet};

use lee_core::{
    AuthorizationSecretKey, DUMMY_COMMITMENT_HASH, MembershipProof, NullifierPublicKey,
    NullifierSecretKey, NullifierWitness, PrivateWitness, RecipientEncryption, RegularKey,
    WitnessKind, account::Nonce, encryption::ViewingPublicKey, program::MessageBody,
};

#[cfg(feature = "test-utils")]
use crate::validated_state_diff::{StateDiff, ValidatedStateDiff};
use crate::{Account, AccountId, PrivateKey, PublicKey, error::LeeError};

pub struct TestPrivateKeys {
    pub ask: AuthorizationSecretKey,
    pub d: [u8; 32],
    pub z: [u8; 32],
}

impl TestPrivateKeys {
    #[must_use]
    pub fn nsk(&self) -> NullifierSecretKey {
        (&self.ask).into()
    }

    #[must_use]
    pub fn npk(&self) -> NullifierPublicKey {
        NullifierPublicKey::from(&self.nsk())
    }

    #[must_use]
    pub fn vpk(&self) -> ViewingPublicKey {
        ViewingPublicKey::from_seed(&self.d, &self.z)
    }

    #[must_use]
    pub fn account_id(&self) -> AccountId {
        AccountId::for_regular_private_account(&self.npk(), &self.vpk())
    }
}

/// Each signer's nonce, given in signing order.
#[must_use]
pub fn signer_nonces(signers: &[&PrivateKey], nonces: Vec<Nonce>) -> BTreeMap<AccountId, Nonce> {
    assert_eq!(signers.len(), nonces.len(), "one nonce per signer");
    signers
        .iter()
        .map(|key| AccountId::from(&PublicKey::new_from_private_key(key)))
        .zip(nonces)
        .collect()
}

/// Builds a [`ValidatedStateDiff`] carrying only the given public-account changes.
#[cfg(feature = "test-utils")]
#[must_use]
pub const fn validated_state_diff_from_public_diff(
    public_diff: HashMap<AccountId, Account>,
) -> ValidatedStateDiff {
    ValidatedStateDiff::new_unchecked(StateDiff {
        signer_account_ids: Vec::new(),
        public_diff,
        new_commitments: Vec::new(),
        new_nullifiers: Vec::new(),
        events: Vec::new(),
        published: Vec::new(),
        recovery_bindings: Vec::new(),
    })
}

#[must_use]
pub fn init_witness(keys: &TestPrivateKeys) -> PrivateWitness {
    PrivateWitness {
        vpk: keys.vpk(),
        random_seed: [0; 32],
        kind: WitnessKind::Regular(RegularKey::Authorized(keys.ask)),
        nullifier: NullifierWitness::Init {
            commitment_root: DUMMY_COMMITMENT_HASH,
        },
        openings: BTreeSet::new(),
    }
}

#[must_use]
pub fn update_witness(
    keys: &TestPrivateKeys,
    account: Account,
    membership_proof: MembershipProof,
) -> PrivateWitness {
    PrivateWitness {
        vpk: keys.vpk(),
        random_seed: [0; 32],
        kind: WitnessKind::Regular(RegularKey::Authorized(keys.ask)),
        nullifier: NullifierWitness::Update {
            account,
            membership_proof,
        },
        openings: BTreeSet::new(),
    }
}

pub fn no_seal(body: &MessageBody) -> Result<RecipientEncryption, LeeError> {
    Err(LeeError::InvalidInput(format!(
        "No seal for the durable Cast to {:?}",
        body.to
    )))
}
