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
use crate::{
    Account, AccountId, PrivateKey, PublicAccountEvidence, PublicKey, Signature,
    error::LeeError,
    privacy_preserving_transaction::{self, circuit::Proof},
    public_transaction,
    signature::{PublicAccountSecret, Schnorr, signing_key},
};

/// A public account's signing key material, as tests sign with it.
#[derive(Debug, Clone)]
pub struct TestSigner {
    key: PrivateKey,
}

impl TestSigner {
    #[must_use]
    pub fn new(seed: u8) -> Self {
        Self {
            key: PrivateKey::try_new([seed; 32]).expect("seed gives a valid key"),
        }
    }

    #[must_use]
    pub fn account_id(&self) -> AccountId {
        AccountId::from(&self.public_key())
    }

    #[must_use]
    pub fn evidence(&self) -> PublicAccountEvidence {
        PublicAccountEvidence::Key(self.public_key())
    }

    fn public_key(&self) -> PublicKey {
        PublicKey::new_from_private_key(&self.key)
    }
}

impl From<&PrivateKey> for TestSigner {
    fn from(key: &PrivateKey) -> Self {
        Self { key: key.clone() }
    }
}

impl From<&PublicAccountSecret> for TestSigner {
    fn from(secret: &PublicAccountSecret) -> Self {
        Self {
            key: signing_key::<Schnorr>(secret, Nonce(0)).0,
        }
    }
}

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
pub fn signer_nonces(signers: &[&TestSigner], nonces: Vec<Nonce>) -> BTreeMap<AccountId, Nonce> {
    assert_eq!(signers.len(), nonces.len(), "one nonce per signer");
    signers
        .iter()
        .map(|signer| signer.account_id())
        .zip(nonces)
        .collect()
}

/// The witness of `signers` for `message`; each signer must be named in `message.nonces`.
#[must_use]
pub fn witness_for(
    message: &public_transaction::Message,
    signers: &[&TestSigner],
) -> public_transaction::WitnessSet {
    public_transaction::WitnessSet::for_message(message, &signing_keys(&message.nonces, signers))
}

/// The witness of `signers` for `message`; each signer must be named in `message.nonces`.
#[must_use]
pub fn privacy_witness_for(
    message: &privacy_preserving_transaction::Message,
    proof: Proof,
    signers: &[&TestSigner],
) -> privacy_preserving_transaction::WitnessSet {
    privacy_preserving_transaction::WitnessSet::for_message(
        message,
        proof,
        &signing_keys(&message.nonces, signers),
    )
}

/// One signer's witness entry for `message`, whether or not `message.nonces` names it: for
/// witnesses that deliberately disagree with their message.
#[must_use]
pub fn signed_entry(
    signer: &TestSigner,
    message: &public_transaction::Message,
) -> (Signature, PublicKey) {
    (
        Signature::new(&signer.key, &message.hash()),
        signer.public_key(),
    )
}

/// One signer's witness entry for `message`, whether or not `message.nonces` names it: for
/// witnesses that deliberately disagree with their message.
#[must_use]
pub fn privacy_signed_entry(
    signer: &TestSigner,
    message: &privacy_preserving_transaction::Message,
) -> (Signature, PublicKey) {
    (
        Signature::new(&signer.key, &message.hash()),
        signer.public_key(),
    )
}

fn signing_keys<'signer>(
    nonces: &BTreeMap<AccountId, Nonce>,
    signers: &[&'signer TestSigner],
) -> Vec<&'signer PrivateKey> {
    signers
        .iter()
        .map(|signer| {
            assert!(
                nonces.contains_key(&signer.account_id()),
                "signer {} is not in the message's nonces",
                signer.account_id()
            );
            &signer.key
        })
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
        address_openings: BTreeSet::new(),
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
        address_openings: BTreeSet::new(),
    }
}

pub fn no_seal(body: &MessageBody) -> Result<RecipientEncryption, LeeError> {
    Err(LeeError::InvalidInput(format!(
        "No seal for the durable async message to {:?}",
        body.to
    )))
}
