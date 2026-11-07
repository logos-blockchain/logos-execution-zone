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
    WitnessKind,
    account::Nonce,
    encryption::ViewingPublicKey,
    program::MessageBody,
    signing_key::{KeyType, SigningKeyState},
};

#[cfg(feature = "test-utils")]
use crate::validated_state_diff::{StateDiff, ValidatedStateDiff};
use crate::{
    Account, AccountId, PublicAccountEvidence,
    error::LeeError,
    privacy_preserving_transaction::{self, circuit::Proof},
    public_transaction::{self, WitnessEntry},
    signature::{
        INITIAL_KEY_TYPE, PublicAccountSecret, Signer, initial_key, key_state, public_account_id,
    },
};

/// A public account's signing key material, as tests sign with it: its initial key type at
/// nonce 0, and any rotations to other types from given nonces on.
#[derive(Debug, Clone)]
pub struct TestSigner {
    secret: PublicAccountSecret,
    rotations: Vec<(Nonce, KeyType)>,
}

impl TestSigner {
    #[must_use]
    pub const fn new(seed: u8) -> Self {
        Self {
            secret: PublicAccountSecret::new([seed; 32]),
            rotations: Vec::new(),
        }
    }

    /// Signs with `key_type` from `from` on (until a later rotation).
    #[must_use]
    pub fn rotating_to(mut self, key_type: KeyType, from: Nonce) -> Self {
        assert!(from != Nonce(0), "nonce 0 always uses the initial key type");
        self.rotations.push((from, key_type));
        self.rotations.sort_by_key(|(nonce, _)| nonce.0);
        self
    }

    #[must_use]
    pub fn account_id(&self) -> AccountId {
        public_account_id(&self.secret)
    }

    #[must_use]
    pub fn evidence(&self) -> PublicAccountEvidence {
        PublicAccountEvidence::Key(initial_key(&self.secret))
    }

    /// The type of the account's key at `nonce`.
    #[must_use]
    pub fn key_type(&self, nonce: Nonce) -> KeyType {
        self.rotations
            .iter()
            .rev()
            .find(|(from, _)| from.0 <= nonce.0)
            .map_or(INITIAL_KEY_TYPE, |(_, key_type)| *key_type)
    }

    /// The key state of the account's key at `nonce`.
    #[must_use]
    pub fn key_state(&self, nonce: Nonce) -> SigningKeyState {
        key_state(&self.secret, self.key_type(nonce), nonce)
    }

    /// The account as a signer at `nonce`, rotating to its key at the next nonce.
    #[must_use]
    pub fn signer(&self, nonce: Nonce) -> Signer {
        Signer::new(
            &self.secret,
            nonce,
            self.key_type(nonce),
            self.key_type(next_nonce(nonce)),
        )
    }

    /// One witness entry signing `message_with_keys` with the key at `nonce` and rotating to the
    /// key at the next nonce, whatever the message names: for witnesses that deliberately
    /// disagree with their message.
    #[must_use]
    pub fn entry(&self, nonce: Nonce, message_with_keys: &[u8; 32]) -> WitnessEntry {
        let signer = self.signer(nonce);
        WitnessEntry {
            auth_data: signer.auth_data(message_with_keys),
            next: signer.next(),
        }
    }
}

impl From<&PublicAccountSecret> for TestSigner {
    fn from(secret: &PublicAccountSecret) -> Self {
        Self {
            secret: secret.clone(),
            rotations: Vec::new(),
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

/// The witness of `signers` for `message`, each signing with its key at its nonce in
/// `message.nonces` and rotating to the next; each signer must be named in `message.nonces`.
#[must_use]
pub fn witness_for(
    message: &public_transaction::Message,
    signers: &[&TestSigner],
) -> public_transaction::WitnessSet {
    public_transaction::WitnessSet::sign(message, &signing_keys(&message.nonces, signers))
}

/// The witness of `signers` for `message`, each signing with its key at its nonce in
/// `message.nonces` and rotating to the next; each signer must be named in `message.nonces`.
#[must_use]
pub fn privacy_witness_for(
    message: &privacy_preserving_transaction::Message,
    proof: Proof,
    signers: &[&TestSigner],
) -> privacy_preserving_transaction::WitnessSet {
    privacy_preserving_transaction::WitnessSet::sign(
        message,
        proof,
        &signing_keys(&message.nonces, signers),
    )
}

fn signing_keys(nonces: &BTreeMap<AccountId, Nonce>, signers: &[&TestSigner]) -> Vec<Signer> {
    signers
        .iter()
        .map(|signer| {
            let account_id = signer.account_id();
            let nonce = *nonces
                .get(&account_id)
                .unwrap_or_else(|| panic!("signer {account_id} is not in the message's nonces"));
            signer.signer(nonce)
        })
        .collect()
}

const fn next_nonce(mut nonce: Nonce) -> Nonce {
    nonce.public_account_nonce_increment();
    nonce
}

/// Builds a [`ValidatedStateDiff`] carrying only the given public-account changes.
#[cfg(feature = "test-utils")]
#[must_use]
pub const fn validated_state_diff_from_public_diff(
    public_diff: HashMap<AccountId, Account>,
) -> ValidatedStateDiff {
    ValidatedStateDiff::new_unchecked(StateDiff {
        signer_account_ids: Vec::new(),
        key_rotations: Vec::new(),
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
