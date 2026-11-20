//! A public account's id from its secret, as `lee::signature::public_account_id` derives it. `lee`
//! is host-only, so the guest derives it itself; known-answer tests pin both to the same id.

use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use lee_core::{
    account::AccountId,
    signing_key::{KeyType, SigningKeyState},
};
use sha2::{Digest as _, Sha256};

const DS_KEY_SEED: &[u8; 32] =
    b"/LEE/v0.3/KeySeed/\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
const DS_KEYGEN: &[u8; 32] = b"/LEE/v0.3/KeyGen/Schnorr/\x00\x00\x00\x00\x00\x00\x00";
const DS_KEY: &[u8; 32] = b"/LEE/v0.3/KeyCommitment/Schnorr/";

/// The seed of the initial key: Schnorr, nonce 0, counter 0.
fn initial_key_seed(secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DS_KEY_SEED);
    hasher.update(secret);
    hasher.update(
        borsh::to_vec(&KeyType::Schnorr).expect("a key type encodes to its discriminant byte"),
    );
    hasher.update(0_u128.to_le_bytes());
    hasher.update(0_u32.to_le_bytes());
    hasher.finalize().into()
}

/// The x-only public key of the first valid candidate `Sha256(DS_KEYGEN || seed || ctr)`.
fn schnorr_public_key(seed: &[u8; 32]) -> [u8; 32] {
    let secret_key = (0..=u8::MAX)
        .find_map(|ctr| {
            let mut hasher = Sha256::new();
            hasher.update(DS_KEYGEN);
            hasher.update(seed);
            hasher.update([ctr]);
            let candidate: [u8; 32] = hasher.finalize().into();
            k256::SecretKey::from_bytes(&candidate.into()).ok()
        })
        .expect("one of 256 candidates is a valid scalar");
    let encoded = secret_key.public_key().to_encoded_point(false);
    *encoded
        .x()
        .expect("a public key has an x-coordinate")
        .first_chunk()
        .expect("an x-coordinate is 32 bytes")
}

pub fn public_account_id(secret: &[u8; 32]) -> AccountId {
    let pk = schnorr_public_key(&initial_key_seed(secret));
    let mut hasher = Sha256::new();
    hasher.update(DS_KEY);
    hasher.update(pk);
    let initial = SigningKeyState {
        key_type: KeyType::Schnorr,
        key_commitment: hasher.finalize().into(),
    };
    AccountId::for_initial_key(&initial).expect("Schnorr is an initial key type")
}
