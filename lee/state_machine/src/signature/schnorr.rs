use lee_core::signing_key::{KeyCommitment, KeyType};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroize as _;

use super::{AuthError, KeyScheme, SignatureError, SignatureScheme};
use crate::{PrivateKey, PublicKey, Signature};

const DS_KEY: &[u8; 32] = b"/LEE/v0.3/KeyCommitment/Schnorr/";
const DS_KEYGEN: &[u8; 32] = b"/LEE/v0.3/KeyGen/Schnorr/\x00\x00\x00\x00\x00\x00\x00";

/// BIP-340 Schnorr in bunker mode: the account stores `Sha256(DS_KEY || pk)`, and the witness
/// reveals pk alongside the signature.
pub struct Schnorr;

/// 64 B signature || 32 B pk.
pub type SchnorrAuthData = [u8; 96];

impl SignatureScheme for Schnorr {
    type PublicKey = PublicKey;
    type SecretKey = PrivateKey;
    type Signature = Signature;

    fn keygen(seed: &[u8; 32]) -> (PrivateKey, PublicKey) {
        let sk = first_valid_key((0..=u8::MAX).map(|ctr| {
            let mut hasher = Sha256::new();
            hasher.update(DS_KEYGEN);
            hasher.update(seed);
            hasher.update([ctr]);
            hasher.finalize().into()
        }));
        let pk = PublicKey::new_from_private_key(&sk);
        (sk, pk)
    }

    fn sign(sk: &PrivateKey, message: &[u8; 32]) -> Signature {
        Signature::new(sk, message)
    }

    fn verify(pk: &PublicKey, message: &[u8; 32], sig: &Signature) -> Result<(), SignatureError> {
        if sig.is_valid_for(message, pk) {
            Ok(())
        } else {
            Err(SignatureError)
        }
    }
}

impl KeyScheme for Schnorr {
    type AuthData = SchnorrAuthData;
    type Scheme = Self;

    const TYPE: KeyType = KeyType::Schnorr;

    fn commit(pk: &PublicKey) -> KeyCommitment {
        let mut hasher = Sha256::new();
        hasher.update(DS_KEY);
        hasher.update(pk.value());
        hasher.finalize().into()
    }

    fn auth_data(pk: &PublicKey, sig: &Signature) -> SchnorrAuthData {
        let mut auth_data = [0; 96];
        auth_data[..64].copy_from_slice(&sig.value);
        auth_data[64..].copy_from_slice(pk.value());
        auth_data
    }

    fn precheck(
        key_commitment: &KeyCommitment,
        auth_data: &SchnorrAuthData,
    ) -> Result<(PublicKey, Signature), AuthError> {
        let pk = PublicKey::try_new(*auth_data.last_chunk().expect("auth data ends with the key"))
            .map_err(|_err| AuthError::Malformed)?;
        if Self::commit(&pk) != *key_commitment {
            return Err(AuthError::InvalidSignature);
        }
        let value = *auth_data
            .first_chunk()
            .expect("auth data starts with the signature");
        Ok((pk, Signature { value }))
    }
}

fn first_valid_key(candidates: impl IntoIterator<Item = [u8; 32]>) -> PrivateKey {
    candidates
        .into_iter()
        .find_map(|mut candidate| {
            let key = PrivateKey::try_new(candidate).ok();
            candidate.zeroize();
            key
        })
        .expect("one of 256 candidates is a valid scalar")
}
