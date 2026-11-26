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

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use lee_core::signing_key::SigningKeyState;

    use super::*;

    #[test]
    fn keygen_is_deterministic() {
        assert_eq!(Schnorr::keygen(&[0; 32]), Schnorr::keygen(&[0; 32]));
        let (sk_0, pk_0) = Schnorr::keygen(&[0; 32]);
        let (sk_1, pk_1) = Schnorr::keygen(&[1; 32]);
        assert_ne!(sk_0, sk_1);
        assert_ne!(pk_0, pk_1);
    }

    #[test]
    fn first_valid_key_skips_zero_and_out_of_range_candidates() {
        let key = first_valid_key([[0; 32], [0xFF; 32], [1; 32]]);
        assert_eq!(key.value(), &[1; 32]);
    }

    #[test]
    fn keygen_known_answers() {
        for (seed, expected_sk, expected_pk) in [
            (
                [0; 32],
                hex!("554da361d5c4a3f0b746dac9126015694d84a058fb4e12ab4e4eea32810f96fa"),
                hex!("40a52dbcf274dacbf01dc90e67c03023c144ac68434acb28d6a87997a50c17f8"),
            ),
            (
                [1; 32],
                hex!("4741acf27ac4233ba083c7e28dbb9a6738134cd26a4f29dda68df53ce62db1f0"),
                hex!("8ca5e88efbcd3a65f175a58ea99d5ac84dce30286b373e6008e0fb3f442dcb85"),
            ),
            (
                [2; 32],
                hex!("b3c82641c528e05d0f468cc8720dc8e602f9c8cbc692d7c842031ab647cf868a"),
                hex!("daa95922468f34c5c692e5b78f1309e56279d22849e7eb3d792578118b03040c"),
            ),
        ] {
            let (sk, pk) = Schnorr::keygen(&seed);
            assert_eq!(sk.value(), &expected_sk);
            assert_eq!(pk.value(), &expected_pk);
        }
    }

    #[test]
    fn sign_then_verify() {
        let (sk, pk) = Schnorr::keygen(&[0; 32]);
        let message = [1; 32];
        let sig = Schnorr::sign(&sk, &message);
        assert_eq!(Schnorr::verify(&pk, &message, &sig), Ok(()));
    }

    #[test]
    fn verify_rejects_bad_signature_and_wrong_message() {
        let (sk, pk) = Schnorr::keygen(&[0; 32]);
        let message = [1; 32];
        let sig = Schnorr::sign(&sk, &message);
        let mut bad = sig.clone();
        bad.value[0] ^= 1;
        assert_eq!(Schnorr::verify(&pk, &message, &bad), Err(SignatureError));
        assert_eq!(Schnorr::verify(&pk, &[2; 32], &sig), Err(SignatureError));
    }

    #[test]
    fn key_state_commits_to_key() {
        let (_sk, pk) = Schnorr::keygen(&[0; 32]);
        let mut hasher = Sha256::new();
        hasher.update(DS_KEY);
        hasher.update(pk.value());
        assert_eq!(
            Schnorr::key_state(&pk),
            SigningKeyState {
                key_type: KeyType::Schnorr,
                key_commitment: hasher.finalize().into(),
            }
        );
    }

    #[test]
    fn auth_data_round_trips_through_precheck() {
        let (sk, pk) = Schnorr::keygen(&[0; 32]);
        let sig = Schnorr::sign(&sk, &[1; 32]);
        assert_eq!(
            Schnorr::precheck(&Schnorr::commit(&pk), &Schnorr::auth_data(&pk, &sig)),
            Ok((pk, sig))
        );
    }

    #[test]
    fn precheck_rejects_key_not_matching_commitment() {
        let (_sk_0, pk_0) = Schnorr::keygen(&[0; 32]);
        let (sk_1, pk_1) = Schnorr::keygen(&[1; 32]);
        let sig = Schnorr::sign(&sk_1, &[2; 32]);
        assert_eq!(
            Schnorr::precheck(&Schnorr::commit(&pk_0), &Schnorr::auth_data(&pk_1, &sig)),
            Err(AuthError::InvalidSignature)
        );
    }

    #[test]
    fn authenticate_accepts_valid_and_rejects_bad_signature() {
        let (sk, pk) = Schnorr::keygen(&[0; 32]);
        let commitment = Schnorr::commit(&pk);
        let message = [1; 32];
        let sig = Schnorr::sign(&sk, &message);
        assert_eq!(
            Schnorr::authenticate(&commitment, &message, &Schnorr::auth_data(&pk, &sig)),
            Ok(())
        );
        let mut bad = sig;
        bad.value[0] ^= 1;
        assert_eq!(
            Schnorr::authenticate(&commitment, &message, &Schnorr::auth_data(&pk, &bad)),
            Err(AuthError::InvalidSignature)
        );
    }
}
