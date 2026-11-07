use lee_core::{
    account::AccountId,
    signing_key::{KeyCommitment, KeyType, SigningKeyState},
};
use thiserror::Error;

use super::{Schnorr, SchnorrAuthData, Wots, WotsAuthData};

/// Length of the initial key state that prefixes a nonce-0 entry's authentication data.
const INITIAL_KEY_LEN: usize = 33;

pub type PublicKeyOf<K> = <<K as KeyScheme>::Scheme as SignatureScheme>::PublicKey;
pub type SecretKeyOf<K> = <<K as KeyScheme>::Scheme as SignatureScheme>::SecretKey;
pub type SignatureOf<K> = <<K as KeyScheme>::Scheme as SignatureScheme>::Signature;

#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
#[error("invalid signature")]
pub struct SignatureError;

#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    #[error("malformed authentication data")]
    Malformed,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("revealed key does not give the account id")]
    AccountIdMismatch,
}

impl From<SignatureError> for AuthError {
    fn from(_err: SignatureError) -> Self {
        Self::InvalidSignature
    }
}

/// A signature scheme: keys, signing and verification. No LEE concepts.
pub trait SignatureScheme {
    type PublicKey;
    type SecretKey;
    type Signature;

    /// Deterministic key generation from a 32-byte seed. Used only on the signer's side
    /// (wallet, tests), so keys are re-derived rather than stored.
    fn keygen(seed: &[u8; 32]) -> (Self::SecretKey, Self::PublicKey);

    /// One-time schemes must sign deterministically: the same key and message give the same
    /// signature.
    fn sign(sk: &Self::SecretKey, message: &[u8; 32]) -> Self::Signature;

    fn verify(
        pk: &Self::PublicKey,
        message: &[u8; 32],
        sig: &Self::Signature,
    ) -> Result<(), SignatureError>;
}

/// LEE's commitment policy for a signature scheme.
pub trait KeyScheme {
    const TYPE: KeyType;
    type Scheme: SignatureScheme;
    /// This scheme's authentication data: a fixed-size byte array.
    type AuthData: AsRef<[u8]> + for<'bytes> TryFrom<&'bytes [u8]>;

    /// The key's 32-byte commitment, as stored in the account and covered by signatures.
    fn commit(pk: &PublicKeyOf<Self>) -> KeyCommitment;

    /// The `SigningKeyState` for `pk`: what an account stores as its key, and what a witness
    /// commits as a signer's next key.
    fn key_state(pk: &PublicKeyOf<Self>) -> SigningKeyState {
        SigningKeyState {
            key_type: Self::TYPE,
            key_commitment: Self::commit(pk),
        }
    }

    /// The witness bytes for a signature: what `precheck` needs.
    fn auth_data(pk: &PublicKeyOf<Self>, sig: &SignatureOf<Self>) -> Self::AuthData;

    /// Decodes the authentication data and checks it against the commitment (cheap).
    fn precheck(
        key_commitment: &KeyCommitment,
        auth_data: &Self::AuthData,
    ) -> Result<(PublicKeyOf<Self>, SignatureOf<Self>), AuthError>;

    /// `precheck`, then `Scheme::verify`.
    fn authenticate(
        key_commitment: &KeyCommitment,
        message_with_keys: &[u8; 32],
        auth_data: &Self::AuthData,
    ) -> Result<(), AuthError> {
        let (pk, sig) = Self::precheck(key_commitment, auth_data)?;
        Self::Scheme::verify(&pk, message_with_keys, &sig).map_err(AuthError::from)
    }
}

/// The account's current key, and the authentication data to check against it: its stored key
/// or, at nonce 0, the initial key prefixing `auth_data`, which must give the account id.
pub fn current_key(
    stored: Option<SigningKeyState>,
    account_id: AccountId,
    auth_data: &[u8],
) -> Result<(SigningKeyState, &[u8]), AuthError> {
    if let Some(stored) = stored {
        return Ok((stored, auth_data));
    }
    let (prefix, rest) = auth_data
        .split_at_checked(INITIAL_KEY_LEN)
        .ok_or(AuthError::Malformed)?;
    let initial: SigningKeyState =
        borsh::from_slice(prefix).map_err(|_err| AuthError::Malformed)?;
    if AccountId::for_initial_key(&initial) != Some(account_id) {
        return Err(AuthError::AccountIdMismatch);
    }
    Ok((initial, rest))
}

/// Authenticates one signer against its current key, dispatching on `current.key_type`
/// (one `match` arm per `KeyScheme`); returns the signer's next key.
pub fn authenticate(
    current: &SigningKeyState,
    message_with_keys: &[u8; 32],
    auth_data: &[u8],
    next: &SigningKeyState,
) -> Result<SigningKeyState, AuthError> {
    match current.key_type {
        KeyType::Wots => {
            let auth = WotsAuthData::try_from(auth_data).map_err(|_err| AuthError::Malformed)?;
            Wots::authenticate(&current.key_commitment, message_with_keys, &auth)?;
            Ok(*next)
        }
        KeyType::Schnorr => {
            let auth = SchnorrAuthData::try_from(auth_data).map_err(|_err| AuthError::Malformed)?;
            Schnorr::authenticate(&current.key_commitment, message_with_keys, &auth)?;
            Ok(*next)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PublicKey;

    fn signed(seed: u8, message: &[u8; 32]) -> (PublicKey, SchnorrAuthData) {
        let (sk, pk) = Schnorr::keygen(&[seed; 32]);
        let auth = Schnorr::auth_data(&pk, &Schnorr::sign(&sk, message));
        (pk, auth)
    }

    /// A WOTS+ initial key, and a nonce-0 entry's authentication data: the key, then a signature.
    fn initial(seed: u8, message: &[u8; 32]) -> (SigningKeyState, Vec<u8>) {
        let (sk, pk) = Wots::keygen(&[seed; 32]);
        let key = Wots::key_state(&pk);
        let auth_data = [
            borsh::to_vec(&key).unwrap(),
            Wots::sign(&sk, message).to_vec(),
        ]
        .concat();
        (key, auth_data)
    }

    #[test]
    fn current_key_returns_stored_key() {
        let stored = SigningKeyState {
            key_type: KeyType::Schnorr,
            key_commitment: [0; 32],
        };
        assert_eq!(
            current_key(Some(stored), AccountId::new([1; 32]), &[7]),
            Ok((stored, &[7][..]))
        );
    }

    #[test]
    fn current_key_takes_the_initial_key_giving_the_account_id_at_nonce_zero() {
        let (key, auth_data) = initial(0, &[1; 32]);
        let account_id = AccountId::for_initial_key(&key).unwrap();
        assert_eq!(
            current_key(None, account_id, &auth_data),
            Ok((key, &auth_data[INITIAL_KEY_LEN..]))
        );
    }

    #[test]
    fn current_key_rejects_an_initial_key_not_giving_the_account_id() {
        let (_key, auth_data) = initial(0, &[1; 32]);
        assert_eq!(
            current_key(None, AccountId::new([2; 32]), &auth_data),
            Err(AuthError::AccountIdMismatch)
        );
    }

    #[test]
    fn current_key_rejects_a_schnorr_initial_key() {
        let (pk, auth) = signed(0, &[1; 32]);
        let key = Schnorr::key_state(&pk);
        let auth_data = [borsh::to_vec(&key).unwrap(), auth.to_vec()].concat();
        // No account id is a Schnorr account's: whichever is claimed, the key does not give it.
        assert_eq!(
            current_key(None, AccountId::new([2; 32]), &auth_data),
            Err(AuthError::AccountIdMismatch)
        );
    }

    #[test]
    fn current_key_rejects_a_missing_or_unknown_initial_key() {
        let (key, auth_data) = initial(0, &[1; 32]);
        let account_id = AccountId::for_initial_key(&key).unwrap();
        let mut unknown_type = auth_data.clone();
        unknown_type[0] = 2;
        for malformed in [&auth_data[..INITIAL_KEY_LEN - 1], &[][..], &*unknown_type] {
            assert_eq!(
                current_key(None, account_id, malformed),
                Err(AuthError::Malformed)
            );
        }
    }

    #[test]
    fn authenticate_returns_next_key() {
        let message = [1; 32];
        let (pk, auth) = signed(0, &message);
        let next = Schnorr::key_state(&Schnorr::keygen(&[2; 32]).1);
        assert_eq!(
            authenticate(&Schnorr::key_state(&pk), &message, &auth, &next),
            Ok(next)
        );
    }

    #[test]
    fn authenticate_dispatches_to_wots() {
        let message = [1; 32];
        let (key, auth_data) = initial(0, &message);
        let signature = &auth_data[INITIAL_KEY_LEN..];
        assert_eq!(authenticate(&key, &message, signature, &key), Ok(key));
        assert_eq!(
            authenticate(&key, &[2; 32], signature, &key),
            Err(AuthError::InvalidSignature)
        );
    }

    #[test]
    fn authenticate_rejects_witness_of_wrong_length_before_verification() {
        let message = [1; 32];
        let (pk, auth) = signed(0, &message);
        let current = Schnorr::key_state(&pk);
        let longer = [&auth[..], &[0]].concat();
        for witness in [&auth[..95], longer.as_slice()] {
            assert_eq!(
                authenticate(&current, &message, witness, &current),
                Err(AuthError::Malformed)
            );
        }
        let (key, auth_data) = initial(0, &message);
        assert_eq!(
            authenticate(&key, &message, &auth_data, &key),
            Err(AuthError::Malformed),
            "a WOTS+ signature with the initial-key prefix still attached"
        );
    }
}
