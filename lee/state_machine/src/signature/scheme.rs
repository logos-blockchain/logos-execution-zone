use lee_core::{
    account::AccountId,
    signing_key::{KeyCommitment, KeyType, SigningKeyState},
};
use thiserror::Error;

use super::{Schnorr, SchnorrAuthData};
use crate::PublicKey;

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

/// The account's current key: its stored key or, at nonce 0, the initial-key rule
/// (for now: a Schnorr key whose revealed `pk` gives the account id via `AccountId::from(&pk)`).
pub fn current_key(
    stored: Option<SigningKeyState>,
    account_id: AccountId,
    auth_data: &[u8],
) -> Result<SigningKeyState, AuthError> {
    if let Some(stored) = stored {
        return Ok(stored);
    }
    let auth = SchnorrAuthData::try_from(auth_data).map_err(|_err| AuthError::Malformed)?;
    let pk = PublicKey::try_new(*auth.last_chunk().expect("auth data ends with the key"))
        .map_err(|_err| AuthError::Malformed)?;
    if AccountId::from(&pk) != account_id {
        return Err(AuthError::AccountIdMismatch);
    }
    Ok(Schnorr::key_state(&pk))
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
        KeyType::Schnorr => {
            let auth = SchnorrAuthData::try_from(auth_data).map_err(|_err| AuthError::Malformed)?;
            Schnorr::authenticate(&current.key_commitment, message_with_keys, &auth)?;
            Ok(*next)
        }
    }
}
