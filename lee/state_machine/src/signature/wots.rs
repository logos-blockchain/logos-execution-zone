use std::fmt;

use lee_core::signing_key::{KeyCommitment, KeyType};
use wots_tree::{AUTH_LEN, PUBLIC_KEY_LEN, Tree};

use super::{AuthError, KeyScheme, SignatureError, SignatureScheme};

/// Leaves in each nonce's tree: one-time keys an account may sign with at that nonce.
pub const WOTS_LEAVES: u8 = wots_tree::LEAVES;

/// A tree of WOTS+ one-time keys in direct mode: the account stores the tree's public key
/// `PK.seed || root` as is, and the witness carries the signature alone.
pub struct Wots;

pub type WotsPublicKey = [u8; PUBLIC_KEY_LEN];

/// Leaf index, randomizer, chain values and authentication path.
pub type WotsAuthData = [u8; AUTH_LEN];

/// One leaf of one nonce's tree: a one-time signing key.
pub struct WotsSecretKey {
    tree: Tree,
    leaf: u8,
}

impl fmt::Debug for WotsSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WotsSecretKey")
            .field("leaf", &self.leaf)
            .finish_non_exhaustive()
    }
}

impl WotsSecretKey {
    /// The same tree's key at `leaf`.
    ///
    /// # Panics
    ///
    /// If `leaf` is not below [`wots_tree::LEAVES`].
    #[must_use]
    pub fn with_leaf(mut self, leaf: u8) -> Self {
        assert!(leaf < wots_tree::LEAVES, "leaf index out of range");
        self.leaf = leaf;
        self
    }
}

impl SignatureScheme for Wots {
    type PublicKey = WotsPublicKey;
    type SecretKey = WotsSecretKey;
    type Signature = WotsAuthData;

    fn keygen(seed: &[u8; 32]) -> (WotsSecretKey, WotsPublicKey) {
        let tree = Tree::from_seed(seed);
        let public_key = tree.public_key();
        (WotsSecretKey { tree, leaf: 0 }, public_key)
    }

    fn sign(sk: &WotsSecretKey, message: &[u8; 32]) -> WotsAuthData {
        sk.tree.sign(sk.leaf, message)
    }

    fn verify(
        pk: &WotsPublicKey,
        message: &[u8; 32],
        sig: &WotsAuthData,
    ) -> Result<(), SignatureError> {
        wots_tree::verify(pk, message, sig).map_err(|_err| SignatureError)
    }
}

impl KeyScheme for Wots {
    type AuthData = WotsAuthData;
    type Scheme = Self;

    const TYPE: KeyType = KeyType::Wots;

    fn commit(pk: &WotsPublicKey) -> KeyCommitment {
        *pk
    }

    fn auth_data(_pk: &WotsPublicKey, sig: &WotsAuthData) -> WotsAuthData {
        *sig
    }

    fn precheck(
        key_commitment: &KeyCommitment,
        auth_data: &WotsAuthData,
    ) -> Result<(WotsPublicKey, WotsAuthData), AuthError> {
        wots_tree::precheck(auth_data).map_err(|_err| AuthError::Malformed)?;
        Ok((*key_commitment, *auth_data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signature_authenticates_against_its_key_state() {
        let (sk, pk) = Wots::keygen(&[7; 32]);
        let key = Wots::key_state(&pk);
        assert_eq!(key.key_type, KeyType::Wots);
        assert_eq!(key.key_commitment, pk);
        let message = [1; 32];
        let auth = Wots::auth_data(&pk, &Wots::sign(&sk, &message));
        assert_eq!(
            Wots::authenticate(&key.key_commitment, &message, &auth),
            Ok(())
        );
        assert_eq!(
            Wots::authenticate(&key.key_commitment, &[2; 32], &auth),
            Err(AuthError::InvalidSignature)
        );
    }

    #[test]
    fn each_leaf_signs_for_the_same_key() {
        let (sk, pk) = Wots::keygen(&[7; 32]);
        let message = [1; 32];
        let first = Wots::sign(&sk, &message);
        let fifth = Wots::sign(&sk.with_leaf(5), &message);
        assert_eq!(fifth[0], 5);
        assert_ne!(first, fifth);
        assert_eq!(Wots::verify(&pk, &message, &fifth), Ok(()));
    }

    #[test]
    fn signing_is_deterministic() {
        let (sk, _) = Wots::keygen(&[7; 32]);
        assert_eq!(Wots::sign(&sk, &[1; 32]), Wots::sign(&sk, &[1; 32]));
    }

    #[test]
    fn precheck_rejects_an_out_of_range_leaf_before_verification() {
        let (sk, pk) = Wots::keygen(&[7; 32]);
        let mut auth = Wots::sign(&sk, &[1; 32]);
        auth[0] = wots_tree::LEAVES;
        assert_eq!(Wots::precheck(&pk, &auth), Err(AuthError::Malformed));
    }
}
