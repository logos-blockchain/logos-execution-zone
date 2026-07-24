use risc0_zkvm::sha::{Impl, Sha256 as _};
use serde::{Deserialize, Serialize};

pub type AuthorizationSecretKey = [u8; 32];

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(any(feature = "host", test), derive(Hash))]
pub struct AuthorizationPublicKey(pub [u8; 32]);

impl From<&AuthorizationSecretKey> for AuthorizationPublicKey {
    fn from(value: &AuthorizationSecretKey) -> Self {
        const PREFIX: &[u8; 8] = b"LEE/keys";
        const SUFFIX_1: &[u8; 1] = &[8];
        const SUFFIX_2: &[u8; 23] = &[0; 23];
        let mut bytes = Vec::new();
        bytes.extend_from_slice(PREFIX);
        bytes.extend_from_slice(value);
        bytes.extend_from_slice(SUFFIX_1);
        bytes.extend_from_slice(SUFFIX_2);
        Self(
            Impl::hash_bytes(&bytes)
                .as_bytes()
                .try_into()
                .expect("hash should be exactly 32 bytes long"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apk_matches_pinned_vectors() {
        // apk = SHA256("LEE/keys" ‖ ask ‖ [8] ‖ [0; 23]); pinned via independent Python SHA-256.
        assert_eq!(
            AuthorizationPublicKey::from(&[0; 32]).0,
            [
                0x18, 0xfc, 0xad, 0xc8, 0x96, 0x99, 0xc2, 0xbc, 0xcd, 0x98, 0xd7, 0xe7, 0xe5, 0x15,
                0xa3, 0x74, 0xd3, 0x32, 0x44, 0x81, 0x4a, 0x97, 0x0d, 0x5c, 0x97, 0x58, 0x44, 0xe3,
                0xdb, 0x61, 0x3b, 0x95,
            ]
        );
        assert_eq!(
            AuthorizationPublicKey::from(&[1; 32]).0,
            [
                0x5e, 0xa8, 0xc5, 0x6c, 0xa2, 0xa3, 0x6f, 0x5c, 0xff, 0x7f, 0x4e, 0xb9, 0x54, 0x98,
                0x3d, 0x0d, 0x65, 0x5d, 0x2a, 0xe1, 0x4f, 0x9c, 0x37, 0xdb, 0xf8, 0x8a, 0x18, 0x5c,
                0x6f, 0xf9, 0xd2, 0x63,
            ]
        );
    }

    #[test]
    fn apk_differs_for_different_ask() {
        assert_ne!(
            AuthorizationPublicKey::from(&[0; 32]),
            AuthorizationPublicKey::from(&[1; 32]),
        );
    }
}
