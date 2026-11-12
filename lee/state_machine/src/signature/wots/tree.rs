//! A tree of 8 WOTS+ one-time keys built from FIPS 205's components through `slh-dsa`'s
//! `hazmat` API, specified in `SPEC.md` beside this file.

use std::fmt;

use sha2::{Digest as _, Sha256};
use slh_dsa::{Sha2_128f, hazmat};
use zeroize::Zeroize as _;

/// Hash length, in bytes.
pub const N: usize = 16;

/// Tree height: the tree has `2^TREE_HEIGHT` leaves.
pub const TREE_HEIGHT: u32 = 3;

/// Number of leaves, each a WOTS+ one-time key.
pub const LEAVES: u8 = 1 << TREE_HEIGHT;

/// Length of a signed message, in bytes.
pub const MESSAGE_LEN: usize = 32;

/// Length of a public key, `PK.seed || root`.
pub const PUBLIC_KEY_LEN: usize = 2 * N;

/// Length of a signature: leaf index, `R`, 35 chain values and the authentication path.
pub const AUTH_LEN: usize = 1 + N + XMSS_SIG_LEN;

const WOTS_CHAINS: usize = 35;
const PATH_LEN: usize = 3;
const XMSS_SIG_LEN: usize = (WOTS_CHAINS + PATH_LEN) * N;
const H_MSG_LEN: usize = 34;

const DS_SK_SEED: &[u8] = b"WotsTree/v1/SK.seed";
const DS_SK_PRF: &[u8] = b"WotsTree/v1/SK.prf";
const DS_PK_SEED: &[u8] = b"WotsTree/v1/PK.seed";

// The tree is always the single tree at layer 0, tree 0.
const LAYER: u32 = 0;
const TREE: u64 = 0;

type Params = Sha2_128f;

/// Why a signature was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Wrong length or leaf index out of range.
    Malformed,
    /// Does not verify under the public key.
    InvalidSignature,
}

/// A tree of [`LEAVES`] WOTS+ keys, derived from a 32-byte seed.
///
/// Each leaf must sign at most one message. Secrets are cleared on drop.
pub struct Tree {
    sk_seed: [u8; N],
    sk_prf: [u8; N],
    pk_seed: [u8; N],
    root: [u8; N],
}

impl Tree {
    /// Derives the tree from `seed`.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let sk_seed = expand(DS_SK_SEED, seed);
        let sk_prf = expand(DS_SK_PRF, seed);
        let pk_seed = expand(DS_PK_SEED, seed);
        let mut root = [0; N];
        hazmat::xmss_root::<Params>(&sk_seed, &pk_seed, LAYER, TREE, &mut root);
        Self {
            sk_seed,
            sk_prf,
            pk_seed,
            root,
        }
    }

    /// `PK.seed || root`.
    #[must_use]
    pub const fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        let mut public_key = [0; PUBLIC_KEY_LEN];
        let (pk_seed, root) = public_key.split_at_mut(N);
        pk_seed.copy_from_slice(&self.pk_seed);
        root.copy_from_slice(&self.root);
        public_key
    }

    /// Signs `message` with `leaf`. Deterministic: the same leaf and message give the same
    /// signature.
    ///
    /// # Panics
    ///
    /// If `leaf` is not below [`LEAVES`].
    #[must_use]
    pub fn sign(&self, leaf: u8, message: &[u8; MESSAGE_LEN]) -> [u8; AUTH_LEN] {
        assert!(leaf < LEAVES, "leaf index out of range");
        let mut auth_data = [0; AUTH_LEN];
        let (leaf_byte, rest) = auth_data.split_at_mut(1);
        let (r, xmss_sig) = rest.split_at_mut(N);
        leaf_byte.copy_from_slice(&[leaf]);
        hazmat::prf_msg::<Params>(&self.sk_prf, &self.pk_seed, message, r);
        let digest = message_digest(r, &self.pk_seed, &self.root, message);
        hazmat::xmss_sign::<Params>(
            &digest,
            &self.sk_seed,
            &self.pk_seed,
            LAYER,
            TREE,
            u32::from(leaf),
            xmss_sig,
        );
        auth_data
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        self.sk_seed.zeroize();
        self.sk_prf.zeroize();
    }
}

impl fmt::Debug for Tree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tree")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

/// Cheap checks, with no hashing: length and leaf index.
///
/// # Errors
///
/// [`Error::Malformed`] if `auth_data` is not [`AUTH_LEN`] bytes or its leaf index is out of
/// range.
pub const fn precheck(auth_data: &[u8]) -> Result<(), Error> {
    match auth_data.first() {
        Some(&leaf) if auth_data.len() == AUTH_LEN && leaf < LEAVES => Ok(()),
        _ => Err(Error::Malformed),
    }
}

/// Verifies `auth_data` over `message` under `public_key`.
///
/// # Errors
///
/// [`Error::Malformed`] if [`precheck`] fails, [`Error::InvalidSignature`] if the signature does
/// not verify.
pub fn verify(
    public_key: &[u8; PUBLIC_KEY_LEN],
    message: &[u8; MESSAGE_LEN],
    auth_data: &[u8],
) -> Result<(), Error> {
    precheck(auth_data)?;
    let (pk_seed, root) = public_key.split_at(N);
    let (&leaf, rest) = auth_data.split_first().ok_or(Error::Malformed)?;
    let (r, xmss_sig) = rest.split_at(N);
    let digest = message_digest(r, pk_seed, root, message);
    let mut recovered = [0; N];
    hazmat::xmss_pk_from_sig::<Params>(
        u32::from(leaf),
        xmss_sig,
        &digest,
        pk_seed,
        LAYER,
        TREE,
        &mut recovered,
    )
    .map_err(|_err| Error::Malformed)?;
    if recovered == root {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

/// `Sha256(ds || seed)`, truncated to `N` bytes.
fn expand(ds: &[u8], seed: &[u8; 32]) -> [u8; N] {
    let mut hash: [u8; 32] = Sha256::new()
        .chain_update(ds)
        .chain_update(seed)
        .finalize()
        .into();
    let mut out = [0; N];
    out.copy_from_slice(hash.split_at(N).0);
    hash.zeroize();
    out
}

/// `H_msg(R, PK.seed, root, message)`, truncated to `N` bytes: the value WOTS+ signs.
fn message_digest(r: &[u8], pk_seed: &[u8], root: &[u8], message: &[u8]) -> [u8; N] {
    let mut h_msg = [0; H_MSG_LEN];
    hazmat::h_msg::<Params>(r, pk_seed, root, message, &mut h_msg);
    let mut digest = [0; N];
    digest.copy_from_slice(h_msg.split_at(N).0);
    digest
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    const SEED: [u8; 32] = [1; 32];
    const MESSAGE: [u8; 32] = [2; 32];
    const VECTOR_LEAF: u8 = 5;
    const VECTOR_MESSAGE: [u8; 32] = [0xab; 32];
    const VECTOR_PUBLIC_KEY: [u8; 32] =
        hex!("82e8ce66e2dda65233dc06e067c6cb01d9fede44a6f92a004277afdd6ade41a9");
    const VECTOR_AUTH_DATA_PREFIX: [u8; 48] = hex!(
        "0569538180c60a068ddc9f6a0935df1ffa28e2037c714ac9bfaf03ccb80d21bf"
        "6ffc0c057a10f75f972784cd08c49ef8"
    );
    const VECTOR_AUTH_DATA_SHA256: [u8; 32] =
        hex!("6883b240bb47d7ba57908d5a72b89c5e54e0b8100c8ef9ecf44a662d6807c015");

    #[test]
    fn constants_match_the_parameter_set() {
        assert_eq!(N, hazmat::n::<Params>());
        assert_eq!(H_MSG_LEN, hazmat::m::<Params>());
        assert_eq!(TREE_HEIGHT, hazmat::tree_height::<Params>());
        assert_eq!(PATH_LEN, usize::try_from(TREE_HEIGHT).expect("small"));
        assert_eq!(XMSS_SIG_LEN, hazmat::xmss_sig_len::<Params>());
        assert_eq!(AUTH_LEN, 625);
    }

    #[test]
    fn expansion_is_domain_separated() {
        let seed = [9; 32];
        let values = [
            expand(DS_SK_SEED, &seed),
            expand(DS_SK_PRF, &seed),
            expand(DS_PK_SEED, &seed),
        ];
        assert_ne!(values[0], values[1]);
        assert_ne!(values[0], values[2]);
        assert_ne!(values[1], values[2]);
    }

    #[test]
    fn every_leaf_signs_and_verifies() {
        let tree = Tree::from_seed(&SEED);
        let public_key = tree.public_key();
        for leaf in 0..LEAVES {
            let auth_data = tree.sign(leaf, &MESSAGE);
            assert_eq!(auth_data[0], leaf);
            assert_eq!(verify(&public_key, &MESSAGE, &auth_data), Ok(()));
        }
    }

    #[test]
    fn signing_is_deterministic() {
        let tree = Tree::from_seed(&SEED);
        assert_eq!(tree.sign(3, &MESSAGE), tree.sign(3, &MESSAGE));
        assert_eq!(
            Tree::from_seed(&SEED).public_key(),
            tree.public_key(),
            "the same seed gives the same tree"
        );
    }

    #[test]
    fn different_seeds_give_different_keys() {
        assert_ne!(
            Tree::from_seed(&[1; 32]).public_key(),
            Tree::from_seed(&[2; 32]).public_key()
        );
    }

    #[test]
    fn flipping_any_byte_is_rejected() {
        let tree = Tree::from_seed(&SEED);
        let public_key = tree.public_key();
        let auth_data = tree.sign(5, &MESSAGE);
        for i in 0..AUTH_LEN {
            let mut tampered = auth_data;
            tampered[i] ^= 1;
            assert!(
                verify(&public_key, &MESSAGE, &tampered).is_err(),
                "flipped byte {i} accepted"
            );
        }
    }

    #[test]
    fn another_leafs_index_is_rejected() {
        let tree = Tree::from_seed(&SEED);
        let mut auth_data = tree.sign(2, &MESSAGE);
        auth_data[0] = 3;
        assert_eq!(
            verify(&tree.public_key(), &MESSAGE, &auth_data),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn leaf_index_out_of_range_is_malformed() {
        let tree = Tree::from_seed(&SEED);
        let mut auth_data = tree.sign(0, &MESSAGE);
        auth_data[0] = LEAVES;
        assert_eq!(precheck(&auth_data), Err(Error::Malformed));
        assert_eq!(
            verify(&tree.public_key(), &MESSAGE, &auth_data),
            Err(Error::Malformed)
        );
    }

    #[test]
    #[should_panic(expected = "leaf index out of range")]
    fn signing_with_a_leaf_out_of_range_panics() {
        assert_eq!(
            Tree::from_seed(&SEED).sign(LEAVES, &MESSAGE).len(),
            AUTH_LEN
        );
    }

    #[test]
    fn wrong_public_key_is_rejected() {
        let tree = Tree::from_seed(&SEED);
        let auth_data = tree.sign(1, &MESSAGE);
        for half in [0, N] {
            let mut public_key = tree.public_key();
            public_key[half] ^= 1;
            assert_eq!(
                verify(&public_key, &MESSAGE, &auth_data),
                Err(Error::InvalidSignature),
                "{}",
                if half == 0 { "PK.seed" } else { "root" }
            );
        }
    }

    #[test]
    fn wrong_message_is_rejected() {
        let tree = Tree::from_seed(&SEED);
        let auth_data = tree.sign(4, &MESSAGE);
        assert_eq!(
            verify(&tree.public_key(), &[3; 32], &auth_data),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn wrong_lengths_are_malformed() {
        let tree = Tree::from_seed(&SEED);
        let auth_data = tree.sign(0, &MESSAGE);
        let mut extended = auth_data.to_vec();
        extended.push(0);
        for bytes in [&auth_data[..AUTH_LEN - 1], extended.as_slice(), &[][..]] {
            assert_eq!(precheck(bytes), Err(Error::Malformed));
            assert_eq!(
                verify(&tree.public_key(), &MESSAGE, bytes),
                Err(Error::Malformed)
            );
        }
    }

    fn vector_seed() -> [u8; 32] {
        core::array::from_fn(|i| u8::try_from(i).expect("index below 32"))
    }

    #[test]
    fn fixed_seed_vectors() {
        let tree = Tree::from_seed(&vector_seed());
        assert_eq!(tree.public_key(), VECTOR_PUBLIC_KEY);
        let auth_data = tree.sign(VECTOR_LEAF, &VECTOR_MESSAGE);
        assert_eq!(auth_data[..48], VECTOR_AUTH_DATA_PREFIX);
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(auth_data)),
            VECTOR_AUTH_DATA_SHA256
        );
        assert_eq!(
            verify(&VECTOR_PUBLIC_KEY, &VECTOR_MESSAGE, &auth_data),
            Ok(())
        );
    }

    #[test]
    fn spec_derivation_matches() {
        let seed = vector_seed();
        let sk_seed = expand(b"WotsTree/v1/SK.seed", &seed);
        let sk_prf = expand(b"WotsTree/v1/SK.prf", &seed);
        let pk_seed = expand(b"WotsTree/v1/PK.seed", &seed);

        let mut root = [0; N];
        hazmat::xmss_root::<Params>(&sk_seed, &pk_seed, 0, 0, &mut root);
        assert_eq!(VECTOR_PUBLIC_KEY[..N], pk_seed);
        assert_eq!(VECTOR_PUBLIC_KEY[N..], root);

        let mut r = [0; N];
        hazmat::prf_msg::<Params>(&sk_prf, &pk_seed, &VECTOR_MESSAGE, &mut r);
        let mut h_msg = [0; 34];
        hazmat::h_msg::<Params>(&r, &pk_seed, &root, &VECTOR_MESSAGE, &mut h_msg);
        let mut xmss_sig = [0; AUTH_LEN - 1 - N];
        hazmat::xmss_sign::<Params>(
            &h_msg[..N],
            &sk_seed,
            &pk_seed,
            0,
            0,
            u32::from(VECTOR_LEAF),
            &mut xmss_sig,
        );

        let auth_data = Tree::from_seed(&seed).sign(VECTOR_LEAF, &VECTOR_MESSAGE);
        assert_eq!(auth_data[0], VECTOR_LEAF);
        assert_eq!(auth_data[1..=N], r);
        assert_eq!(auth_data[1 + N..], xmss_sig);
    }
}
