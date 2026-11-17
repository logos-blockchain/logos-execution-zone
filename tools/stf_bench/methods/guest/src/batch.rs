//! BIP340 batch verification, so one block's signatures share a single chain of doublings.
//!
//! Each signature `(r, s)` over `m` by `P` must satisfy `s·G = R + e·P`, with `R = lift_x(r)` and
//! `e = H_challenge(r || P || m)`. A batch checks `Σ aᵢ·Rᵢ + Σ aᵢeᵢ·Pᵢ − (Σ aᵢsᵢ)·G = O` for
//! coefficients `aᵢ` derived from every input, `a₀ = 1`, as BIP340 specifies.
//!
//! On the zkVM the accelerated `mul` is a plain double-and-add, so verifying one signature costs
//! two full chains of 256 doublings. Here every point is folded into one windowed sum, so the
//! doublings are paid once per block instead of twice per signature.

use k256::{
    AffinePoint, FieldBytes, ProjectivePoint, Scalar, U256,
    elliptic_curve::{
        PrimeField as _, ops::Reduce, point::DecompressPoint as _, subtle::Choice,
    },
};
use risc0_zkvm::sha::{Impl, Sha256 as _};

/// One signature check, as the block's transactions present it.
pub struct Check<'a> {
    pub public_key: &'a [u8; 32],
    pub message_hash: &'a [u8; 32],
    pub signature: &'a [u8; 64],
}

const WINDOW: usize = 4;
const TABLE: usize = (1 << WINDOW) - 1;

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Impl::hash_bytes(bytes).as_bytes().try_into().expect("a digest is 32 bytes")
}

fn tagged(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let tag = sha256(tag);
    let mut bytes = Vec::with_capacity(64 + parts.iter().map(|p| p.len()).sum::<usize>());
    bytes.extend_from_slice(&tag);
    bytes.extend_from_slice(&tag);
    for part in parts {
        bytes.extend_from_slice(part);
    }
    sha256(&bytes)
}

fn reduce(bytes: [u8; 32]) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from(bytes))
}

/// The point with x-coordinate `x` and even y, as BIP340 decodes keys and nonces.
fn lift_x(x: &[u8; 32]) -> Option<AffinePoint> {
    AffinePoint::decompress(&FieldBytes::from(*x), Choice::from(0)).into()
}

/// Whether every signature in `checks` is valid. An empty batch is.
#[must_use]
pub fn verify(checks: &[Check<'_>]) -> bool {
    if checks.is_empty() {
        return true;
    }
    // The coefficients bind every input, so no signature can be chosen after them.
    let mut transcript = Vec::with_capacity(checks.len() * 128);
    for check in checks {
        transcript.extend_from_slice(check.public_key);
        transcript.extend_from_slice(check.message_hash);
        transcript.extend_from_slice(check.signature);
    }
    let seed = sha256(&transcript);

    let mut terms: Vec<(AffinePoint, Scalar)> = Vec::with_capacity(2 * checks.len() + 1);
    let mut s_sum = Scalar::ZERO;
    for (i, check) in checks.iter().enumerate() {
        let (r, s) = check.signature.split_at(32);
        let r: &[u8; 32] = r.try_into().expect("32 bytes");
        let Some(s) = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::clone_from_slice(s)))
        else {
            return false;
        };
        let (Some(p), Some(r_point)) = (lift_x(check.public_key), lift_x(r)) else {
            return false;
        };
        let e = reduce(tagged(
            b"BIP0340/challenge",
            &[r, check.public_key, check.message_hash],
        ));
        let a = if i == 0 {
            Scalar::ONE
        } else {
            reduce(sha256(&[&seed[..], &(i as u64).to_le_bytes()].concat()))
        };
        s_sum += a * s;
        terms.push((r_point, a));
        terms.push((p, a * e));
    }
    terms.push((AffinePoint::GENERATOR, -s_sum));
    msm_is_identity(&terms)
}

/// Little-endian 32-bit words of a scalar, the layout the zkVM's curve circuit reads.
fn words(scalar: &Scalar) -> [u32; 8] {
    let mut bytes: [u8; 32] = scalar.to_bytes().into();
    bytes.reverse();
    let mut out = [0_u32; 8];
    for (word, chunk) in out.iter_mut().zip(bytes.chunks_exact(4)) {
        *word = u32::from_le_bytes(chunk.try_into().expect("4 bytes"));
    }
    out
}

/// The `WINDOW`-bit digit of `scalar` at window `index`, counting from the least significant.
fn digit(scalar: &[u32; 8], index: usize) -> usize {
    let bit = index * WINDOW;
    ((scalar[bit / 32] >> (bit % 32)) & ((1 << WINDOW) - 1)) as usize
}

/// Whether `Σ kᵢ·Pᵢ` is the identity, with one shared chain of doublings.
fn msm_is_identity(terms: &[(AffinePoint, Scalar)]) -> bool {
    let tables: Vec<[Point; TABLE]> = terms
        .iter()
        .map(|(p, _)| {
            let base = Point::from_affine(p);
            let mut table = [base; TABLE];
            for k in 1..TABLE {
                table[k] = table[k - 1].add(&base);
            }
            table
        })
        .collect();
    let scalars: Vec<[u32; 8]> = terms.iter().map(|(_, k)| words(k)).collect();

    let mut acc = Point::IDENTITY;
    for window in (0..256 / WINDOW).rev() {
        for _ in 0..WINDOW {
            acc = acc.double();
        }
        for (table, scalar) in tables.iter().zip(&scalars) {
            let d = digit(scalar, window);
            if d != 0 {
                acc = acc.add(&table[d - 1]);
            }
        }
    }
    acc.is_identity()
}

/// The zkVM's accelerated affine point: one circuit call per addition or doubling.
#[cfg(target_os = "zkvm")]
#[derive(Clone, Copy)]
struct Point(risc0_bigint2::ec::AffinePoint<8, risc0_bigint2::ec::Secp256k1Curve>);

#[cfg(target_os = "zkvm")]
impl Point {
    const IDENTITY: Self = Self(risc0_bigint2::ec::AffinePoint::IDENTITY);

    fn from_affine(p: &AffinePoint) -> Self {
        use k256::elliptic_curve::sec1::ToEncodedPoint as _;
        let encoded = p.to_encoded_point(false);
        let coordinate = |bytes: &[u8]| {
            let mut le: [u8; 32] = bytes.try_into().expect("32 bytes");
            le.reverse();
            let mut out = [0_u32; 8];
            for (word, chunk) in out.iter_mut().zip(le.chunks_exact(4)) {
                *word = u32::from_le_bytes(chunk.try_into().expect("4 bytes"));
            }
            out
        };
        Self(risc0_bigint2::ec::AffinePoint::new_unchecked(
            coordinate(encoded.x().expect("not the identity")),
            coordinate(encoded.y().expect("uncompressed")),
        ))
    }

    fn add(&self, other: &Self) -> Self {
        let mut out = Self::IDENTITY;
        self.0.add(&other.0, &mut out.0);
        out
    }

    fn double(&self) -> Self {
        let mut out = Self::IDENTITY;
        self.0.double(&mut out.0);
        out
    }

    fn is_identity(&self) -> bool {
        self.0.is_identity()
    }
}

/// On the host the same algorithm runs over k256's projective points, so it can be tested.
#[cfg(not(target_os = "zkvm"))]
#[derive(Clone, Copy)]
struct Point(ProjectivePoint);

#[cfg(not(target_os = "zkvm"))]
impl Point {
    const IDENTITY: Self = Self(ProjectivePoint::IDENTITY);

    fn from_affine(p: &AffinePoint) -> Self {
        Self(ProjectivePoint::from(*p))
    }

    fn add(&self, other: &Self) -> Self {
        Self(self.0 + other.0)
    }

    fn double(&self) -> Self {
        Self(self.0.double())
    }

    fn is_identity(&self) -> bool {
        self.0 == ProjectivePoint::IDENTITY
    }
}

#[cfg(test)]
mod tests {
    use k256::schnorr::{SigningKey, signature::hazmat::PrehashSigner as _};

    use super::*;

    fn signed(n: u8) -> ([u8; 32], [u8; 32], [u8; 64]) {
        let key = SigningKey::from_bytes(&[n.max(1); 32]).expect("a valid key");
        let message = sha256(&[n]);
        let signature = key.sign_prehash(&message).expect("signs");
        (
            key.verifying_key().to_bytes().into(),
            message,
            signature.to_bytes(),
        )
    }

    fn checks(set: &[([u8; 32], [u8; 32], [u8; 64])]) -> Vec<Check<'_>> {
        set.iter()
            .map(|(public_key, message_hash, signature)| Check {
                public_key,
                message_hash,
                signature,
            })
            .collect()
    }

    #[test]
    fn a_batch_of_valid_signatures_verifies() {
        for n in [1_u8, 2, 5, 20] {
            let set: Vec<_> = (1..=n).map(signed).collect();
            assert!(verify(&checks(&set)), "batch of {n}");
        }
    }

    #[test]
    fn one_bad_signature_fails_the_whole_batch() {
        let mut set: Vec<_> = (1..=8).map(signed).collect();
        set[5].2[63] ^= 1;
        assert!(!verify(&checks(&set)));
    }

    #[test]
    fn a_signature_over_another_message_fails() {
        let mut set: Vec<_> = (1..=4).map(signed).collect();
        set[2].1 = sha256(b"something else");
        assert!(!verify(&checks(&set)));
    }

    #[test]
    fn swapped_signatures_fail_even_though_each_is_valid_for_someone() {
        let mut set: Vec<_> = (1..=3).map(signed).collect();
        let first = set[0].2;
        set[0].2 = set[1].2;
        set[1].2 = first;
        assert!(!verify(&checks(&set)));
    }

    #[test]
    fn it_agrees_with_k256_single_verification() {
        use k256::schnorr::{VerifyingKey, signature::hazmat::PrehashVerifier as _};
        let set: Vec<_> = (1..=6).map(signed).collect();
        for (public_key, message_hash, signature) in &set {
            let key = VerifyingKey::from_bytes(public_key).expect("a key");
            let sig = k256::schnorr::Signature::try_from(signature.as_slice()).expect("a sig");
            assert!(key.verify_prehash(message_hash, &sig).is_ok());
        }
        assert!(verify(&checks(&set)));
    }
}
