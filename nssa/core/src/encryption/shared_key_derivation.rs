#![expect(
    clippy::arithmetic_side_effects,
    reason = "Multiplication of finite field elements can't overflow"
)]

use std::fmt::Write as _;

use borsh::{BorshDeserialize, BorshSerialize};
use k256::{
    AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint,
    elliptic_curve::{
        PrimeField as _,
        sec1::{FromEncodedPoint as _, ToEncodedPoint as _},
    },
};
use serde::{Deserialize, Serialize};

use crate::{SharedSecretKey, encryption::Scalar};

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Secp256k1Point(pub Vec<u8>);

impl std::fmt::Debug for Secp256k1Point {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex: String = self.0.iter().fold(String::new(), |mut acc, b| {
            write!(acc, "{b:02x}").expect("writing to string should not fail");
            acc
        });
        write!(f, "Secp256k1Point({hex})")
    }
}

impl Secp256k1Point {
    #[must_use]
    pub fn from_scalar(value: Scalar) -> Self {
        let x_bytes: FieldBytes = value.into();
        let x = k256::Scalar::from_repr(x_bytes).unwrap();

        let p = ProjectivePoint::GENERATOR * x;
        let q = AffinePoint::from(p);
        let enc = q.to_encoded_point(true);

        Self(enc.as_bytes().to_vec())
    }
}

pub type EphemeralSecretKey = Scalar;
pub type EphemeralPublicKey = Secp256k1Point;
pub type ViewingPublicKey = Secp256k1Point;
impl From<&EphemeralSecretKey> for EphemeralPublicKey {
    fn from(value: &EphemeralSecretKey) -> Self {
        Self::from_scalar(*value)
    }
}

impl SharedSecretKey {
    /// Creates a new shared secret key from a scalar and a point.
    #[must_use]
    pub fn new(scalar: &Scalar, point: &Secp256k1Point) -> Self {
        let scalar = k256::Scalar::from_repr((*scalar).into()).unwrap();
        let point: [u8; 33] = point.0.clone().try_into().unwrap();

        let encoded = EncodedPoint::from_bytes(point).unwrap();
        let pubkey_affine = AffinePoint::from_encoded_point(&encoded).unwrap();

        let shared = ProjectivePoint::from(pubkey_affine) * scalar;
        let shared_affine = shared.to_affine();

        let shared_affine_encoded = shared_affine.to_encoded_point(false);
        let x_bytes_slice = shared_affine_encoded.x().unwrap();
        let mut x_bytes = [0_u8; 32];
        x_bytes.copy_from_slice(x_bytes_slice);

        Self(x_bytes)
    }
}
