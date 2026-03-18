use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::sha::{Impl, Sha256 as _};
use serde::{Deserialize, Serialize};

use crate::{NullifierPublicKey, account::Account};

/// A commitment to all zero data.
/// ```python
/// from hashlib import sha256
/// hasher = sha256()
/// hasher.update(bytes([0] * 32 + [0] * 32 + [0] * 16 + [0] * 16 + list(sha256().digest())))
/// DUMMY_COMMITMENT = hasher.digest()
/// ```
pub const DUMMY_COMMITMENT: Commitment = Commitment([
    55, 228, 215, 207, 112, 221, 239, 49, 238, 79, 71, 135, 155, 15, 184, 45, 104, 74, 51, 211,
    238, 42, 160, 243, 15, 124, 253, 62, 3, 229, 90, 27,
]);

/// The hash of the dummy commitment.
/// ```python
/// from hashlib import sha256
/// hasher = sha256()
/// hasher.update(DUMMY_COMMITMENT)
/// DUMMY_COMMITMENT_HASH = hasher.digest()
/// ```
pub const DUMMY_COMMITMENT_HASH: [u8; 32] = [
    250, 237, 192, 113, 155, 101, 119, 30, 235, 183, 20, 84, 26, 32, 196, 229, 154, 74, 254, 249,
    129, 241, 118, 39, 41, 253, 141, 171, 184, 71, 8, 41,
];

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    any(feature = "host", test),
    derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)
)]
pub struct Commitment(pub(super) [u8; 32]);

#[cfg(any(feature = "host", test))]
impl std::fmt::Debug for Commitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Write as _;

        let hex: String = self.0.iter().fold(String::new(), |mut acc, b| {
            write!(acc, "{b:02x}").expect("writing to string should not fail");
            acc
        });
        write!(f, "Commitment({hex})")
    }
}

impl Commitment {
    /// Generates the commitment to a private account owned by user for npk:
    /// SHA256( `Comm_DS` || npk || `program_owner` || balance || nonce || SHA256(data)).
    #[must_use]
    pub fn new(npk: &NullifierPublicKey, account: &Account) -> Self {
        const COMMITMENT_PREFIX: &[u8; 32] =
            b"/LEE/v0.3/Commitment/\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

        let mut bytes = Vec::new();
        bytes.extend_from_slice(COMMITMENT_PREFIX);
        bytes.extend_from_slice(&npk.to_byte_array());
        let account_bytes_with_hashed_data = {
            let mut this = Vec::new();
            for word in &account.program_owner {
                this.extend_from_slice(&word.to_le_bytes());
            }
            this.extend_from_slice(&account.balance.to_le_bytes());
            this.extend_from_slice(&account.nonce.0.to_le_bytes());
            let hashed_data: [u8; 32] = Impl::hash_bytes(&account.data)
                .as_bytes()
                .try_into()
                .unwrap();
            this.extend_from_slice(&hashed_data);
            this
        };
        bytes.extend_from_slice(&account_bytes_with_hashed_data);
        Self(Impl::hash_bytes(&bytes).as_bytes().try_into().unwrap())
    }
}

pub type CommitmentSetDigest = [u8; 32];

pub type MembershipProof = (usize, Vec<[u8; 32]>);

/// Computes the resulting digest for the given membership proof and corresponding commitment.
#[must_use]
pub fn compute_digest_for_path(
    commitment: &Commitment,
    proof: &MembershipProof,
) -> CommitmentSetDigest {
    let value_bytes = commitment.to_byte_array();
    let mut result: [u8; 32] = Impl::hash_bytes(&value_bytes)
        .as_bytes()
        .try_into()
        .unwrap();
    let mut level_index = proof.0;
    for node in &proof.1 {
        let mut bytes = [0_u8; 64];
        let is_left_child = level_index & 1 == 0;
        if is_left_child {
            bytes[..32].copy_from_slice(&result);
            bytes[32..].copy_from_slice(node);
        } else {
            bytes[..32].copy_from_slice(node);
            bytes[32..].copy_from_slice(&result);
        }
        result = Impl::hash_bytes(&bytes).as_bytes().try_into().unwrap();
        level_index >>= 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    use crate::{
        Commitment, DUMMY_COMMITMENT, DUMMY_COMMITMENT_HASH, NullifierPublicKey, account::Account,
    };

    #[test]
    fn nothing_up_my_sleeve_dummy_commitment() {
        let default_account = Account::default();
        let npk_null = NullifierPublicKey([0; 32]);
        let expected_dummy_commitment = Commitment::new(&npk_null, &default_account);
        assert_eq!(DUMMY_COMMITMENT, expected_dummy_commitment);
    }

    #[test]
    fn nothing_up_my_sleeve_dummy_commitment_hash() {
        let expected_dummy_commitment_hash: [u8; 32] =
            Impl::hash_bytes(&DUMMY_COMMITMENT.to_byte_array())
                .as_bytes()
                .try_into()
                .unwrap();
        assert_eq!(DUMMY_COMMITMENT_HASH, expected_dummy_commitment_hash);
    }
}
