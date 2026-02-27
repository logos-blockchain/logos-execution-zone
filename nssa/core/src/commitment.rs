use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::sha::{Impl, Sha256};
use serde::{Deserialize, Serialize};

use crate::{NullifierPublicKey, account::Account};

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    any(feature = "host", test),
    derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)
)]
pub struct Commitment(pub(super) [u8; 32]);

#[cfg(any(feature = "host", test))]
impl std::fmt::Debug for Commitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex: String = self.0.iter().map(|b| format!("{b:02x}")).collect();
        write!(f, "Commitment({hex})")
    }
}

/// A commitment to all zero data.
/// ```python
/// from hashlib import sha256
/// hasher = sha256()
/// hasher.update(bytes([0] * 32 + [0] * 32 + [0] * 16 + [0] * 16 + list(sha256().digest())))
/// DUMMY_COMMITMENT = hasher.digest()
/// ```
pub const DUMMY_COMMITMENT: Commitment = Commitment([
    130, 75, 48, 230, 171, 101, 121, 141, 159, 118, 21, 74, 135, 248, 16, 255, 238, 156, 61, 24,
    165, 33, 34, 172, 227, 30, 215, 20, 85, 47, 230, 29,
]);

/// The hash of the dummy commitment
/// ```python
/// from hashlib import sha256
/// hasher = sha256()
/// hasher.update(DUMMY_COMMITMENT)
/// DUMMY_COMMITMENT_HASH = hasher.digest()
/// ```
pub const DUMMY_COMMITMENT_HASH: [u8; 32] = [
    170, 10, 217, 228, 20, 35, 189, 177, 238, 235, 97, 129, 132, 89, 96, 247, 86, 91, 222, 214, 38,
    194, 216, 67, 56, 251, 208, 226, 0, 117, 149, 39,
];

impl Commitment {
    /// Generates the commitment to a private account owned by user for npk:
    /// SHA256(npk || program_owner || balance || nonce || SHA256(data))
    pub fn new(npk: &NullifierPublicKey, account: &Account) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&npk.to_byte_array());
        let account_bytes_with_hashed_data = {
            let mut this = Vec::new();
            for word in &account.program_owner {
                this.extend_from_slice(&word.to_le_bytes());
            }
            this.extend_from_slice(&account.balance.to_le_bytes());
            this.extend_from_slice(&account.nonce.to_le_bytes());
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

/// Computes the resulting digest for the given membership proof and corresponding commitment
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
        let is_left_child = level_index & 1 == 0;
        if is_left_child {
            let mut bytes = [0u8; 64];
            bytes[..32].copy_from_slice(&result);
            bytes[32..].copy_from_slice(node);
            result = Impl::hash_bytes(&bytes).as_bytes().try_into().unwrap();
        } else {
            let mut bytes = [0u8; 64];
            bytes[..32].copy_from_slice(node);
            bytes[32..].copy_from_slice(&result);
            result = Impl::hash_bytes(&bytes).as_bytes().try_into().unwrap();
        }
        level_index >>= 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use risc0_zkvm::sha::{Impl, Sha256};

    use crate::{
        Commitment, DUMMY_COMMITMENT, DUMMY_COMMITMENT_HASH, NullifierPublicKey, account::Account,
    };

    #[test]
    fn test_nothing_up_my_sleeve_dummy_commitment() {
        let default_account = Account::default();
        let npk_null = NullifierPublicKey([0; 32]);
        let expected_dummy_commitment = Commitment::new(&npk_null, &default_account);
        assert_eq!(DUMMY_COMMITMENT, expected_dummy_commitment);
    }

    #[test]
    fn test_nothing_up_my_sleeve_dummy_commitment_hash() {
        let expected_dummy_commitment_hash: [u8; 32] =
            Impl::hash_bytes(&DUMMY_COMMITMENT.to_byte_array())
                .as_bytes()
                .try_into()
                .unwrap();
        assert_eq!(DUMMY_COMMITMENT_HASH, expected_dummy_commitment_hash);
    }
}
