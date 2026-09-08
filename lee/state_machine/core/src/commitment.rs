use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::sha::{Impl, Sha256 as _};
use serde::{Deserialize, Serialize};

use crate::{
    Nullifier,
    account::{Account, AccountId},
};

/// A commitment to all zero data.
/// ```python
/// from hashlib import sha256
/// prefix = b"/LEE/v0.3/Commitment/" + bytes(11)
/// DUMMY_COMMITMENT = sha256(prefix + bytes(32) + sha256(bytes(36)).digest()).digest()
/// ```
pub const DUMMY_COMMITMENT: Commitment = Commitment([
    72, 211, 137, 183, 48, 13, 155, 70, 255, 224, 0, 129, 85, 237, 56, 154, 206, 234, 233, 73, 26,
    54, 157, 85, 138, 140, 147, 77, 9, 105, 183, 166,
]);

/// The hash of the dummy commitment.
/// ```python
/// from hashlib import sha256
/// hasher = sha256()
/// hasher.update(DUMMY_COMMITMENT)
/// DUMMY_COMMITMENT_HASH = hasher.digest()
/// ```
pub const DUMMY_COMMITMENT_HASH: [u8; 32] = [
    158, 138, 10, 134, 23, 4, 169, 223, 141, 146, 190, 141, 69, 221, 237, 154, 56, 59, 247, 201,
    229, 244, 112, 151, 12, 148, 144, 118, 203, 125, 9, 233,
];

#[derive(Copy, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    any(feature = "host", test),
    derive(Default, PartialEq, Eq, Hash, PartialOrd, Ord)
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
    /// Commits to the account ID and account state.
    /// SHA256(`Comm_DS` || `account_id` || SHA256(borsh(account))).
    // TODO: Accept account_id by value as it's Copy
    #[must_use]
    pub fn new(account_id: &AccountId, account: &Account) -> Self {
        const COMMITMENT_PREFIX: &[u8; 32] =
            b"/LEE/v0.3/Commitment/\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

        let hashed_account: [u8; 32] = Impl::hash_bytes(&account.to_bytes())
            .as_bytes()
            .try_into()
            .unwrap();

        let mut bytes = Vec::new();
        bytes.extend_from_slice(COMMITMENT_PREFIX);
        bytes.extend_from_slice(account_id.value());
        bytes.extend_from_slice(&hashed_account);
        Self(Impl::hash_bytes(&bytes).as_bytes().try_into().unwrap())
    }

    #[must_use]
    pub fn for_dummy(nullifier: &Nullifier, commitment_seed: &[u8; 32]) -> Self {
        const DUMMY_PREFIX: &[u8; 32] = b"/LEE/v0.3/Commitment/Dummy/\x00\x00\x00\x00\x00";
        let mut bytes = DUMMY_PREFIX.to_vec();
        bytes.extend_from_slice(&nullifier.0);
        bytes.extend_from_slice(commitment_seed);
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
        Commitment, DUMMY_COMMITMENT, DUMMY_COMMITMENT_HASH, Nullifier,
        account::{Account, AccountId},
    };

    #[test]
    fn nothing_up_my_sleeve_dummy_commitment() {
        let default_account = Account::default();
        let account_id_null = AccountId::new([0; 32]);
        let expected_dummy_commitment = Commitment::new(&account_id_null, &default_account);
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

    #[test]
    fn for_dummy_matches_pinned_value() {
        let nullifier = Nullifier::for_dummy(&[0; 32]);
        let commitment_seed = [1; 32];
        let expected_commitment = Commitment([
            106, 88, 233, 248, 28, 251, 254, 48, 62, 53, 61, 248, 25, 148, 223, 133, 108, 213, 184,
            83, 73, 145, 122, 104, 89, 220, 111, 132, 40, 87, 12, 105,
        ]);
        assert_eq!(
            Commitment::for_dummy(&nullifier, &commitment_seed),
            expected_commitment
        );
    }
}
