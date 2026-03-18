use serde::{Deserialize, Serialize};

use crate::{
    Commitment, CommitmentSetDigest, MembershipProof, Nullifier, NullifierPublicKey,
    NullifierSecretKey, SharedSecretKey,
    account::{Account, AccountWithMetadata, Nonce},
    encryption::Ciphertext,
    program::{ProgramId, ProgramOutput},
};

#[derive(Serialize, Deserialize)]
pub struct PrivacyPreservingCircuitInput {
    /// Outputs of the program execution.
    pub program_outputs: Vec<ProgramOutput>,
    /// Visibility mask for accounts.
    ///
    /// - `0` - public account
    /// - `1` - private account with authentication
    /// - `2` - private account without authentication
    pub visibility_mask: Vec<u8>,
    /// Nonces of private accounts.
    pub private_account_nonces: Vec<Nonce>,
    /// Public keys of private accounts.
    pub private_account_keys: Vec<(NullifierPublicKey, SharedSecretKey)>,
    /// Nullifier secret keys for authorized private accounts.
    pub private_account_nsks: Vec<NullifierSecretKey>,
    /// Membership proofs for private accounts. Can be [`None`] for uninitialized accounts.
    pub private_account_membership_proofs: Vec<Option<MembershipProof>>,
    /// Program ID.
    pub program_id: ProgramId,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
pub struct PrivacyPreservingCircuitOutput {
    pub public_pre_states: Vec<AccountWithMetadata>,
    pub public_post_states: Vec<Account>,
    pub ciphertexts: Vec<Ciphertext>,
    pub new_commitments: Vec<Commitment>,
    pub new_nullifiers: Vec<(Nullifier, CommitmentSetDigest)>,
}

#[cfg(feature = "host")]
impl PrivacyPreservingCircuitOutput {
    /// Serializes the circuit output to a byte vector.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        bytemuck::cast_slice(&risc0_zkvm::serde::to_vec(&self).unwrap()).to_vec()
    }
}

#[cfg(feature = "host")]
#[cfg(test)]
mod tests {
    use risc0_zkvm::serde::from_slice;

    use super::*;
    use crate::{
        Commitment, Nullifier, NullifierPublicKey,
        account::{Account, AccountId, AccountWithMetadata},
    };

    #[test]
    fn privacy_preserving_circuit_output_to_bytes_is_compatible_with_from_slice() {
        let output = PrivacyPreservingCircuitOutput {
            public_pre_states: vec![
                AccountWithMetadata::new(
                    Account {
                        program_owner: [1, 2, 3, 4, 5, 6, 7, 8],
                        balance: 12_345_678_901_234_567_890,
                        data: b"test data".to_vec().try_into().unwrap(),
                        nonce: 0xFFFF_FFFF_FFFF_FFFE,
                    },
                    true,
                    AccountId::new([0; 32]),
                ),
                AccountWithMetadata::new(
                    Account {
                        program_owner: [9, 9, 9, 8, 8, 8, 7, 7],
                        balance: 123_123_123_456_456_567_112,
                        data: b"test data".to_vec().try_into().unwrap(),
                        nonce: 9_999_999_999_999_999_999_999,
                    },
                    false,
                    AccountId::new([1; 32]),
                ),
            ],
            public_post_states: vec![Account {
                program_owner: [1, 2, 3, 4, 5, 6, 7, 8],
                balance: 100,
                data: b"post state data".to_vec().try_into().unwrap(),
                nonce: 0xFFFF_FFFF_FFFF_FFFF,
            }],
            ciphertexts: vec![Ciphertext(vec![255, 255, 1, 1, 2, 2])],
            new_commitments: vec![Commitment::new(
                &NullifierPublicKey::from(&[1; 32]),
                &Account::default(),
            )],
            new_nullifiers: vec![(
                Nullifier::for_account_update(
                    &Commitment::new(&NullifierPublicKey::from(&[2; 32]), &Account::default()),
                    &[1; 32],
                ),
                [0xab; 32],
            )],
        };
        let bytes = output.to_bytes();
        let output_from_slice: PrivacyPreservingCircuitOutput = from_slice(&bytes).unwrap();
        assert_eq!(output, output_from_slice);
    }
}
