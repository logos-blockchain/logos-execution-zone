use serde::{Deserialize, Serialize};

use crate::{
    Commitment, CommitmentSetDigest, MembershipProof, Nullifier, NullifierPublicKey,
    NullifierSecretKey, SharedSecretKey,
    account::{Account, AccountWithMetadata},
    encryption::Ciphertext,
    program::{BlockValidityWindow, ProgramId, ProgramOutput, TimestampValidityWindow},
};

#[derive(Serialize, Deserialize)]
pub struct PrivacyPreservingCircuitInput {
    /// Outputs of the program execution.
    pub program_outputs: Vec<ProgramOutput>,
    /// One entry per `pre_state`, in the same order as the program's `pre_states`.
    /// Length must equal the number of `pre_states` derived from `program_outputs`.
    /// The guest's `private_pda_npk_by_position` and `private_pda_bound_positions`
    /// rely on this position alignment.
    pub account_identities: Vec<InputAccountIdentity>,
    /// Program ID.
    pub program_id: ProgramId,
}

/// Per-account input to the privacy-preserving circuit. Each variant carries exactly the fields
/// the guest needs for that account's code path.
#[derive(Serialize, Deserialize, Clone)]
pub enum InputAccountIdentity {
    /// Public account. The guest reads pre/post state from `program_outputs` and emits no
    /// commitment, ciphertext, or nullifier.
    Public,
    /// Init of an authorized standalone private account: no membership proof. The `pre_state`
    /// must be `Account::default()`. `npk` is derived from `nsk` and matched against
    /// `pre_state.account_id` via `AccountId::from(npk)`.
    PrivateAuthorizedInit {
        ssk: SharedSecretKey,
        nsk: NullifierSecretKey,
    },
    /// Update of an authorized standalone private account: existing on-chain commitment, with
    /// membership proof.
    PrivateAuthorizedUpdate {
        ssk: SharedSecretKey,
        nsk: NullifierSecretKey,
        membership_proof: MembershipProof,
    },
    /// Init of a standalone private account the caller does not own (e.g. a recipient who
    /// doesn't yet exist on chain). No `nsk`, no membership proof.
    PrivateUnauthorized {
        npk: NullifierPublicKey,
        ssk: SharedSecretKey,
    },
    /// Init of a private PDA, unauthorized. The npk-to-account_id binding is proven upstream
    /// via `Claim::Pda(seed)` or a caller's `pda_seeds` match.
    PrivatePdaInit {
        npk: NullifierPublicKey,
        ssk: SharedSecretKey,
    },
    /// Update of an existing private PDA, authorized, with membership proof. `npk` is derived
    /// from `nsk`. Authorization is established upstream by a caller `pda_seeds` match or a
    /// previously-seen authorization in a chained call.
    PrivatePdaUpdate {
        ssk: SharedSecretKey,
        nsk: NullifierSecretKey,
        membership_proof: MembershipProof,
    },
}

impl InputAccountIdentity {
    #[must_use]
    pub const fn is_public(&self) -> bool {
        matches!(self, Self::Public)
    }

    #[must_use]
    pub const fn is_private_pda(&self) -> bool {
        matches!(
            self,
            Self::PrivatePdaInit { .. } | Self::PrivatePdaUpdate { .. }
        )
    }

    /// For private PDA variants, return the nullifier public key. `Init` carries it directly;
    /// `Update` derives it from `nsk`. For non-PDA variants returns `None`.
    #[must_use]
    pub fn npk_if_private_pda(&self) -> Option<NullifierPublicKey> {
        match self {
            Self::PrivatePdaInit { npk, .. } => Some(*npk),
            Self::PrivatePdaUpdate { nsk, .. } => Some(NullifierPublicKey::from(nsk)),
            Self::Public
            | Self::PrivateAuthorizedInit { .. }
            | Self::PrivateAuthorizedUpdate { .. }
            | Self::PrivateUnauthorized { .. } => None,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
pub struct PrivacyPreservingCircuitOutput {
    pub public_pre_states: Vec<AccountWithMetadata>,
    pub public_post_states: Vec<Account>,
    pub ciphertexts: Vec<Ciphertext>,
    pub new_commitments: Vec<Commitment>,
    pub new_nullifiers: Vec<(Nullifier, CommitmentSetDigest)>,
    pub block_validity_window: BlockValidityWindow,
    pub timestamp_validity_window: TimestampValidityWindow,
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
        account::{Account, AccountId, AccountWithMetadata, Nonce},
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
                        nonce: Nonce(0xFFFF_FFFF_FFFF_FFFE),
                    },
                    true,
                    AccountId::new([0; 32]),
                ),
                AccountWithMetadata::new(
                    Account {
                        program_owner: [9, 9, 9, 8, 8, 8, 7, 7],
                        balance: 123_123_123_456_456_567_112,
                        data: b"test data".to_vec().try_into().unwrap(),
                        nonce: Nonce(9_999_999_999_999_999_999_999),
                    },
                    false,
                    AccountId::new([1; 32]),
                ),
            ],
            public_post_states: vec![Account {
                program_owner: [1, 2, 3, 4, 5, 6, 7, 8],
                balance: 100,
                data: b"post state data".to_vec().try_into().unwrap(),
                nonce: Nonce(0xFFFF_FFFF_FFFF_FFFF),
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
            block_validity_window: (1..).into(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
        };
        let bytes = output.to_bytes();
        let output_from_slice: PrivacyPreservingCircuitOutput = from_slice(&bytes).unwrap();
        assert_eq!(output, output_from_slice);
    }
}
